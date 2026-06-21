// Package tracer owns an eBPF session that reports, in real time, when a process
// performs I/O to a hardware security key (YubiKey) — across the hidraw
// (FIDO/U2F/HMAC) and usbfs/CCID (OpenPGP via scdaemon) interfaces — and
// delivers the parsed events on a channel.
//
// It replaces the old yubikey-touch-detector D-Bus source. Loading and attaching
// the kprobes requires root (or CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN).
package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Source is the transport interface an event came from.
type Source uint8

const (
	SourceHIDRaw Source = iota // FIDO/U2F/HMAC via /dev/hidrawN
	SourceCCID                 // OpenPGP/smartcard via usbfs (scdaemon)
)

func (s Source) String() string {
	if s == SourceCCID {
		return "ccid"
	}
	return "hidraw"
}

// Kind is a coarse, user-facing label for the credential type behind a Source.
func (s Source) Kind() string {
	if s == SourceCCID {
		return "GPG"
	}
	return "FIDO"
}

// flags bits — must match the EV_* defines in tracer.bpf.c.
const (
	evWrite = 0x1
	evCCID  = 0x2
)

// Event is one I/O to the security key, attributed to the issuing process.
//
// For SourceHIDRaw, PID is the user-facing client leaf (ssh-sk-helper,
// chromium, …). For SourceCCID, PID is scdaemon (a singleton daemon) — the
// real client must be resolved separately from the gpg-agent socket peer.
type Event struct {
	PID    uint32
	Source Source
	Write  bool // true: host->key; false: key->host
}

// rawEvent mirrors `struct event` in tracer.bpf.c (8 bytes incl. tail padding).
type rawEvent struct {
	PID   uint32
	Flags uint8
	_     [3]byte
}

// kprobes maps kernel symbol -> BPF program name in the object.
var kprobes = map[string]string{
	"hidraw_write":      "kprobe_hidraw_write",
	"hidraw_read":       "kprobe_hidraw_read",
	"proc_do_submiturb": "kprobe_proc_do_submiturb",
}

// Tracer owns a loaded+attached eBPF session and a goroutine draining its ring
// buffer into Events().
type Tracer struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	events chan Event
}

// New loads the BPF object at objectPath, attaches the kprobes, and starts
// draining events. Call Close to detach and release resources.
func New(objectPath string) (*Tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("load %s: %w", objectPath, err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection (need root/CAP_BPF?): %w", err)
	}

	t := &Tracer{coll: coll, events: make(chan Event, 128)}

	for sym, progName := range kprobes {
		prog := coll.Programs[progName]
		if prog == nil {
			t.teardown()
			return nil, fmt.Errorf("program %q not found in %s", progName, objectPath)
		}
		kp, err := link.Kprobe(sym, prog, nil)
		if err != nil {
			t.teardown()
			return nil, fmt.Errorf("attach kprobe %s: %w", sym, err)
		}
		t.links = append(t.links, kp)
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		t.teardown()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	t.reader = rd

	go t.drain()
	return t, nil
}

// Events delivers parsed events until Close is called, after which it is closed.
func (t *Tracer) Events() <-chan Event { return t.events }

func (t *Tracer) drain() {
	defer close(t.events)
	var raw rawEvent
	for {
		rec, err := t.reader.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return
		}
		if err != nil {
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev := Event{PID: raw.PID, Write: raw.Flags&evWrite != 0}
		if raw.Flags&evCCID != 0 {
			ev.Source = SourceCCID
		}
		// Non-blocking: the touch-wait is a flood and we debounce downstream, so
		// dropping when the consumer is briefly behind is harmless.
		select {
		case t.events <- ev:
		default:
		}
	}
}

// Close detaches the kprobes, closes the ring buffer (unblocking the drain
// goroutine, which closes Events()), and releases the collection.
func (t *Tracer) Close() error {
	if t.reader != nil {
		t.reader.Close()
	}
	t.teardown()
	return nil
}

func (t *Tracer) teardown() {
	for _, l := range t.links {
		l.Close()
	}
	t.links = nil
	if t.coll != nil {
		t.coll.Close()
	}
}
