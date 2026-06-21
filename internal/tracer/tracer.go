// Package tracer runs the eBPF session that reports, per process, I/O to a
// security key across the hidraw (FIDO) and usbfs/CCID (OpenPGP) interfaces.
// Loading the kprobes needs root or CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN.
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
	"golang.org/x/sys/unix"
)

// Source is the transport an event came from.
type Source uint8

const (
	SourceHIDRaw Source = iota // FIDO/U2F/HMAC via /dev/hidrawN
	SourceCCID                 // OpenPGP via usbfs (scdaemon)
)

func (s Source) String() string {
	if s == SourceCCID {
		return "ccid"
	}
	return "hidraw"
}

// Kind is a user-facing label for the credential type.
func (s Source) Kind() string {
	if s == SourceCCID {
		return "GPG"
	}
	return "FIDO"
}

// flags bits, matching the EV_* defines in tracer.bpf.c.
const (
	evWrite = 0x1
	evCCID  = 0x2
)

// Event is one I/O to the key. For CCID, PID is scdaemon, not the real client.
type Event struct {
	PID    uint32
	Source Source
	Write  bool
}

// rawEvent mirrors struct event in tracer.bpf.c (8 bytes with padding).
type rawEvent struct {
	PID   uint32
	Flags uint8
	_     [3]byte
}

// kprobes maps kernel symbol -> BPF program name.
var kprobes = map[string]string{
	"hidraw_write":      "kprobe_hidraw_write",
	"hidraw_read":       "kprobe_hidraw_read",
	"proc_do_submiturb": "kprobe_proc_do_submiturb",
}

type Tracer struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	events chan Event
}

// New loads the BPF object, attaches the kprobes, and starts draining events.
func New(objectPath string) (*Tracer, error) {
	// File caps mark us non-dumpable, hiding /proc/self/mem, which cilium reads
	// to detect the kernel version while loading kprobes. Restore dumpability.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0)

	// Best-effort: only needed (and only permitted) on kernels < 5.11.
	_ = rlimit.RemoveMemlock()

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

// Events delivers parsed events until Close, after which it is closed.
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
		// Non-blocking: the touch-wait floods and we debounce downstream.
		select {
		case t.events <- ev:
		default:
		}
	}
}

// Close detaches the kprobes and stops the drain goroutine.
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
