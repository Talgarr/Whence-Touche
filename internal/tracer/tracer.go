// Package tracer runs the eBPF session that reports, per process, I/O to a
// security key across the hidraw (FIDO) and usbfs/CCID (OpenPGP) interfaces.
// Loading the kprobes needs root or CAP_BPF+CAP_PERFMON+CAP_SYS_ADMIN.
package tracer

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
)

// embeddedObject is the compiled BPF object baked into the binary at build time,
// so the default path needs no filesystem read at startup. The Makefile compiles
// tracer.bpf.o into this directory for the embed to pick up.
//
//go:embed tracer.bpf.o
var embeddedObject []byte

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
	coll         *ebpf.Collection
	links        []link.Link
	reader       *ringbuf.Reader
	events       chan Event
	agentClients *ebpf.Map // agent kind -> client whose request the agent most recently read
}

// New loads the embedded BPF object, attaches the kprobes, and starts draining
// events.
func New() (*Tracer, error) {
	// File caps mark us non-dumpable, which restricts the /proc/self/* files
	// (maps, mem, …) cilium/ebpf reads while loading programs. Restore dumpability.
	// This does NOT cover kernel-version detection: cilium reads that from the ELF
	// auxv the Go runtime captured at startup, before this runs. A pure-Go binary
	// gets auxv from the stack (fine), but a cgo build falls back to
	// /proc/self/auxv — already blocked here — and then version detection fails.
	// That is why the build pins CGO_ENABLED=0 (see Makefile/flake/goreleaser).
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0)

	// Best-effort: only needed (and only permitted) on kernels < 5.11.
	_ = rlimit.RemoveMemlock()

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(embeddedObject))
	if err != nil {
		return nil, fmt.Errorf("load embedded BPF object: %w", err)
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
			return nil, fmt.Errorf("program %q not found in BPF object", progName)
		}
		kp, err := link.Kprobe(sym, prog, nil)
		if err != nil {
			t.teardown()
			return nil, fmt.Errorf("attach kprobe %s: %w", sym, err)
		}
		t.links = append(t.links, kp)
	}

	// Optional agent request graph: attribute agent-mediated touches (gpg-agent,
	// ssh-agent) to the real client by recording, per agent kind, the client whose
	// request the agent most recently read (see tracer.bpf.c). Each probe is
	// non-fatal — if a symbol or program is missing, an agent-mediated touch is
	// simply attributed to the agent's helper (scdaemon/ssh-sk-helper) instead.
	t.agentClients = coll.Maps["agent_clients"]
	attachOpt := func(ret bool, sym, progName string) {
		prog := coll.Programs[progName]
		if prog == nil {
			return
		}
		var l link.Link
		var err error
		if ret {
			l, err = link.Kretprobe(sym, prog, nil)
		} else {
			l, err = link.Kprobe(sym, prog, nil)
		}
		if err != nil {
			log.Warn().Err(err).Str("sym", sym).Msg("agent graph: attach failed (agent-mediated touches will show the helper)")
			return
		}
		t.links = append(t.links, l)
	}
	attachOpt(false, "unix_accept", "kprobe_unix_accept")
	attachOpt(true, "unix_accept", "kretprobe_unix_accept")
	attachOpt(false, "unix_stream_recvmsg", "kprobe_unix_stream_recvmsg")

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		t.teardown()
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}
	t.reader = rd

	go t.drain()
	return t, nil
}

// Agent kinds for AgentClientPID, matching AGENT_* in tracer.bpf.c.
const (
	AgentGPG uint32 = 0
	AgentSSH uint32 = 1
)

// clientInfo mirrors struct client_info in tracer.bpf.c.
type clientInfo struct {
	PID uint32
	_   uint32
	TS  uint64
}

// AgentClientPID returns the pid of the process whose request the given agent
// (AgentGPG/AgentSSH) most recently read, as recorded by the request graph, or 0
// if unknown. Because the agent protocols are synchronous and the physical key
// serializes touches, that is the client behind the current touch. It lets the
// caller attribute an agent-mediated touch to the real client without scanning
// /proc.
func (t *Tracer) AgentClientPID(kind uint32) uint32 {
	if t == nil || t.agentClients == nil {
		return 0
	}
	var ci clientInfo
	if err := t.agentClients.Lookup(&kind, &ci); err != nil {
		return 0
	}
	return ci.PID
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
