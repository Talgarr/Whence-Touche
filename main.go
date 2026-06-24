// Whence Touché watches YubiKey activity via eBPF, classifies the calling
// process, and shows a desktop notification that clears when the touch is done.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	clsf "github.com/Talgarr/Whence-Touche/internal/classifier"
	"github.com/Talgarr/Whence-Touche/internal/classifier/rules"
	"github.com/Talgarr/Whence-Touche/internal/config"
	"github.com/Talgarr/Whence-Touche/internal/notifier"
	"github.com/Talgarr/Whence-Touche/internal/proctree"
	"github.com/Talgarr/Whence-Touche/internal/tracer"
)

// sessionKey groups events into one logical touch. hidraw uses the client PID;
// ccid always uses scdaemon, so GPG activity collapses into one session.
type sessionKey struct {
	src tracer.Source
	pid uint32
}

type session struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
	notifID   uint32
	shown     bool
}

// ready reports whether the session has shown enough sustained activity to
// warrant a notification: at least `threshold` I/O events spanning at least
// `delay` of wall-clock time. The dwell requirement is what filters out the
// brief command/PIN-probe burst that precedes PIN entry, so we don't pop a
// notification that closes during the PIN prompt and reopens after — the
// "flash" from issue #1. A genuine touch-wait keeps the device polling until
// the user touches, so its span clears `delay` comfortably.
func (s *session) ready(threshold int, delay time.Duration) bool {
	return !s.shown && s.count >= threshold && s.lastSeen.Sub(s.firstSeen) >= delay
}

func main() {
	cfg, cfgErr := config.Load()
	verbose := flag.Bool("verbose", cfg.Debug, "enable debug logging (or set WHENCE_DEBUG=true)")
	backend := flag.String("notifier", cfg.Notifier,
		`notification backend: "dbus" for desktop notifications, "log" to only log touches (or set WHENCE_NOTIFIER)`)
	flag.Parse()

	level := zerolog.InfoLevel
	if *verbose {
		level = zerolog.DebugLevel
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		Level(level).
		With().Timestamp().Str("bin", "whence-touche").Logger()

	if cfgErr != nil {
		log.Fatal().Err(cfgErr).Msg("load config")
	}

	tr, err := tracer.New()
	if err != nil {
		log.Fatal().Err(err).Msg("start eBPF tracer (run as root / with CAP_BPF?)")
	}
	defer tr.Close()

	ntf, err := notifier.New(*backend)
	if err != nil {
		log.Fatal().Err(err).Msg("set WHENCE_NOTIFIER to supported value")
	}

	allRules := rules.All()
	sessions := make(map[sessionKey]*session)

	ticker := time.NewTicker(cfg.Sweep)
	defer ticker.Stop()

	log.Info().Msg("listening for YubiKey activity via eBPF")

	for {
		select {
		case ev, ok := <-tr.Events():
			if !ok {
				log.Warn().Msg("tracer event stream closed")
				return
			}
			handleEvent(allRules, sessions, ev, cfg.NotifyThreshold, cfg.NotifyDelay, ntf, tr)

		case <-ticker.C:
			now := time.Now()
			for key, s := range sessions {
				if now.Sub(s.lastSeen) < cfg.Quiet {
					continue
				}
				if s.shown {
					ntf.Close(s.notifID)
					log.Debug().Str("kind", key.src.Kind()).Uint32("pid", key.pid).Msg("touch done")
				}
				delete(sessions, key)
			}
		}
	}
}

// handleEvent records an I/O and notifies once a session shows sustained
// activity (see session.ready). The notifier ntf decides how the touch is
// surfaced — a desktop notification or a log line (see internal/notifier).
func handleEvent(allRules []clsf.Rule, sessions map[sessionKey]*session, ev tracer.Event, threshold int, delay time.Duration, ntf notifier.Notifier, tr *tracer.Tracer) {
	key := sessionKey{ev.Source, ev.PID}
	s := sessions[key]
	now := time.Now()
	if s == nil {
		s = &session{firstSeen: now}
		sessions[key] = s
	}
	s.count++
	s.lastSeen = now

	if !s.ready(threshold, delay) {
		return
	}
	s.shown = true

	body := buildBody(allRules, ev, tr)
	log.Debug().Str("kind", ev.Source.Kind()).Uint32("pid", ev.PID).Str("body", body).Msg("touch needed")

	id, err := ntf.TouchNeeded(body)
	if err != nil {
		log.Warn().Err(err).Msg("send notification")
		return
	}
	s.notifID = id
}

// buildBody resolves the calling process and renders the notification text. CCID
// is attributed to scdaemon, so the GPG client comes from the gpg-agent socket
// peer; ssh-agent-mediated FIDO is resolved the same way.
func buildBody(allRules []clsf.Rule, ev tracer.Event, tr *tracer.Tracer) string {
	pid := ev.PID
	if ev.Source == tracer.SourceCCID {
		if client := resolveClient(tr, tracer.AgentGPG); client != 0 {
			pid = client
		} else {
			log.Debug().Uint32("scdaemon", ev.PID).Msg("no gpg-agent client resolved; attributing to scdaemon")
		}
	}
	if pid == 0 {
		return ev.Source.Kind() + ": unknown process"
	}

	tree := proctree.Walk(pid)
	if len(tree) == 0 {
		log.Debug().Str("kind", ev.Source.Kind()).Uint32("pid", pid).Msg("process gone before walk")
		return fmt.Sprintf("%s: pid %d (process gone)", ev.Source.Kind(), pid)
	}

	if ev.Source == tracer.SourceHIDRaw &&
		clsf.Has(tree, "ssh-sk-helper") && clsf.Has(tree, "ssh-agent") && !clsf.Has(tree, "ssh") {
		if client := resolveClient(tr, tracer.AgentSSH); client != 0 {
			if t := proctree.Walk(client); len(t) > 0 {
				tree = t
			}
		}
	}

	// The entire process call stack the classifier sees, oldest ancestor first.
	log.Debug().Str("stack", proctree.Format(tree)).Msg("call stack")

	if c, ok := clsf.Classify(allRules, tree); ok {
		body := c.Tool
		if c.Action != "" {
			body += " " + c.Action
		}
		if c.Resource != "" {
			body += ": " + c.Resource
		}
		return body
	}

	return proctree.Format(tree)
}

// resolveClient finds the real client behind an agent-mediated request via the
// eBPF request graph (exact, in-kernel, no extra privilege). Returns 0 when the
// graph has no live entry, in which case the caller attributes the touch to the
// agent's helper (scdaemon/ssh-sk-helper).
func resolveClient(tr *tracer.Tracer, kind uint32) uint32 {
	pid := tr.AgentClientPID(kind)
	if pid == 0 || !pidAlive(pid) {
		return 0
	}
	log.Debug().Uint32("client", pid).Uint32("kind", kind).Msg("agent client via eBPF graph")
	return pid
}

func pidAlive(pid uint32) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}
