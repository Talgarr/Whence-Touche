// yubikey-notifier watches YubiKey activity via eBPF (the internal/tracer
// package), walks the calling process tree to classify the operation, and shows
// a desktop notification that dismisses itself once the touch is complete.
//
// It replaces the previous yubikey-touch-detector D-Bus listener. Because eBPF
// reports a raw I/O firehose (not the detector's clean ON/OFF), the event loop
// debounces: a notification is shown once a process accumulates a few I/Os to
// the key, and dismissed after the key goes quiet (touch finished).
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/talgarr/yubikey-notifier/internal/agentpeer"
	clsf "github.com/talgarr/yubikey-notifier/internal/classifier"
	"github.com/talgarr/yubikey-notifier/internal/classifier/rules"
	"github.com/talgarr/yubikey-notifier/internal/config"
	"github.com/talgarr/yubikey-notifier/internal/notifier"
	"github.com/talgarr/yubikey-notifier/internal/proctree"
	"github.com/talgarr/yubikey-notifier/internal/tracer"
)

// sessionKey groups events into one logical touch. For hidraw the PID is the
// real client, so concurrent FIDO touches stay distinct. For ccid the PID is
// always scdaemon, so all GPG activity collapses into one session (fine: GPG
// touches are effectively serialized through scdaemon).
type sessionKey struct {
	src tracer.Source
	pid uint32
}

type session struct {
	count    int
	lastSeen time.Time
	notifID  uint32
	shown    bool
}

func main() {
	verbose := flag.Bool("verbose", false, "enable debug logging")
	cfg, cfgErr := config.Load()
	objPath := flag.String("bpf-object", cfg.ObjectPath, "path to tracer.bpf.o (overrides $YUBIKEY_TRACER_OBJ_PATH)")
	flag.Parse()

	level := zerolog.InfoLevel
	if *verbose {
		level = zerolog.DebugLevel
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		Level(level).
		With().Timestamp().Str("bin", "yubikey-notifier").Logger()

	if cfgErr != nil {
		log.Fatal().Err(cfgErr).Msg("load config")
	}

	restoreSessionBus()

	tr, err := tracer.New(*objPath)
	if err != nil {
		log.Fatal().Err(err).Msg("start eBPF tracer (run as root / with CAP_BPF?)")
	}
	defer tr.Close()

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
			handleEvent(allRules, sessions, ev, cfg.NotifyThreshold)

		case <-ticker.C:
			now := time.Now()
			for key, s := range sessions {
				if now.Sub(s.lastSeen) < cfg.Quiet {
					continue
				}
				if s.shown {
					notifier.Close(s.notifID)
					log.Debug().Str("kind", key.src.Kind()).Uint32("pid", key.pid).Msg("touch done")
				}
				delete(sessions, key)
			}
		}
	}
}

// restoreSessionBus makes desktop notifications reach the *invoking* user's
// session bus when the daemon is started as root via sudo. eBPF needs
// privilege, but a root process's D-Bus session points at root's (absent) bus,
// so notifications silently fail. When we're root and were sudo'd, derive the
// user's bus/runtime dir from SUDO_UID unless already set (e.g. by `sudo -E`).
// Running unprivileged (the file-capabilities path) skips this entirely.
func restoreSessionBus() {
	if os.Geteuid() != 0 {
		return
	}
	uid := os.Getenv("SUDO_UID")
	if uid == "" {
		return
	}
	if os.Getenv("XDG_RUNTIME_DIR") == "" {
		os.Setenv("XDG_RUNTIME_DIR", "/run/user/"+uid)
	}
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
		addr := "unix:path=/run/user/" + uid + "/bus"
		os.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
		log.Debug().Str("addr", addr).Msg("derived session bus from SUDO_UID")
	}
}

// handleEvent records an I/O against its session, showing a notification once
// the session crosses the notify threshold.
func handleEvent(allRules []clsf.Rule, sessions map[sessionKey]*session, ev tracer.Event, threshold int) {
	key := sessionKey{ev.Source, ev.PID}
	s := sessions[key]
	if s == nil {
		s = &session{}
		sessions[key] = s
	}
	s.count++
	s.lastSeen = time.Now()

	if s.shown || s.count < threshold {
		return
	}
	s.shown = true

	body := buildBody(allRules, ev)
	log.Debug().Str("kind", ev.Source.Kind()).Uint32("pid", ev.PID).Str("body", body).Msg("touch needed")

	id, err := notifier.TouchNeeded(body)
	if err != nil {
		log.Warn().Err(err).Msg("send notification")
		return
	}
	s.notifID = id
}

// buildBody resolves the user-facing process behind an event and renders a
// notification body.
//
// The PID that issued the I/O is not always the tool that asked for it: when a
// request is routed through an agent daemon, the real client is a socket peer of
// that agent, not a process ancestor of the I/O leaf. We resolve those via
// agentpeer:
//   - CCID/GPG: the event PID is always scdaemon → resolve the gpg-agent peer.
//   - hidraw/SSH: the event PID is normally the client leaf (ssh-sk-helper with
//     ssh as its parent), but when the key is held in ssh-agent the leaf's
//     parent is ssh-agent and the real ssh is a socket peer → resolve that.
func buildBody(allRules []clsf.Rule, ev tracer.Event) string {
	pid := ev.PID
	if ev.Source == tracer.SourceCCID {
		if client := agentpeer.GPGAgent.FindClientPID(); client != 0 {
			pid = client
		}
	}
	if pid == 0 {
		return ev.Source.Kind() + ": unknown process"
	}

	tree := proctree.Walk(pid)
	if len(tree) == 0 {
		return fmt.Sprintf("%s: pid %d (process gone)", ev.Source.Kind(), pid)
	}

	// SSH via ssh-agent: ssh-sk-helper was forked by ssh-agent, so the real ssh
	// client (and its host) is a socket peer absent from this tree. Re-resolve.
	if ev.Source == tracer.SourceHIDRaw &&
		clsf.Has(tree, "ssh-sk-helper") && clsf.Has(tree, "ssh-agent") && !clsf.Has(tree, "ssh") {
		if client := agentpeer.SSHAgent.FindClientPID(); client != 0 {
			if t := proctree.Walk(client); len(t) > 0 {
				tree = t
			}
		}
	}

	log.Debug().Str("tree", proctree.Format(tree)).Msg("process tree")

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
