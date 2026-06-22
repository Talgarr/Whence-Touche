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

	"github.com/Talgarr/Whence-Touche/internal/agentpeer"
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
	count    int
	lastSeen time.Time
	notifID  uint32
	shown    bool
}

func main() {
	cfg, cfgErr := config.Load()
	verbose := flag.Bool("verbose", cfg.Debug, "enable debug logging (or set WHENCE_DEBUG=true)")
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

// handleEvent records an I/O and notifies once a session crosses the threshold.
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

// buildBody resolves the calling process and renders the notification text. CCID
// is attributed to scdaemon, so the GPG client comes from the gpg-agent socket
// peer; ssh-agent-mediated FIDO is resolved the same way.
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
