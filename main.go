// yubikey-notifier: listens to yubikey-touch-detector events via DBus,
// walks the calling process tree, classifies the operation, and shows
// a desktop notification that dismisses itself when the touch is complete.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	clsf "github.com/talgarr/yubikey-notifier-v2/internal/classifier"
	"github.com/talgarr/yubikey-notifier-v2/internal/classifier/rules"
	"github.com/talgarr/yubikey-notifier-v2/internal/notifier"
	"github.com/talgarr/yubikey-notifier-v2/internal/proctree"
)

const (
	detectorIface = "com.github.maximbaz.YubikeyTouchDetector"
	detectorPath  = "/com/github/maximbaz/YubikeyTouchDetector"
	matchRule     = "type='signal',interface='" + detectorIface + "',member='TouchEvent'"
)

func main() {
	verbose := flag.Bool("verbose", false, "enable debug logging")
	flag.Parse()

	level := zerolog.InfoLevel
	if *verbose {
		level = zerolog.DebugLevel
	}
	log.Logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
		Level(level).
		With().Timestamp().Str("bin", "yubikey-notifier").Logger()

	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		log.Fatal().Err(err).Msg("connect session bus")
	}
	defer conn.Close()

	if err := conn.AddMatchSignal(
		dbus.WithMatchInterface(detectorIface),
		dbus.WithMatchMember("TouchEvent"),
		dbus.WithMatchObjectPath(detectorPath),
	); err != nil {
		log.Fatal().Err(err).Msg("add match signal")
	}

	signals := make(chan *dbus.Signal, 20)
	conn.Signal(signals)

	log.Info().Msg("listening for YubiKey touch events")

	allRules := rules.All()

	// active holds open notification IDs keyed by signal key (type+pid).
	var mu sync.Mutex
	active := make(map[string]uint32)

	for sig := range signals {
		if len(sig.Body) < 2 {
			continue
		}
		eventType, ok := sig.Body[0].(string)
		if !ok || eventType == "" {
			continue
		}
		pid, ok := sig.Body[1].(uint32)
		if !ok {
			continue
		}

		isOn := eventType == "GPG_1" || eventType == "U2F_1" || eventType == "MAC_1"
		isOff := eventType == "GPG_0" || eventType == "U2F_0" || eventType == "MAC_0"

		log.Debug().Str("type", eventType).Uint32("pid", pid).Msg("touch event")

		key := fmt.Sprintf("%s/%d", eventType[:3], pid)

		if isOn {
			body := buildBody(allRules, pid)
			id, err := notifier.TouchNeeded(body)
			if err != nil {
				log.Warn().Err(err).Msg("send notification")
				continue
			}
			mu.Lock()
			active[key] = id
			mu.Unlock()
		} else if isOff {
			mu.Lock()
			var toClose []uint32
			if pid != 0 {
				// Exact match: close only the notification for this PID.
				if id, ok := active[key]; ok {
					toClose = append(toClose, id)
					delete(active, key)
				}
			} else {
				// PID unknown — close all notifications of this type.
				prefix := eventType[:3] + "/"
				for k, id := range active {
					if strings.HasPrefix(k, prefix) {
						toClose = append(toClose, id)
						delete(active, k)
					}
				}
			}
			mu.Unlock()
			for _, id := range toClose {
				notifier.Close(id)
			}
		}
	}
}

// buildBody walks the process tree for pid and returns a notification body string.
// Falls back to "pid <N>" when the process is gone or unclassifiable.
func buildBody(allRules []clsf.Rule, pid uint32) string {
	if pid == 0 {
		return "Unknown process"
	}

	tree := proctree.Walk(pid)
	if len(tree) == 0 {
		return fmt.Sprintf("pid %d (process gone)", pid)
	}

	c, ok := clsf.Classify(allRules, tree)
	if ok {
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
