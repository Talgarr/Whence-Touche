// Package notifier shows and dismisses "touch your security key" notifications.
//
// A backend is chosen at startup with New: the default DBus backend posts real
// desktop notifications via the org.freedesktop.Notifications interface, while
// the Log backend only writes to the log. The Log backend needs no session bus
// or notification daemon, so it suits headless runs and the container e2e
// harness, which asserts the resolved tool from the log line alone.
package notifier

import (
	"errors"
)

// Notifier announces a pending security-key touch and later dismisses it.
//
// TouchNeeded posts a notification for body and returns an ID; once the touch
// completes, Close dismisses the notification with that ID. Backends that have
// nothing on screen to dismiss (e.g. Log) may ignore the ID.
type Notifier interface {
	TouchNeeded(body string) (uint32, error)
	Close(id uint32)
}

// New returns the notifier backend named by name: "dbus" for desktop
// notifications, "log" for the log-only backend. Any other name is an error.
func New(name string) (Notifier, error) {
	switch name {
	case "log":
		return Log{}, nil
	case "dbus":
		return DBus{}, nil
	default:
		return nil, errors.New("unknown notifier type")
	}
}
