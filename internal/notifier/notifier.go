// Package notifier sends desktop notifications via the org.freedesktop.Notifications
// DBus interface.  Using DBus directly (instead of notify-send) lets us obtain
// the notification ID so we can dismiss it programmatically once the YubiKey
// has been touched.
package notifier

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

const (
	dest  = "org.freedesktop.Notifications"
	opath = "/org/freedesktop/Notifications"
	iface = "org.freedesktop.Notifications"
)

// TouchNeeded shows a persistent critical-urgency notification asking the user
// to touch their YubiKey.  It never expires automatically; call Close with the
// returned ID once the touch is detected.
func TouchNeeded(body string) (uint32, error) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return 0, fmt.Errorf("session bus: %w", err)
	}

	hints := map[string]dbus.Variant{
		"urgency": dbus.MakeVariant(byte(2)), // 2 = critical
	}

	call := conn.Object(dest, opath).Call(
		iface+".Notify", 0,
		"Whence Touché",      // app_name
		uint32(0),            // replaces_id  (0 = new notification)
		"dialog-password",    // app_icon
		"Touch your YubiKey", // summary
		body,                 // body
		[]string{},           // actions
		hints,                // hints
		int32(0),             // expire_timeout: 0 = never expire
	)
	if call.Err != nil {
		return 0, call.Err
	}
	var id uint32
	if err := call.Store(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// Close dismisses a notification by the ID returned from TouchNeeded.
// Errors are silently discarded — the notification daemon may have already
// closed it (e.g. the user clicked it away).
func Close(id uint32) {
	conn, err := dbus.SessionBus()
	if err != nil {
		return
	}
	conn.Object(dest, opath).Call(iface+".CloseNotification", 0, id)
}
