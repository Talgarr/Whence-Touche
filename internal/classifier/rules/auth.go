package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Auth matches PAM-based authentication backed by pam_u2f / pam-u2f
// (FIDO2/U2F). pam_u2f runs in-process inside the authenticating program and
// talks to the key over hidraw, so the touch fires in that program's own
// process (sudo, login, a screen locker, etc.) rather than in a helper.
// See https://github.com/Yubico/pam-u2f.
type Auth struct{}

// authNames lists the privilege/login/lock-screen programs that commonly use
// pam_u2f. The kernel `comm` is truncated to 15 chars (TASK_COMM_LEN), and
// FindFirst matches either Process.Name() (argv[0] basename, untruncated) or
// Comm — so for long names we list both the full name and its 15-char
// truncation (e.g. "gdm-session-worker" / "gdm-session-wor",
// "polkit-agent-helper-1" / "polkit-agent-he") to catch the comm-only case.
//
// Note: "sshd" is intentionally excluded — SSH is handled by the SSH rule.
var authNames = []string{
	"sudo",
	"su",
	"login",
	"pkexec",
	"polkitd",
	"polkit-agent-he", // polkit-agent-helper-1, truncated to 15 chars
	"gdm-session-worker",
	"gdm-session-wor", // gdm-session-worker, truncated to 15 chars
	"gdm-password",
	"sddm-helper",
	"lightdm",
	"greetd",
	"swaylock",
	"hyprlock",
	"i3lock",
	"gtklock",
}

func (Auth) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, authNames...)
	if !ok {
		return classifier.Classification{}, false
	}
	name := p.Name()
	return classifier.Classification{
		Tool:     name,
		Action:   "authenticate",
		Resource: authResource(name, p),
		Depth:    idx,
	}, true
}

// authResource derives a short context describing what is being authenticated.
func authResource(name string, p classifier.Process) string {
	switch name {
	case "sudo":
		// The command being authorised: the non-flag args after argv[0].
		var cmd []string
		for _, a := range p.Args[safeStart(p):] {
			if strings.HasPrefix(a, "-") {
				continue
			}
			cmd = append(cmd, a)
		}
		if len(cmd) == 0 {
			return "as root"
		}
		return strings.Join(cmd, " ")
	case "su":
		if target := classifier.FirstPositional(p); target != "" {
			return target
		}
		return "as root"
	case "swaylock", "hyprlock", "i3lock", "gtklock":
		return "unlock session"
	case "login", "gdm-session-worker", "gdm-session-wor", "gdm-password",
		"sddm-helper", "lightdm", "greetd":
		return "login"
	case "pkexec", "polkitd", "polkit-agent-he":
		return "privileged action"
	default:
		return "system authentication"
	}
}

// safeStart returns the index of the first argument after argv[0], or 0 when
// argv is empty (matched via Comm only).
func safeStart(p classifier.Process) int {
	if len(p.Args) > 0 {
		return 1
	}
	return 0
}
