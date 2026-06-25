package rules

import (
	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Bitwarden matches Bitwarden (https://bitwarden.com/) vault unlocks that
// touch the key. Bitwarden offers a YubiKey OTP two-factor method: both the
// desktop app (the `bitwarden` Electron binary) and the `bw` CLI prompt for
// the YubiKey OTP, and the key emits the one-time code on touch (HID OTP).
// (WebAuthn/passkey unlock goes through the browser and is out of scope here.)
type Bitwarden struct{}

func (Bitwarden) Match(tree []classifier.Process) (classifier.Classification, bool) {
	// "bw" is the CLI and is a short name, but a rule only fires inside a
	// confirmed YubiKey-touch process tree, so false positives are unlikely.
	idx, _, ok := classifier.FindFirst(tree, "bitwarden", "bw")
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     "bitwarden",
		Action:   "authenticate",
		Resource: "Bitwarden vault",
		Depth:    idx,
	}, true
}
