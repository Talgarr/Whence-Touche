package rules

import (
	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// OnePassword matches 1Password (https://1password.com/) touch requests from
// either the desktop app or the "op" CLI.
//
// On Linux the security key is most often used as account 2FA in the browser,
// which the Browser rule already names; this rule names the touch when the
// 1Password desktop app or the `op` CLI is the toucher instead.
type OnePassword struct{}

func (OnePassword) Match(tree []classifier.Process) (classifier.Classification, bool) {
	// "op" is the 1Password CLI and is a short/generic name; a rule only fires
	// inside a confirmed YubiKey-touch tree, so false positives are unlikely.
	idx, _, ok := classifier.FindFirst(tree, "1password", "1Password", "op")
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     "1password",
		Action:   "authenticate",
		Resource: "1Password",
		Depth:    idx,
	}, true
}
