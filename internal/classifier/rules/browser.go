package rules

import (
	"github.com/talgarr/yubikey-notifier-v2/internal/classifier"
)

// Browser matches WebAuthn/passkey touch requests from browser processes.
type Browser struct{}

var browsers = []string{
	"firefox", "firefox-esr",
	"google-chrome", "google-chrome-stable",
	"chromium", "chromium-browser",
	"brave", "brave-browser",
	"opera", "vivaldi",
}

func (Browser) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, browsers...)
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     p.Name(),
		Action:   "authenticate",
		Resource: "WebAuthn / passkey",
		Depth:    idx,
	}, true
}
