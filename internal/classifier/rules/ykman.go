package rules

import (
	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Ykman matches the YubiKey Manager CLI (ykman) and the Yubico Authenticator
// GUI. OATH TOTP/HOTP credentials configured to require touch blink when a
// code is generated; ykman's PIV/FIDO/OpenPGP subcommands can likewise require
// a touch to authorise the operation.
//
// See https://github.com/Yubico/yubikey-manager and
// https://github.com/Yubico/yubioath-flutter.
type Ykman struct{}

func (Ykman) Match(tree []classifier.Process) (classifier.Classification, bool) {
	// "authenticator" is the binary name of the modern Yubico Authenticator
	// app; it is somewhat generic, but a rule only fires inside a confirmed
	// YubiKey-touch tree.
	idx, p, ok := classifier.FindFirst(tree,
		"ykman", "yubikey-manager",
		"yubico-authenticator", "authenticator",
		"yubioath-desktop", "yubioath",
	)
	if !ok {
		return classifier.Classification{}, false
	}

	tool := "yubico-authenticator"
	switch p.Name() {
	case "ykman", "yubikey-manager":
		tool = "ykman"
	}
	if p.Comm == "ykman" || p.Comm == "yubikey-manager" {
		tool = "ykman"
	}

	action, resource := ykmanOperation(tool, p)
	return classifier.Classification{
		Tool:     tool,
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func ykmanOperation(tool string, p classifier.Process) (action, resource string) {
	// The GUI apps don't expose a useful command line; they generate OATH
	// codes, so report a sensible default.
	if tool != "ykman" {
		return "OATH code", "TOTP"
	}

	sub, words := parseYkmanArgs(p)
	resource = "YubiKey"

	switch sub {
	case "oath":
		action = "OATH code"
		// "ykman oath accounts code <name>" — the credential name follows the
		// "code" token.
		if name := wordAfter(words, "code"); name != "" {
			resource = name
		} else {
			resource = "TOTP"
		}
	case "piv":
		action = "PIV"
		if verb := firstOf(words, "sign", "generate", "import"); verb != "" {
			action = "PIV " + verb
		}
	case "fido":
		action = "FIDO"
	case "openpgp":
		action = "OpenPGP"
	case "otp":
		action = "OTP"
	default:
		action = "manage"
	}
	return action, resource
}

// parseYkmanArgs returns the first subcommand among the recognised set and the
// remaining positional words that follow it (flags stripped).
func parseYkmanArgs(p classifier.Process) (sub string, words []string) {
	subcommands := map[string]bool{
		"oath": true, "piv": true, "fido": true,
		"openpgp": true, "otp": true, "config": true,
	}
	for _, arg := range p.Args[1:] {
		if len(arg) > 0 && arg[0] == '-' {
			continue
		}
		if sub == "" {
			if subcommands[arg] {
				sub = arg
			}
			continue
		}
		words = append(words, arg)
	}
	return sub, words
}

// wordAfter returns the word immediately following key in words, or "".
func wordAfter(words []string, key string) string {
	for i, w := range words {
		if w == key && i+1 < len(words) {
			return words[i+1]
		}
	}
	return ""
}

// firstOf returns the first of candidates that appears in words, or "".
func firstOf(words []string, candidates ...string) string {
	for _, w := range words {
		for _, c := range candidates {
			if w == c {
				return w
			}
		}
	}
	return ""
}
