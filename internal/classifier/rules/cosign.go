package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Cosign matches cosign (Sigstore) signing operations.
// https://docs.sigstore.dev/cosign/
//
// cosign can sign with a PIV hardware token (touch-policy=always) via its
// go-piv / PKCS#11 backend, so a sustained touch-wait while cosign runs is a
// hardware-key signing request.
type Cosign struct{}

func (Cosign) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "cosign")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := cosignOperation(p)
	return classifier.Classification{
		Tool:     "cosign",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func cosignOperation(p classifier.Process) (action, resource string) {
	sub, pos := parseCosignArgs(p)

	switch sub {
	case "sign":
		action = "sign"
		resource = pos
		if resource == "" {
			resource = "artifact"
		}
	case "sign-blob":
		action = "sign blob"
		resource = pos
		if resource == "" {
			if key, ok := classifier.Arg(p, "--key"); ok {
				resource = key
			} else {
				resource = "blob"
			}
		}
	case "attest":
		action = "attest"
		resource = pos
		if resource == "" {
			resource = "artifact"
		}
	case "generate-key-pair":
		action = "generate key"
		resource = "PIV key"
	default:
		action = "sign"
		resource = "artifact"
	}
	return
}

// parseCosignArgs returns the first subcommand token (the first non-flag arg
// after argv[0]) and the first positional that follows it. A bare flag (e.g.
// "--key pkcs11:...") consumes the next token as its value so it is not
// mistaken for a positional.
func parseCosignArgs(p classifier.Process) (sub, pos string) {
	skip := false
	for _, arg := range p.Args[1:] {
		if skip {
			skip = false
			continue
		}
		if strings.HasPrefix(arg, "-") {
			// "--flag=value" is self-contained; "--flag value" eats the next token.
			if !strings.Contains(arg, "=") {
				skip = true
			}
			continue
		}
		if sub == "" {
			sub = arg
			continue
		}
		pos = arg
		return
	}
	return
}
