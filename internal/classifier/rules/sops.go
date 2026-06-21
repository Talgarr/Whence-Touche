package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// SOPS matches Mozilla SOPS secret file operations.
type SOPS struct{}

func (SOPS) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "sops")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := sopsOperation(p)
	return classifier.Classification{
		Tool:     "sops",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func sopsOperation(p classifier.Process) (action, resource string) {
	action = "edit/decrypt"
	resource = "secrets file"

	for i, arg := range p.Args {
		if i == 0 {
			continue
		}
		switch arg {
		case "-e", "--encrypt":
			action = "encrypt"
		case "-d", "--decrypt":
			action = "decrypt"
		case "-r", "--rotate":
			action = "rotate keys"
		case "--edit", "-i", "--in-place":
			action = "edit"
		default:
			if !strings.HasPrefix(arg, "-") && resource == "secrets file" {
				resource = arg
			}
		}
	}
	return
}
