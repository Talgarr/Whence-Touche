package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Age matches age/rage file encryption/decryption operations.
type Age struct{}

func (Age) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "age", "rage")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := ageOperation(p)
	return classifier.Classification{
		Tool:     "age",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func ageOperation(p classifier.Process) (action, resource string) {
	action = "decrypt"
	resource = "encrypted file"

	for i, arg := range p.Args {
		if i == 0 {
			continue
		}
		switch arg {
		case "-e", "--encrypt":
			action = "encrypt"
		case "-d", "--decrypt":
			action = "decrypt"
		case "-o", "--output":
			// next arg is the output file, skip
		default:
			if !strings.HasPrefix(arg, "-") {
				resource = arg
			}
		}
	}
	return
}
