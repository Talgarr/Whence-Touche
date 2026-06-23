package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// KeePassXC matches KeePassXC (https://keepassxc.org/) database unlocks.
// A .kdbx database can be protected by a YubiKey/OnlyKey challenge-response
// (HMAC-SHA1) secondary key. When that slot is configured with "require
// touch", the key blinks and waits for a touch while the database is unlocked.
type KeePassXC struct{}

func (KeePassXC) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "keepassxc", "keepassxc-cli")
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     "keepassxc",
		Action:   "unlock",
		Resource: keepassxcResource(p),
		Depth:    idx,
	}, true
}

// keepassxcResource returns the database path: the first .kdbx argument when
// present, otherwise the first positional argument, otherwise "database".
func keepassxcResource(p classifier.Process) string {
	for _, arg := range p.Args {
		if strings.HasSuffix(arg, ".kdbx") {
			return arg
		}
	}
	if pos := classifier.FirstPositional(p); pos != "" {
		return pos
	}
	return "database"
}
