package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Pass matches password-store (https://www.passwordstore.org/) operations.
type Pass struct{}

func (Pass) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "pass")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := passOperation(p)
	return classifier.Classification{
		Tool:     "pass",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func passOperation(p classifier.Process) (action, resource string) {
	sub, entry := parsePassArgs(p)

	switch sub {
	case "insert", "add":
		action = "encrypt"
	case "generate":
		action = "generate"
	case "edit":
		action = "edit"
	case "rm", "remove", "delete":
		action = "delete"
	case "git":
		action = "git sync"
	default:
		// "pass show GH_TOKEN" or "pass GH_TOKEN" — sub is the entry
		action = "decrypt"
		if entry == "" {
			entry = sub
		}
	}

	if entry == "" {
		return action, "password"
	}
	return action, passwordStorePath(entry)
}

func parsePassArgs(p classifier.Process) (sub, entry string) {
	for _, arg := range p.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		if sub == "" {
			sub = arg
			continue
		}
		if entry == "" {
			entry = arg
			return
		}
	}
	return
}

func passwordStorePath(entry string) string {
	storeDir := os.Getenv("PASSWORD_STORE_DIR")
	if storeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return entry
		}
		storeDir = filepath.Join(home, ".password-store")
	}
	return filepath.Join(storeDir, entry)
}
