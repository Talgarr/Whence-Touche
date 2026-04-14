package rules

import (
	"os"
	"path/filepath"

	"github.com/talgarr/yubikey-notifier/internal/classifier"
)

// Gopass matches gopass (https://github.com/gopasspw/gopass) operations.
// gopass is a fork of pass with additional subcommands.
type Gopass struct{}

func (Gopass) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "gopass")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := gopassOperation(p)
	return classifier.Classification{
		Tool:     "gopass",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func gopassOperation(p classifier.Process) (action, resource string) {
	sub, entry := parsePassArgs(p)

	switch sub {
	case "insert", "add":
		action = "encrypt"
	case "generate":
		action = "generate"
	case "create", "new":
		action = "create"
	case "edit":
		action = "edit"
	case "rm", "remove", "delete":
		action = "delete"
	case "copy", "cp":
		action = "copy"
	case "move", "mv":
		action = "move"
	case "git":
		action = "git sync"
	case "sync":
		action = "sync"
	case "recipients":
		action = "recipients"
	case "mounts", "mount", "umount":
		action = "mounts"
	case "exec-env", "env":
		action = "exec-env"
	default:
		// "gopass show GH_TOKEN" or "gopass GH_TOKEN" — sub is the entry
		action = "decrypt"
		if entry == "" {
			entry = sub
		}
	}

	if entry == "" {
		return action, "password"
	}
	return action, gopassStorePath(entry)
}

func gopassStorePath(entry string) string {
	// gopass respects PASSWORD_STORE_DIR for compatibility; otherwise defaults
	// to ~/.local/share/gopass/stores/root.
	if dir := os.Getenv("PASSWORD_STORE_DIR"); dir != "" {
		return filepath.Join(dir, entry)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return entry
	}
	return filepath.Join(home, ".local", "share", "gopass", "stores", "root", entry)
}
