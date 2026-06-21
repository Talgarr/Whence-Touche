package rules

import (
	"os"
	"path/filepath"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Gopass matches gopass (https://github.com/gopasspw/gopass) operations.
// gopass is a fork of pass with additional subcommands.
type Gopass struct{}

// gopassCryptoBackend reports whether name is a backend gopass uses
// internally to load/decrypt secrets.
func gopassCryptoBackend(name string) bool {
	switch name {
	case "gpg", "gpg2", "age":
		return true
	}
	return false
}

// gopassNextProcess returns the name of the first non-gopass process after
// afterIdx in the tree. Gopass may spawn intermediate gopass subprocesses
// (e.g. "gopass show" inside "gopass env") before reaching the crypto backend,
// so we skip over them.
func gopassNextProcess(tree []classifier.Process, afterIdx int) (string, bool) {
	for _, p := range tree[afterIdx:] {
		if p.Name() != "gopass" {
			return p.Name(), true
		}
	}
	return "", false
}

func (Gopass) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, p, ok := classifier.FindFirst(tree, "gopass")
	if !ok {
		return classifier.Classification{}, false
	}
	sub, _ := parsePassArgs(p)
	if sub == "shell" || sub == "exec-env" || sub == "env" {
		// If gopass is running a shell-spawning subcommand and is still in the
		// tree, it should only match if it is currently in its loading phase
		// (the first non-gopass descendant is its own crypto backend). Once it
		// execs the user command via syscall.Exec, gopass disappears from the
		// tree and this branch is never reached. If gopass is fork-exec'ing
		// instead (e.g. gopass shell keeping alive as parent), the descendant
		// will be a shell — not a crypto backend — so we yield to other rules.
		next, ok := gopassNextProcess(tree, idx+1)
		if !ok || !gopassCryptoBackend(next) {
			return classifier.Classification{}, false
		}
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
