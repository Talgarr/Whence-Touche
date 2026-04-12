// Package classifier identifies the tool, action, and resource behind a
// YubiKey touch request by inspecting the process call tree.
package classifier

import "path/filepath"

// Process is one node in the call tree, oldest ancestor first.
type Process struct {
	PID  uint32
	Comm string   // kernel comm (up to 15 chars)
	Args []string // argv from /proc/PID/cmdline; may be empty for kernel threads
}

// Name returns the most precise process name: basename of argv[0] when
// present, kernel comm otherwise.
func (p Process) Name() string {
	if len(p.Args) > 0 {
		return filepath.Base(p.Args[0])
	}
	return p.Comm
}

// Classification is the structured output produced by a Rule.
type Classification struct {
	Tool     string // e.g. "ssh", "gpg", "git", "sops", "firefox"
	Action   string // e.g. "authenticate", "decrypt", "push"
	Resource string // e.g. "github.com/talgarr/test", "~/.password-store/GH_TOKEN"
	Depth    int    // index of the matched process in tree (0 = oldest ancestor)
}

// Rule is implemented once per tool in the rules/ sub-package.
// Match returns a Classification and true if this rule applies to tree.
// Classification.Depth must be set to the tree index of the matched process.
type Rule interface {
	Match(tree []Process) (Classification, bool)
}

// Classify evaluates every rule and returns the match with the lowest Depth
// (shallowest in the process tree — the most user-facing tool).
// When two rules match at the same depth, the one listed first in rules wins.
// Returns (zero, false) when no rule matches.
func Classify(rules []Rule, tree []Process) (Classification, bool) {
	best := len(tree) // sentinel: larger than any valid index
	var result Classification
	found := false
	for _, r := range rules {
		c, ok := r.Match(tree)
		if !ok || c.Depth >= best {
			continue
		}
		best = c.Depth
		result = c
		found = true
	}
	return result, found
}

// FindFirst returns the index and process of the shallowest (first) occurrence
// of any of the given names in tree.
func FindFirst(tree []Process, names ...string) (int, Process, bool) {
	for i, p := range tree {
		for _, name := range names {
			if p.Name() == name || p.Comm == name {
				return i, p, true
			}
		}
	}
	return 0, Process{}, false
}

// FindLast returns the index and process of the deepest (last) occurrence
// of any of the given names in tree. Searches from deepest to shallowest.
func FindLast(tree []Process, names ...string) (int, Process, bool) {
	for i := len(tree) - 1; i >= 0; i-- {
		p := tree[i]
		for _, name := range names {
			if p.Name() == name || p.Comm == name {
				return i, p, true
			}
		}
	}
	return 0, Process{}, false
}

// Find returns the shallowest (first) occurrence of any given name in tree.
func Find(tree []Process, name string) (Process, bool) {
	for _, p := range tree {
		if p.Name() == name || p.Comm == name {
			return p, true
		}
	}
	return Process{}, false
}

// Has reports whether any process in tree matches name.
func Has(tree []Process, name string) bool {
	_, ok := Find(tree, name)
	return ok
}

// Arg returns the value of a named flag in a process's argv.
// Handles "--flag value" and "--flag=value" styles.
func Arg(p Process, flags ...string) (string, bool) {
	for i, a := range p.Args {
		for _, f := range flags {
			if a == f && i+1 < len(p.Args) {
				return p.Args[i+1], true
			}
			if len(a) > len(f)+1 && a[:len(f)+1] == f+"=" {
				return a[len(f)+1:], true
			}
		}
	}
	return "", false
}

// FirstPositional returns the first non-flag argument after argv[0].
func FirstPositional(p Process) string {
	for _, a := range p.Args[1:] {
		if len(a) > 0 && a[0] != '-' {
			return a
		}
	}
	return ""
}
