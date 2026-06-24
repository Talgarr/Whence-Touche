// Package classifier identifies the tool, action, and resource behind a
// YubiKey touch request by inspecting the process call tree.
package classifier

import (
	"path/filepath"
	"strings"
)

// Process is one node in the call tree, oldest ancestor first.
type Process struct {
	PID  uint32
	Comm string   // kernel comm (up to 15 chars)
	Args []string // argv from /proc/PID/cmdline; may be empty for kernel threads
}

// shells are interpreters we look through: a process running `bash /usr/bin/pass`
// is, for classification, "pass" — the script it runs, not the interpreter.
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true,
	"ksh": true, "ash": true, "fish": true,
}

// Name returns the most precise process name: the basename of argv[0] when
// present, the kernel comm otherwise. Args are first run through
// NormalizeShellArgs, so a tool shipped as a shell script — e.g. pass, seen as
// `bash /usr/bin/pass …` — is named after the tool, not the interpreter.
func (p Process) Name() string {
	if base := argv0Base(NormalizeShellArgs(p.Args)); base != "" {
		return base
	}
	return p.Comm
}

// NormalizeShellArgs rewrites a shell-script invocation to read like a direct
// one: `bash -e /usr/bin/pass show x` becomes `[pass show x]`. This makes a tool
// shipped as a shell script classify by name AND parse its own arguments (rather
// than the interpreter's). Non-shell invocations are returned unchanged.
// proctree applies this when building the tree, so every rule sees clean argv.
func NormalizeShellArgs(args []string) []string {
	base := argv0Base(args)
	if base == "" || !shells[base] {
		return args
	}
	// The first non-flag argument is the script the shell runs (or the first
	// word of a -c command); rewrite it as argv[0] with its arguments after it.
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		out := make([]string, 0, len(args)-i)
		out = append(out, denixWrapper(filepath.Base(firstField(a))))
		out = append(out, args[i+1:]...)
		return out
	}
	return args
}

// argv0Base is the de-wrapped basename of the first field of argv[0], or "".
// argv[0] may be a rewritten process title holding the whole command line (e.g.
// Chromium has no NUL separators), so take its first field.
func argv0Base(args []string) string {
	if len(args) == 0 {
		return ""
	}
	ff := firstField(args[0])
	if ff == "" {
		return ""
	}
	return denixWrapper(filepath.Base(ff))
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

// denixWrapper unwraps Nix's wrapper naming: wrapProgram moves a program `foo`
// to `.foo-wrapped` and ships a `foo` wrapper; the running process often shows
// as `.foo-wrapped`, so map it back to `foo`.
func denixWrapper(name string) string {
	if strings.HasPrefix(name, ".") && strings.HasSuffix(name, "-wrapped") {
		return name[1 : len(name)-len("-wrapped")]
	}
	return name
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
