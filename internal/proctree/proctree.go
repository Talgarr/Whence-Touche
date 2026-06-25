// Package proctree reads process call trees from /proc.
package proctree

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	clsf "github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Walk walks /proc upward from pid and returns a slice of Process nodes,
// oldest ancestor first.  Must be called while the process is still alive.
func Walk(pid uint32) []clsf.Process {
	var chain []clsf.Process
	seen := make(map[uint32]bool)
	for p := pid; p > 1 && !seen[p]; {
		seen[p] = true
		comm, args, ppid := info(p)
		// Normalize shell-script invocations (e.g. `bash /usr/bin/pass show`)
		// so the tool — not the interpreter — names the process and its args
		// parse correctly.
		chain = append(chain, clsf.Process{PID: p, Comm: comm, Args: clsf.NormalizeShellArgs(args)})
		p = ppid
	}
	// Reverse: oldest ancestor first.
	for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
		chain[i], chain[j] = chain[j], chain[i]
	}
	return chain
}

// Format renders a process tree as "cmd arg…[pid] → cmd arg…[pid]".
func Format(tree []clsf.Process) string {
	parts := make([]string, len(tree))
	for i, p := range tree {
		name := p.Comm
		if len(p.Args) > 0 {
			name = strings.Join(p.Args, " ")
		}
		parts[i] = fmt.Sprintf("%s[%d]", name, p.PID)
	}
	return strings.Join(parts, " → ")
}

// info reads comm, argv, and parent PID for a process from /proc.
func info(pid uint32) (comm string, args []string, ppid uint32) {
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "Name:"):
				comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			case strings.HasPrefix(line, "PPid:"):
				fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")), "%d", &ppid)
			}
		}
	}
	if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil && len(raw) > 0 {
		for _, b := range bytes.Split(bytes.TrimRight(raw, "\x00"), []byte{0}) {
			if len(b) > 0 {
				args = append(args, string(b))
			}
		}
	}
	if comm == "" {
		comm = fmt.Sprintf("pid%d", pid)
	}
	return
}
