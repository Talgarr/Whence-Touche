package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// Git matches git operations that require a YubiKey touch:
// push/pull/fetch over SSH and signed commits via GPG.
type Git struct{}

func (Git) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, _, ok := classifier.FindFirst(tree, "git")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := gitOperation(tree)
	return classifier.Classification{
		Tool:     "git",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func gitOperation(tree []classifier.Process) (action, resource string) {
	action = "git operation"
	resource = "repository"

	p, ok := classifier.Find(tree, "git")
	if !ok {
		return
	}

	sub := ""
	for _, arg := range p.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			sub = arg
			break
		}
	}

	switch sub {
	case "push":
		return "push", gitRemote(p, "origin")
	case "pull":
		return "pull", gitRemote(p, "origin")
	case "fetch":
		return "fetch", gitRemote(p, "origin")
	case "clone":
		for i, arg := range p.Args {
			if arg == "clone" && i+1 < len(p.Args) {
				return "clone", p.Args[i+1]
			}
		}
		return "clone", resource
	case "commit":
		return "sign commit", gitRemote(p, "origin")
	default:
		if sub != "" {
			action = sub
		}
		return action, gitRemote(p, "origin")
	}
}

// gitRemote reads the URL of remoteName from the repo config reachable via
// the git process's working directory.
func gitRemote(p classifier.Process, remoteName string) string {
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", p.PID))
	if err != nil {
		return remoteName
	}
	for dir := cwd; ; dir = filepath.Dir(dir) {
		data, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
		if err == nil {
			if url := parseRemoteURL(string(data), remoteName); url != "" {
				return url
			}
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	return remoteName
}

func parseRemoteURL(config, name string) string {
	header := fmt.Sprintf(`[remote "%s"]`, name)
	inSection := false
	for _, line := range strings.Split(config, "\n") {
		line = strings.TrimSpace(line)
		if line == header {
			inSection = true
			continue
		}
		if !inSection {
			continue
		}
		if strings.HasPrefix(line, "[") {
			return ""
		}
		after, ok := strings.CutPrefix(line, "url")
		if !ok {
			continue
		}
		after = strings.TrimSpace(after)
		if !strings.HasPrefix(after, "=") {
			continue
		}
		return strings.TrimSpace(after[1:])
	}
	return ""
}
