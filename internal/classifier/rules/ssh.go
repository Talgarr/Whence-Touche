package rules

import (
	"strings"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// SSH matches FIDO2 SSH authentication (ssh-sk-helper in tree) and
// plain SSH sessions. Depth is set to the deepest SSH-related process found.
type SSH struct{}

func (SSH) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, _, ok := classifier.FindFirst(tree, "ssh-sk-helper", "ssh", "scp", "sftp", "sshd")
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     "ssh",
		Action:   "authenticate",
		Resource: sshResource(tree),
		Depth:    idx,
	}, true
}

// sshResource extracts the remote host from the ssh invocation args.
func sshResource(tree []classifier.Process) string {
	for _, name := range []string{"ssh", "scp", "sftp"} {
		p, ok := classifier.Find(tree, name)
		if !ok {
			continue
		}
		for i, arg := range p.Args {
			if i == 0 || strings.HasPrefix(arg, "-") {
				continue
			}
			if strings.Contains(arg, "@") {
				return strings.SplitN(arg, "@", 2)[1]
			}
			return arg
		}
	}
	return "SSH key"
}
