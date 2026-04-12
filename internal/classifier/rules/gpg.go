package rules

import (
	"github.com/talgarr/yubikey-notifier-v2/internal/classifier"
)

// GPG matches GPG/GPG2 operations routed through gpg-agent and scdaemon.
type GPG struct{}

func (GPG) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, _, ok := classifier.FindFirst(tree, "gpg", "gpg2", "gpg-agent", "scdaemon")
	if !ok {
		return classifier.Classification{}, false
	}
	action, resource := gpgOperation(tree)
	return classifier.Classification{
		Tool:     "gpg",
		Action:   action,
		Resource: resource,
		Depth:    idx,
	}, true
}

func gpgOperation(tree []classifier.Process) (action, resource string) {
	action = "sign/decrypt"
	resource = "GPG key"

	for _, name := range []string{"gpg", "gpg2"} {
		p, ok := classifier.Find(tree, name)
		if !ok {
			continue
		}
		for i, arg := range p.Args {
			switch arg {
			case "--decrypt", "-d":
				action = "decrypt"
				if i+1 < len(p.Args) {
					resource = p.Args[i+1]
				}
			case "--sign", "-s", "--clearsign", "--detach-sign":
				action = "sign"
				if i+1 < len(p.Args) {
					resource = p.Args[i+1]
				}
			case "--verify":
				action = "verify"
			case "--encrypt", "-e":
				action = "encrypt"
			case "--recipient", "-r":
				if i+1 < len(p.Args) {
					resource = p.Args[i+1]
				}
			}
		}
		return
	}
	return
}
