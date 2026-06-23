package rules

import (
	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// YubiKeyAgent matches yubikey-agent (github.com/FiloSottile/yubikey-agent), a
// standalone PIV ssh-agent. With touch-policy=always, every SSH authentication
// served by the agent triggers a touch.
//
// Design note: the requesting ssh client talks to yubikey-agent over a UNIX
// socket, so the ssh client is NOT an ancestor in this process tree — that is
// exactly why the generic SSH rule does not catch this case, and why this
// dedicated rule exists. The agent has no per-host context, so the Resource is
// static.
//
// See https://github.com/FiloSottile/yubikey-agent.
type YubiKeyAgent struct{}

func (YubiKeyAgent) Match(tree []classifier.Process) (classifier.Classification, bool) {
	idx, _, ok := classifier.FindFirst(tree, "yubikey-agent")
	if !ok {
		return classifier.Classification{}, false
	}
	return classifier.Classification{
		Tool:     "yubikey-agent",
		Action:   "ssh authenticate",
		Resource: "PIV SSH key",
		Depth:    idx,
	}, true
}
