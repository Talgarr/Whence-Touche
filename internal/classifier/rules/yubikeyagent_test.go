package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestYubiKeyAgent(t *testing.T) {
	tests := []struct {
		name         string
		tree         []classifier.Process
		wantOK       bool
		wantTool     string
		wantAction   string
		wantResource string
		wantDepth    int
	}{
		{
			name: "yubikey-agent serving an SSH authentication",
			tree: []classifier.Process{
				{PID: 1, Comm: "systemd", Args: []string{"/usr/lib/systemd/systemd"}},
				{PID: 42, Comm: "yubikey-agent", Args: []string{"/usr/bin/yubikey-agent", "-l", "/run/user/1000/yubikey-agent/yubikey-agent.sock"}},
			},
			wantOK:       true,
			wantTool:     "yubikey-agent",
			wantAction:   "ssh authenticate",
			wantResource: "PIV SSH key",
			wantDepth:    1,
		},
		{
			name: "plain ssh must not match this rule",
			tree: []classifier.Process{
				{PID: 1, Comm: "systemd", Args: []string{"/usr/lib/systemd/systemd"}},
				{PID: 99, Comm: "ssh", Args: []string{"ssh", "git@github.com"}},
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := YubiKeyAgent{}.Match(tt.tree)
			if ok != tt.wantOK {
				t.Fatalf("Match() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.Tool != tt.wantTool {
				t.Errorf("Tool = %q, want %q", got.Tool, tt.wantTool)
			}
			if got.Action != tt.wantAction {
				t.Errorf("Action = %q, want %q", got.Action, tt.wantAction)
			}
			if got.Resource != tt.wantResource {
				t.Errorf("Resource = %q, want %q", got.Resource, tt.wantResource)
			}
			if got.Depth != tt.wantDepth {
				t.Errorf("Depth = %d, want %d", got.Depth, tt.wantDepth)
			}
		})
	}
}
