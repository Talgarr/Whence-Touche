package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestYkmanMatch(t *testing.T) {
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
			name: "oath code with account name",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash"},
				{PID: 2, Comm: "ykman", Args: []string{"ykman", "oath", "accounts", "code", "github"}},
			},
			wantOK:       true,
			wantTool:     "ykman",
			wantAction:   "OATH code",
			wantResource: "github",
			wantDepth:    1,
		},
		{
			name: "piv keys sign",
			tree: []classifier.Process{
				{PID: 1, Comm: "ykman", Args: []string{"ykman", "piv", "keys", "sign", "9a", "cert.pem"}},
			},
			wantOK:       true,
			wantTool:     "ykman",
			wantAction:   "PIV sign",
			wantResource: "YubiKey",
			wantDepth:    0,
		},
		{
			name: "gui yubico-authenticator",
			tree: []classifier.Process{
				{PID: 1, Comm: "systemd"},
				{PID: 2, Comm: "yubico-authent", Args: []string{"/usr/bin/yubico-authenticator"}},
			},
			wantOK:       true,
			wantTool:     "yubico-authenticator",
			wantAction:   "OATH code",
			wantResource: "TOTP",
			wantDepth:    1,
		},
		{
			name: "no match",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash"},
				{PID: 2, Comm: "ssh", Args: []string{"ssh", "host"}},
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Ykman{}.Match(tt.tree)
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
