package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestOnePasswordMatch(t *testing.T) {
	cases := []struct {
		name         string
		tree         []classifier.Process
		wantTool     string
		wantAction   string
		wantResource string
		wantDepth    int
		wantOK       bool
	}{
		{
			name: "1password desktop app matches",
			tree: []classifier.Process{
				{PID: 1, Comm: "systemd", Args: []string{"/sbin/init"}},
				{PID: 2, Comm: "1password", Args: []string{"/opt/1Password/1password"}},
			},
			wantTool:     "1password",
			wantAction:   "authenticate",
			wantResource: "1Password",
			wantDepth:    1,
			wantOK:       true,
		},
		{
			name: "op CLI matches",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"bash"}},
				{PID: 2, Comm: "op", Args: []string{"op", "item", "get", "GitHub"}},
			},
			wantTool:     "1password",
			wantAction:   "authenticate",
			wantResource: "1Password",
			wantDepth:    1,
			wantOK:       true,
		},
		{
			name: "no match returns false",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"bash"}},
				{PID: 2, Comm: "gpg", Args: []string{"gpg", "--sign"}},
			},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := OnePassword{}.Match(tc.tree)
			if ok != tc.wantOK {
				t.Fatalf("Match() ok = %v, want %v", ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if got.Tool != tc.wantTool {
				t.Errorf("Tool = %q, want %q", got.Tool, tc.wantTool)
			}
			if got.Action != tc.wantAction {
				t.Errorf("Action = %q, want %q", got.Action, tc.wantAction)
			}
			if got.Resource != tc.wantResource {
				t.Errorf("Resource = %q, want %q", got.Resource, tc.wantResource)
			}
			if got.Depth != tc.wantDepth {
				t.Errorf("Depth = %d, want %d", got.Depth, tc.wantDepth)
			}
		})
	}
}
