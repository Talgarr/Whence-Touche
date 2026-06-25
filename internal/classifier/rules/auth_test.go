package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestAuthMatch(t *testing.T) {
	tests := []struct {
		name     string
		tree     []classifier.Process
		wantTool string
		wantRes  string
		wantDep  int
		wantOK   bool
	}{
		{
			name: "sudo apt update",
			tree: []classifier.Process{
				{PID: 1, Comm: "sudo", Args: []string{"sudo", "apt", "update"}},
			},
			wantTool: "sudo",
			wantRes:  "apt update",
			wantDep:  0,
			wantOK:   true,
		},
		{
			name: "su someuser",
			tree: []classifier.Process{
				{PID: 1, Comm: "su", Args: []string{"su", "someuser"}},
			},
			wantTool: "su",
			wantRes:  "someuser",
			wantDep:  0,
			wantOK:   true,
		},
		{
			name: "swaylock screen locker",
			tree: []classifier.Process{
				{PID: 1, Comm: "swaylock", Args: []string{"swaylock"}},
			},
			wantTool: "swaylock",
			wantRes:  "unlock session",
			wantDep:  0,
			wantOK:   true,
		},
		{
			name: "gdm-session-worker via comm only",
			tree: []classifier.Process{
				{PID: 1, Comm: "gdm-session-wor", Args: nil},
			},
			wantTool: "gdm-session-wor",
			wantRes:  "login",
			wantDep:  0,
			wantOK:   true,
		},
		{
			name: "sudo nested in a deeper tree",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"bash"}},
				{PID: 2, Comm: "sudo", Args: []string{"sudo", "-u", "deploy", "systemctl", "restart", "nginx"}},
			},
			wantTool: "sudo",
			wantRes:  "deploy systemctl restart nginx",
			wantDep:  1,
			wantOK:   true,
		},
		{
			name: "no matching names",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"bash"}},
				{PID: 2, Comm: "vim", Args: []string{"vim", "notes.txt"}},
			},
			wantOK: false,
		},
		{
			name: "sshd is not stolen",
			tree: []classifier.Process{
				{PID: 1, Comm: "sshd", Args: []string{"sshd"}},
			},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Auth{}.Match(tt.tree)
			if ok != tt.wantOK {
				t.Fatalf("Match ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.Tool != tt.wantTool {
				t.Errorf("Tool = %q, want %q", got.Tool, tt.wantTool)
			}
			if got.Action != "authenticate" {
				t.Errorf("Action = %q, want %q", got.Action, "authenticate")
			}
			if got.Resource != tt.wantRes {
				t.Errorf("Resource = %q, want %q", got.Resource, tt.wantRes)
			}
			if got.Depth != tt.wantDep {
				t.Errorf("Depth = %d, want %d", got.Depth, tt.wantDep)
			}
		})
	}
}
