package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestBitwardenMatch(t *testing.T) {
	cases := []struct {
		name      string
		tree      []classifier.Process
		wantOK    bool
		wantDepth int
	}{
		{
			name: "desktop bitwarden matches",
			tree: []classifier.Process{
				{PID: 1, Comm: "systemd", Args: []string{"/usr/lib/systemd/systemd"}},
				{PID: 2, Comm: "bitwarden", Args: []string{"/opt/Bitwarden/bitwarden"}},
			},
			wantOK:    true,
			wantDepth: 1,
		},
		{
			name: "bw CLI matches",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"/bin/bash"}},
				{PID: 2, Comm: "bw", Args: []string{"bw", "unlock"}},
			},
			wantOK:    true,
			wantDepth: 1,
		},
		{
			name: "tree without bitwarden returns false",
			tree: []classifier.Process{
				{PID: 1, Comm: "bash", Args: []string{"/bin/bash"}},
				{PID: 2, Comm: "ssh", Args: []string{"ssh", "host"}},
			},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := Bitwarden{}.Match(tc.tree)
			if ok != tc.wantOK {
				t.Fatalf("Match() ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Tool != "bitwarden" {
				t.Errorf("Tool = %q, want %q", got.Tool, "bitwarden")
			}
			if got.Action != "authenticate" {
				t.Errorf("Action = %q, want %q", got.Action, "authenticate")
			}
			if got.Resource != "Bitwarden vault" {
				t.Errorf("Resource = %q, want %q", got.Resource, "Bitwarden vault")
			}
			if got.Depth != tc.wantDepth {
				t.Errorf("Depth = %d, want %d", got.Depth, tc.wantDepth)
			}
		})
	}
}
