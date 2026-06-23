package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

// proc builds a Process with both Comm and Args set so Name() resolves to the
// argv[0] basename while Comm still satisfies the kernel-comm fallback.
func proc(comm string, args ...string) classifier.Process {
	return classifier.Process{Comm: comm, Args: args}
}

func TestKeePassXCMatch(t *testing.T) {
	cases := []struct {
		name         string
		tree         []classifier.Process
		wantOK       bool
		wantTool     string
		wantAction   string
		wantResource string
		wantDepth    int
	}{
		{
			name: "kdbx path resolves as resource",
			tree: []classifier.Process{
				proc("bash", "bash"),
				proc("keepassxc", "keepassxc", "/home/me/secrets.kdbx"),
			},
			wantOK:       true,
			wantTool:     "keepassxc",
			wantAction:   "unlock",
			wantResource: "/home/me/secrets.kdbx",
			wantDepth:    1,
		},
		{
			name: "keepassxc-cli matches and prefers kdbx over other positionals",
			tree: []classifier.Process{
				proc("keepassxc-cli", "keepassxc-cli", "open", "/vault/db.kdbx"),
			},
			wantOK:       true,
			wantTool:     "keepassxc",
			wantAction:   "unlock",
			wantResource: "/vault/db.kdbx",
			wantDepth:    0,
		},
		{
			name: "no kdbx falls back to first positional",
			tree: []classifier.Process{
				proc("keepassxc-cli", "keepassxc-cli", "show", "Email"),
			},
			wantOK:       true,
			wantTool:     "keepassxc",
			wantAction:   "unlock",
			wantResource: "show",
			wantDepth:    0,
		},
		{
			name: "no positional falls back to database",
			tree: []classifier.Process{
				proc("keepassxc", "keepassxc"),
			},
			wantOK:       true,
			wantTool:     "keepassxc",
			wantAction:   "unlock",
			wantResource: "database",
			wantDepth:    0,
		},
		{
			name: "tree without keepassxc does not match",
			tree: []classifier.Process{
				proc("bash", "bash"),
				proc("ssh", "ssh", "host"),
			},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := KeePassXC{}.Match(tc.tree)
			if ok != tc.wantOK {
				t.Fatalf("Match ok = %v, want %v", ok, tc.wantOK)
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
