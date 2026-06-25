package rules

import (
	"testing"

	"github.com/Talgarr/Whence-Touche/internal/classifier"
)

func TestCosignMatch(t *testing.T) {
	cases := []struct {
		name         string
		comm         string
		args         []string
		wantOK       bool
		wantTool     string
		wantAction   string
		wantResource string
		wantDepth    int
	}{
		{
			name:         "sign image reference",
			comm:         "cosign",
			args:         []string{"cosign", "sign", "ghcr.io/acme/app:1.0"},
			wantOK:       true,
			wantTool:     "cosign",
			wantAction:   "sign",
			wantResource: "ghcr.io/acme/app:1.0",
			wantDepth:    0,
		},
		{
			name:         "sign-blob with key flag and file",
			comm:         "cosign",
			args:         []string{"cosign", "sign-blob", "--key", "pkcs11:object=signing", "artifact.tar"},
			wantOK:       true,
			wantTool:     "cosign",
			wantAction:   "sign blob",
			wantResource: "artifact.tar",
			wantDepth:    0,
		},
		{
			name:   "no match",
			comm:   "bash",
			args:   []string{"bash", "-c", "echo hi"},
			wantOK: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := []classifier.Process{{PID: 100, Comm: tc.comm, Args: tc.args}}
			got, ok := Cosign{}.Match(tree)
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
