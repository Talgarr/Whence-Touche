package classifier

import (
	"reflect"
	"testing"
)

// TestProcessName covers Name's resolution, especially looking through a shell
// to the script it runs so tools shipped as shell scripts (e.g. pass) are named
// after the tool, not "bash".
func TestProcessName(t *testing.T) {
	cases := []struct {
		name string
		p    Process
		want string
	}{
		{"binary argv0", Process{Comm: "gpg", Args: []string{"/usr/bin/gpg", "--sign"}}, "gpg"},
		{"comm fallback when no args", Process{Comm: "scdaemon"}, "scdaemon"},
		{"rewritten title takes first field", Process{Comm: "chromium", Args: []string{"/opt/chrome/chrome --type=gpu"}}, "chrome"},
		{"shell script is named after the script", Process{Comm: "bash", Args: []string{"bash", "/usr/bin/pass", "show", "x"}}, "pass"},
		{"shell script with interpreter flags", Process{Comm: "bash", Args: []string{"bash", "-e", "/nix/store/abc/bin/pass", "show"}}, "pass"},
		{"nix wrapper is unwrapped", Process{Comm: "bash", Args: []string{"bash", "/nix/store/abc/bin/.pass-wrapped", "show", "x"}}, "pass"},
		{"shell -c command names the command", Process{Comm: "bash", Args: []string{"bash", "-c", "gpg --sign"}}, "gpg"},
		{"bare shell stays the shell", Process{Comm: "bash", Args: []string{"bash"}}, "bash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Name(); got != tc.want {
				t.Errorf("Name() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestNormalizeShellArgs verifies a shell-script invocation is rewritten to read
// like a direct one, so downstream rules parse the tool's own arguments.
func TestNormalizeShellArgs(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"direct binary unchanged", []string{"/usr/bin/gpg", "--sign"}, []string{"/usr/bin/gpg", "--sign"}},
		{"shell script rewritten", []string{"bash", "/usr/bin/pass", "show", "x"}, []string{"pass", "show", "x"}},
		{"interpreter flags skipped", []string{"bash", "-e", "/nix/store/abc/bin/.pass-wrapped", "show", "x"}, []string{"pass", "show", "x"}},
		{"empty unchanged", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeShellArgs(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("NormalizeShellArgs(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
