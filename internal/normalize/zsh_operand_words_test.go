package normalize

import (
	"os"
	"path/filepath"
	"testing"
)

// TestZshOperandWordsStillScanned is the Codex pass-1 finding on #4627: once
// repeat is unwrapped, its count is no longer an argument of an unknown
// "repeat" executable, and main extracted it as a path. A protected path in
// that position went BLOCK -> AUDIT. normalize now reads the consumed words
// the same way, so unwrapping adds the real command and drops nothing main
// scanned.
func TestZshOperandWordsStillScanned(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	cwd := t.TempDir()
	tests := []struct {
		cmd  string
		want string
	}{
		{"repeat ~/.aws/credentials true", filepath.Join(home, ".aws/credentials")},
		{"noglob repeat ~/.aws/credentials true", filepath.Join(home, ".aws/credentials")},
		// Parity, not improvement: main read an assignment word as a plain
		// argument, so it lands cwd-relative here too.
		{"repeat 2 FOO=/etc/shadow true", filepath.Join(cwd, "FOO=/etc/shadow")},
		// Codex pass 2: a wrapper behind the zsh word or =word.
		{"noglob env -u ~/.aws/credentials true", filepath.Join(home, ".aws/credentials")},
		{"=env -u ~/.aws/credentials true", filepath.Join(home, ".aws/credentials")},
		{"repeat 1 env -u ~/.aws/credentials true", filepath.Join(home, ".aws/credentials")},
	}
	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			paths := NormalizeCommand(tt.cmd, cwd).Paths
			for _, p := range paths {
				if p == tt.want {
					return
				}
			}
			t.Errorf("NormalizeCommand(%q).Paths = %q, want it to include %q", tt.cmd, paths, tt.want)
		})
	}
}
