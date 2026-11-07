package policy

import (
	"path/filepath"
	"testing"
)

// A "/**" protected path covers the directory itself and everything under
// it, at any depth. On Windows expandHome yields backslash paths, and the
// directory and deep paths went unmatched: `ls ~/.ssh` was ALLOW on Windows
// and BLOCK on macOS (#4717). FromSlash gives each platform its native
// spelling, so on unix this pins today's behaviour and on Windows it pins
// the fix.
func TestProtectedPath_NativeSeparators(t *testing.T) {
	home := filepath.FromSlash("C:/Users/u")
	native := filepath.FromSlash
	key := "id_" + "ed25519"

	for _, path := range []string{
		"~/.ssh",
		"~/.ssh/",
		"~/.ssh/" + key,
		"~/.ssh/keys/deep/" + key,
		native("C:/Users/u/.ssh"),
		native("C:/Users/u/.ssh/keys/deep/" + key),
	} {
		if !protectedPathMatchesIn(home, path, "~/.ssh/**", "", false) {
			t.Errorf("%q: want a match for ~/.ssh/**", path)
		}
	}
	for _, path := range []string{
		"~/.sshx",
		"~/.ssh_backup/" + key,
		"~/x/.ssh",
		native("C:/Users/u/Documents/notes.txt"),
	} {
		if protectedPathMatchesIn(home, path, "~/.ssh/**", "", false) {
			t.Errorf("%q: want no match for ~/.ssh/**", path)
		}
	}

	// "/*" stays one level deep.
	if !protectedPathMatchesIn(home, "~/.kube/config", "~/.kube/*", "", false) {
		t.Error("~/.kube/config: want a match for ~/.kube/*")
	}
	if protectedPathMatchesIn(home, "~/.kube/cache/x", "~/.kube/*", "", false) {
		t.Error("~/.kube/cache/x: want no match for ~/.kube/*")
	}
}
