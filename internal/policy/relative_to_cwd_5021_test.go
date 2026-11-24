package policy

import (
	"path/filepath"
	"testing"
)

// relativeToCwd's own truth table on every OS (#5021, P-b). filepath.Rel
// answers in the OS separator, so a path outside cwd is "../x" on unix and
// "..\x" on Windows; both are refused. A name that merely starts with ".."
// is under cwd and is kept.
func TestRelativeToCwd_5021(t *testing.T) {
	root := t.TempDir()
	cwd := filepath.Join(root, "a", "b")
	for _, tc := range []struct {
		name, path string
		want       string // "" means refused
	}{
		{"under cwd", filepath.Join(cwd, "x"), "x"},
		{"cwd itself", cwd, "."},
		{"a child named ..x", filepath.Join(cwd, "..x", "y"), filepath.Join("..x", "y")},
		{"a child named x..", filepath.Join(cwd, "x..", "y"), filepath.Join("x..", "y")},
		{"relative, joined onto cwd", "secrets/token", filepath.Join("secrets", "token")},
		{"the parent", filepath.Join(root, "a"), ""},
		{"a sibling", filepath.Join(root, "a", "c"), ""},
		{"two levels up", filepath.Join(root, "org-token"), ""},
		{"relative, climbing out", "../org-token", ""},
		{"relative, climbing out twice", "../../org-token", ""},
	} {
		got, ok := relativeToCwd(tc.path, "secrets/**", cwd, root)
		if tc.want == "" {
			if ok {
				t.Errorf("%s: relativeToCwd(%s) = %q, kept; want refused (outside cwd)", tc.name, tc.path, got)
			}
			continue
		}
		if !ok || got != tc.want {
			t.Errorf("%s: relativeToCwd(%s) = %q, %v; want %q", tc.name, tc.path, got, ok, tc.want)
		}
	}
}
