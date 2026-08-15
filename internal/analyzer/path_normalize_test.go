package analyzer

import "testing"

// TestNormalizeTargetPath verifies shell-unquoting + path.Clean collapse
// path-equivalent spellings of dangerous targets while leaving benign and
// dynamic paths intact.
func TestNormalizeTargetPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{`"/"`, "/"},
		{`'/'`, "/"},
		{`\/`, "/"},
		{"/.", "/"},
		{"/./", "/"},
		{"//", "/"},
		{"/home/../", "/"},
		{"/tmp/..", "/"},
		{`"/etc"`, "/etc"},
		{"/etc/", "/etc"},
		{"/*", "/*"},
		{"/", "/"},
		// Benign paths preserved (not collapsed to root/system).
		{"./build", "build"},
		{"node_modules", "node_modules"},
		{"./dist/../out", "out"},
		{"../sibling", "../sibling"},
		{"/home/user/project", "/home/user/project"},
		// Dynamic values left untouched.
		{"$BUILD_DIR", "$BUILD_DIR"},
		{"$(pwd)/build", "$(pwd)/build"},
		{"`echo /`", "`echo /`"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := normalizeTargetPath(tt.in); got != tt.want {
			t.Errorf("normalizeTargetPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestRootAndSystemTargetEvasion locks in that equivalent spellings of root /
// system dirs are recognized while benign relative paths are not.
func TestRootAndSystemTargetEvasion(t *testing.T) {
	root := []string{`"/"`, `'/'`, `\/`, "/.", "/./", "//", "/home/../", "/tmp/..", "/*"}
	for _, p := range root {
		if !isRootTarget(p) {
			t.Errorf("isRootTarget(%q) = false, want true", p)
		}
	}
	notRoot := []string{"./build", "node_modules", "../sibling", "/home/user/x", "$BUILD_DIR"}
	for _, p := range notRoot {
		if isRootTarget(p) {
			t.Errorf("isRootTarget(%q) = true, want false", p)
		}
	}
	sys := []string{`"/etc"`, "/etc/", "/usr/../etc", "/var/log/"}
	for _, p := range sys {
		if !isSystemDir(p) {
			t.Errorf("isSystemDir(%q) = false, want true", p)
		}
	}
	notSys := []string{"/etc-backup", "/home/user/etc", "./var", "$DIR"}
	for _, p := range notSys {
		if isSystemDir(p) {
			t.Errorf("isSystemDir(%q) = true, want false", p)
		}
	}
}
