package shellparse

import "testing"

// TestDeglobEdgeWildcards_4410: a wildcard on the TAIL of a protected name
// pins that name and resolves; the interior-only builder left every one of
// these unresolved (cat /etc/shado? decided ALLOW).
func TestDeglobEdgeWildcards_4410(t *testing.T) {
	cases := []struct{ in, want string }{
		{"cat /etc/shado?", "cat /etc/shadow"},
		{"cat /etc/shad*", "cat /etc/shadow"},
		{"cat /etc/passw?", "cat /etc/passwd"},
		{"cat /etc/passw??", "cat /etc/passwd-"},
		{"cat ~/.netr?", "cat ~/.netrc"},
		{"cat ~/Passwords.kd?x", "cat ~/Passwords.kdbx"},
		{"cat ~/Passwords.kdb*", "cat ~/Passwords.kdbx"},
		{"cat ~/Passwords.kd[b]x", "cat ~/Passwords.kdbx"},
		{"cat /etc/shad[o]w", "cat /etc/shadow"},
	}
	for _, tc := range cases {
		found := false
		for _, alt := range DeglobSensitivePaths(tc.in) {
			if alt == tc.want {
				found = true
			}
		}
		if !found {
			t.Errorf("DeglobSensitivePaths(%q) = %v, want to contain %q", tc.in, DeglobSensitivePaths(tc.in), tc.want)
		}
	}
	if got := DeglobPath("/etc/shado?"); got != "/etc/shadow" {
		t.Errorf("DeglobPath(/etc/shado?) = %q", got)
	}
	if got := DeglobPath("/etc/shad[o]w"); got != "/etc/shadow" {
		t.Errorf("DeglobPath(/etc/shad[o]w) = %q", got)
	}
}

// TestDeglobEdgeWildcards_StayUnresolved_4410: a trailing wildcard that
// leaves fewer than minGlobEdgeLiteral bytes, a wildcard that is not last,
// and a quoted one match ordinary names too (or are not globbed) and must not
// resolve.
func TestDeglobEdgeWildcards_StayUnresolved_4410(t *testing.T) {
	for _, c := range []string{
		"cat /etc/s*",
		"cat ~/.n*",
		"du -sh ~/.*",
		"cat /etc/sha*",
		"cat /etc/shado?x",
		"cat '/etc/shado?'",
		"ls /etc/*",
		"cat [ab]file",
	} {
		if got := DeglobSensitivePaths(c); got != nil {
			t.Errorf("DeglobSensitivePaths(%q) = %v, want nil", c, got)
		}
		if got := DeglobPath(c); got != c {
			t.Errorf("DeglobPath(%q) = %q, want unchanged", c, got)
		}
	}
}

// TestHasUnresolvedGlobWord_4410 pins which words withhold an ALLOW.
func TestHasUnresolvedGlobWord_4410(t *testing.T) {
	yes := []string{
		"cat /etc/shado?",
		"ls *.go",
		"cat file[0-9]",
		"find . -name *.go",
		"grep x a.txt b*",
		"echo hi > out*",
		"echo 'unterminated",
	}
	for _, c := range yes {
		if !HasUnresolvedGlobWord(c) {
			t.Errorf("HasUnresolvedGlobWord(%q) = false, want true", c)
		}
		if !AllowDisqualified(c) {
			t.Errorf("AllowDisqualified(%q) = false, want true", c)
		}
	}
	no := []string{
		"ls -la",
		`echo "a ? b"`,
		`echo 'a * b'`,
		"FOO=* ls",
		"cat <<'EOF'\n* x\nEOF",
		"cat <<EOF\n* x ? y\nEOF",
		"cat <<< 'a*'",
		"grep -rn 'TODO*' .",
		"echo a[b",
		"   ",
	}
	for _, c := range no {
		if HasUnresolvedGlobWord(c) {
			t.Errorf("HasUnresolvedGlobWord(%q) = true, want false", c)
		}
	}
}
