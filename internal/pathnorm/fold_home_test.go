package pathnorm

import "testing"

func TestFoldHomeVar(t *testing.T) {
	cases := []struct{ in, want string }{
		{"$HOME", "~"},
		{"${HOME}", "~"},
		{"$HOME/x/y", "~/x/y"},
		{"${HOME}/x/y", "~/x/y"},
		// Not a home reference: the name continues past HOME.
		{"$HOMEBREW_PREFIX/bin", "$HOMEBREW_PREFIX/bin"},
		{"$HOMEDIR", "$HOMEDIR"},
		{"${HOMEBREW_PREFIX}/bin", "${HOMEBREW_PREFIX}/bin"},
		// Not at the front: only a leading reference names the home root.
		{"/opt/$HOME/x", "/opt/$HOME/x"},
		{"~/x", "~/x"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := FoldHomeVar(tc.in); got != tc.want {
			t.Errorf("FoldHomeVar(%q) = %q; want %q", tc.in, got, tc.want)
		}
	}
}
