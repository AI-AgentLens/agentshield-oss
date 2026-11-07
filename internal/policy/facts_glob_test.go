package policy

import (
	"path"
	"testing"
)

// TestPSGlob_TrailingDoubleStar: `dir/**` is dir and anything under it, on
// paths_any, values_any and a call's values; a pattern without it is
// unchanged. A binary that predates it reads `**` as `*`: one level, so
// fewer matches, never other ones.
func TestPSGlob_TrailingDoubleStar(t *testing.T) {
	g := asciiFold("?:/Windows/**")
	for _, p := range []string{"C:/Windows", "c:/windows/", "C:/Windows/System32", "D:/WINDOWS/System32/drivers/etc/x.sys"} {
		if !psGlobMatches(g, p) {
			t.Errorf("%q should match %q", g, p)
		}
	}
	for _, p := range []string{"C:/WindowsApps", "C:/", "C:", "C:/Users/Windows", "Windows/System32", ""} {
		if psGlobMatches(g, p) {
			t.Errorf("%q should not match %q", g, p)
		}
	}
	any := asciiFold("**/classes/ms-settings/**")
	for _, p := range []string{"HKCU:/Software/Classes/ms-settings", "Registry::HKEY_CURRENT_USER/Software/Classes/ms-settings/Shell/Open/command"} {
		if !psGlobMatches(any, p) {
			t.Errorf("%q should match %q", any, p)
		}
	}
	if psGlobMatches(any, "HKCU:/Software/Classes/ms-settings-x/Shell") {
		t.Error("a sibling with a longer name matched")
	}
	// Without the suffix: exactly path.Match, as before.
	if psGlobMatches(asciiFold("?:/Windows/*"), "C:/Windows/System32/drivers") {
		t.Error("`*` crossed a separator")
	}
	// What an older binary reads: `**` as `*`, one level, a subset.
	old := func(glob, p string) bool { ok, _ := path.Match(glob, asciiFold(p)); return ok }
	for _, p := range []string{"C:/Windows", "C:/Windows/System32", "C:/Windows/System32/drivers", "C:/WindowsApps"} {
		if old(g, p) && !psGlobMatches(g, p) {
			t.Errorf("an older binary matches %q and this one does not", p)
		}
	}
}
