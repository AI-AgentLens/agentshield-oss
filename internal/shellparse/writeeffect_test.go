package shellparse

import "testing"

// TestHasPrefixWithBoundary is the unit-level regression for #3534: bare
// strings.HasPrefix let an allowlisted token match as a substring of an
// unrelated program name (`ls` matches `lsyncd`). hasPrefixWithBoundary is
// the primitive both PrefixRuleMatches and AllStatementsHavePrefix now use
// on the ALLOW path.
func TestHasPrefixWithBoundary(t *testing.T) {
	cases := []struct {
		name    string
		s       string
		prefix  string
		want    bool
		comment string
	}{
		// --- exact / space-delimited matches keep matching ---
		{"exact match", "ls", "ls", true, "prefix == whole string"},
		{"space-separated arg", "ls -la", "ls", true, "next char is a space, a boundary"},
		{"prefix already ends in space", "grep -rn foo .", "grep ", true, "trailing space in prefix is itself a boundary"},

		// --- the #3534 empirical cases: bare prefix must NOT match a longer program name ---
		{"lsyncd not ls", "lsyncd /etc/lsyncd.conf", "ls", false, "ls is a substring of lsyncd, not a token"},
		{"lsyncd payload script", "lsyncd-with-a-payload.sh", "ls", false, "attacker-controlled filename"},
		{"pwdx not pwd", "pwdx 1234", "pwd", false, "pwdx is a distinct program"},
		{"idmapd not id", "idmapd -f", "id", false, "idmapd is a distinct program"},
		{"idevicebackup2 not id", "idevicebackup2 backup /tmp/dump", "id", false, "idevicebackup2 is a distinct program"},
		{"dfu-util not df", "dfu-util -D firmware.bin", "df", false, "dfu-util is a distinct program"},
		{"dumpe2fs not du", "dumpe2fs /dev/disk1", "du", false, "dumpe2fs is a distinct program"},
		{"freeradius not free", "freeradius -X", "free", false, "freeradius is a distinct program"},
		{"dateutils.dconv not date", "dateutils.dconv x", "date", false, "dateutils.dconv is a distinct program"},
		{"uptimed not uptime", "uptimed -f", "uptime", false, "uptimed is a distinct program"},
		{"unamex not uname", "unamex", "uname", false, "unrelated but shares the prefix"},

		// --- non-matching prefix entirely ---
		{"no prefix match", "touch /tmp/x", "ls", false, "prefix absent"},

		// --- boundary characters other than space ---
		{"slash is a boundary char", "ls/subdir", "ls", true, "/ ends a word just like space does — this is a boundary decision, not a claim ls/subdir is a real invocation"},
		{"empty prefix never matches", "ls -la", "", false, "empty prefix is degenerate, must not vacuously match"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := hasPrefixWithBoundary(tc.s, tc.prefix)
			if got != tc.want {
				t.Errorf("hasPrefixWithBoundary(%q, %q) = %v, want %v (%s)",
					tc.s, tc.prefix, got, tc.want, tc.comment)
			}
		})
	}
}

// TestAllStatementsHavePrefixRejectsLaunderedProgramNames pins the compound
// shape of #3534: a genuinely read-only first statement must not vouch for a
// second statement whose program name merely starts with the same token.
func TestAllStatementsHavePrefixRejectsLaunderedProgramNames(t *testing.T) {
	prefixes := []string{"ls", "pwd", "id", "df", "du", "free", "uname", "date", "uptime"}

	laundered := []string{
		"ls -la && lsyncd /etc/lsyncd.conf",
		"pwd && pwdx 1234",
		"id && idmapd -f",
		"df -h && dfu-util -D firmware.bin",
		"du -sh . && dumpe2fs /dev/disk1",
	}
	for _, cmd := range laundered {
		if AllStatementsHavePrefix(cmd, prefixes) {
			t.Errorf("%q: a laundered program-name suffix must not satisfy AllStatementsHavePrefix", cmd)
		}
	}

	genuine := []string{
		"ls -la && pwd",
		"id && uname -a",
		"df -h && du -sh .",
	}
	for _, cmd := range genuine {
		if !AllStatementsHavePrefix(cmd, prefixes) {
			t.Errorf("%q: every statement is a genuine read-only command, want true", cmd)
		}
	}
}
