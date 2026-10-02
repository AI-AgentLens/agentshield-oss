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

// TestHasFileWriteRedirect pins both directions of the #4082 predicate. A
// "writes" row that stopped being reported would hand ts-allow-readonly's
// ALLOW back to a file write; a "harmless" row that started being reported
// would cost a read-only command its ALLOW. The exemption rows are the
// direction that KEEPS an ALLOW, so they carry near-miss spellings too.
func TestHasFileWriteRedirect(t *testing.T) {
	writes := []struct{ cmd, why string }{
		{"echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv", "append to a startup file (the #4082 carrier)"},
		{"echo x > /etc/hosts", "truncating write"},
		{"cat site.conf > /etc/nginx/sites-enabled/site.conf", "cat is a copy once redirected"},
		{"printf 'x' >| out.txt", "clobber"},
		{"printf 'x' &> out.txt", "stdout+stderr to a file"},
		{"printf 'x' &>> out.txt", "append stdout+stderr to a file"},
		{"ls -la 2> errors.log", "n> to a path writes the file too"},
		{"echo x 1<> out.txt", "<> opens read-write and creates the file"},
		{"echo x >&out.txt", "bash reads >&word with a non-numeric word as &>word"},
		{"echo x >&4", "fd 4 is whatever the parent left open, not a stream the command owns"},
		{"echo x 1<&4", "N<&M with N != 0 is an output dup (bash implements both as dup2)"},
		{`echo x > "$OUT"`, "an expansion's value is unknown, so it is not provably /dev/null"},
		{`echo x > ${NULL:-/dev/null}`, "a default-value expansion is still an expansion"},
		{`echo x > /dev/nu\ll`, "an escape spelling loses the exemption rather than earning it"},
		{"echo x > /dev/null2", "near-miss of /dev/null"},
		{"echo x > /dev/tty", "only the three listed device paths are exempt"},
		{"echo a; { echo b; } > out.txt", "a group's redirect: SplitTopLevelStatements drops it, the walk must not"},
		{"echo a; (echo b) >> out.txt", "a subshell's redirect"},
		{"echo a; for i in 1 2; do echo $i; done > out.txt", "a loop's redirect"},
		{"cat <<'EOF' > notes.md\nhello\nEOF", "heredoc input does not excuse the output redirect"},
		{"echo 'unterminated > x", "unparseable: fails closed"},
		// #4088 pass 1 (Opus review): each row kills a mutant that survived
		// every grader before it was added.
		{"echo a >&0", "fd 0 is not an inherited OUTPUT stream (mutant: treat >&0 as harmless)"},
		{`echo x >&$OUT`, ">&word with an expansion is a file write whose target is unknown (pass-2 mutant G6: non-literal >& target treated as harmless)"},
		{"echo a > ./dev/null", "a relative dev/null is a file (mutant: exempt any path ending in /dev/null)"},
		{"echo a > build/dev/null", "a relative dev/null is a file (same mutant)"},
		{"echo a > $HOME/dev/null", "an expansion prefix keeps the target unknown (mutant: skip expansion parts, keep literals)"},
		{"echo a; { echo b > out.txt; }", "a redirect INSIDE a group body (mutant: no descent into compound bodies)"},
		{"echo a; if true; then echo b > out.txt; fi", "a redirect inside an if body (same mutant)"},
		{"echo a; while false; do echo b > out.txt; done", "a redirect inside a loop body (same mutant)"},
	}
	for _, tc := range writes {
		if !HasFileWriteRedirect(tc.cmd) {
			t.Errorf("HasFileWriteRedirect(%q) = false, want true (%s)", tc.cmd, tc.why)
		}
	}

	harmless := []struct{ cmd, why string }{
		{"echo hi", "no redirect"},
		{"cat README.md", "no redirect"},
		{"echo x > /dev/null", "null device"},
		{"echo x >> /dev/null", "null device, append"},
		{`echo x > "/dev/null"`, "quote removal applies: this IS /dev/null"},
		{"echo x > '/dev/stderr'", "quoted inherited stream"},
		{"echo x > /dev/stdout", "inherited stream"},
		{"grep -rn foo . 2>/dev/null", "stderr to the null device"},
		{"ls /nope &> /dev/null", "both streams to the null device"},
		{`printf '%s\n' foo 2>&1`, "fd dup onto stdout"},
		{"echo done >&2", "fd dup onto stderr"},
		{"echo done 1>&-", "close"},
		{"wc -l < /etc/hosts", "input redirect"},
		{"wc -c <<< hello", "here-string"},
		{"cat <<'EOF'\nhello\nEOF", "heredoc to stdout"},
		{"cat <&3", "input dup onto stdin reads"},
		{`echo 'a > b' "c >> d"`, "a quoted > is text, not a redirect"},
		{"grep -n '>' notes.txt", "a quoted > is text, not a redirect"},
		{"   ", "blank"},
		{"ls -la >& /dev/null", ">&/dev/null is the older spelling of &>/dev/null (#4088 pass 1, F3)"},
		{"ls -la >&/dev/null", "same, no space"},
	}
	for _, tc := range harmless {
		if HasFileWriteRedirect(tc.cmd) {
			t.Errorf("HasFileWriteRedirect(%q) = true, want false (%s)", tc.cmd, tc.why)
		}
	}
}

// TestPrefixRuleMatchesWithholdsAllowFromRedirectWrites is the #4082
// regression at the PrefixRuleMatches level, which is the one implementation
// both the analyzer pipeline and the policy engine call. The restrictive-rule
// half is asserted too: a BLOCK/AUDIT prefix rule must keep firing on a
// redirecting command, or this fix would open a gap of its own.
func TestPrefixRuleMatchesWithholdsAllowFromRedirectWrites(t *testing.T) {
	prefixes := []string{"echo ", "printf ", "cat ", "grep ", "ls"}

	for _, cmd := range []string{
		"echo 'export PATH=$PATH:/opt/bin' >> ~/.zshenv",
		"printf 'x' > /etc/hosts",
		"cat site.conf > /etc/nginx/sites-enabled/site.conf",
		"grep -h '' notes.txt > copy.txt",
		"ls > listing.txt",
		"echo a && echo b > out.txt",
		"echo a; { echo b; } > out.txt",
	} {
		if PrefixRuleMatches(cmd, prefixes, true) {
			t.Errorf("ALLOW prefix rule fired on file-writing %q", cmd)
		}
		if !PrefixRuleMatches(cmd, prefixes, false) {
			t.Errorf("restrictive prefix rule stopped firing on %q: only the ALLOW path may narrow", cmd)
		}
	}

	for _, cmd := range []string{
		"echo hi",
		"echo x > /dev/null",
		`printf '%s\n' foo 2>&1`,
		"grep -rn foo . 2>/dev/null | ls",
		"cat README.md",
	} {
		if !PrefixRuleMatches(cmd, prefixes, true) {
			t.Errorf("ALLOW prefix rule stopped firing on read-only %q", cmd)
		}
	}
}
