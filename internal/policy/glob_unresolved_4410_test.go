package policy

import "testing"

// TestGlobWordDecisions_4410 pins Gary's 2026-10-19 decision on #4410 at the
// engine, through the shipped packs:
//
//  1. a glob that pins ONE protected name BLOCKs, by alias of the literal;
//  2. a glob that also matches ordinary names is recorded (AUDIT), never
//     blocked;
//  3. ts-allow-readonly never ALLOWs a word that still holds an unresolved
//     glob, so such a command is always at least AUDIT.
//
// Every BLOCK row's literal twin is asserted first: an alias is only an alias
// when the spelling it stands for BLOCKs.
func TestGlobWordDecisions_4410(t *testing.T) {
	engine := newAllPacksEngine(t)

	blocked := []struct{ glob, literal string }{
		{"cat /etc/shado?", "cat /etc/shadow"},
		{"cat /etc/shad*", "cat /etc/shadow"},
		{"cat /etc/shad[o]w", "cat /etc/shadow"},
		{"cat ~/.netr?", "cat ~/.netrc"},
		{"cat ~/Passwords.kd?x", "cat ~/Passwords.kdbx"},
		{"cat ~/Passwords.kdb*", "cat ~/Passwords.kdbx"},
		{"cat ~/Passwords.kd[b]x", "cat ~/Passwords.kdbx"},
	}
	for _, c := range blocked {
		if got := evalNormalized(engine, c.literal).Decision; got != DecisionBlock {
			t.Fatalf("control %q = %s, want BLOCK", c.literal, got)
		}
		if got := evalNormalized(engine, c.glob).Decision; got != DecisionBlock {
			t.Errorf("%q = %s, want BLOCK (alias of %q)", c.glob, got, c.literal)
		}
	}

	// Broad globs and ordinary globs: recorded, never BLOCK, never ALLOW.
	recorded := []string{
		"cat /etc/s*",
		"cat ~/.n*",
		"du -sh ~/.*",
		"ls /etc/s*",
		"cat /etc/shado?x",
		"ls *.go",
		"grep -rn TODO src/*.go",
		"find . -name *.go",
	}
	for _, cmd := range recorded {
		got := evalNormalized(engine, cmd).Decision
		if got != DecisionAudit {
			t.Errorf("%q = %s, want AUDIT (unresolved glob: recorded, not blocked, not vouched)", cmd, got)
		}
	}

	// Words the shell does not glob keep their ALLOW.
	allowed := []string{
		"ls -la",
		`echo "a ? b"`,
		`echo 'x * y'`,
		"echo hi > /dev/null",
		"cat <<'EOF'\n* bullet\nEOF",
		"grep -rn 'TODO*' .",
	}
	for _, cmd := range allowed {
		if got := evalNormalized(engine, cmd).Decision; got != DecisionAllow {
			t.Errorf("%q = %s, want ALLOW (no unquoted glob word)", cmd, got)
		}
	}
}
