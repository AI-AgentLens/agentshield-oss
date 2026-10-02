package analyzer

import "testing"

// TestGlobEvasion_SubstitutionBodyAttribution pins #3927: a command- or
// process-substitution body's own glob-obfuscated sensitive path must be
// visible to the SAME attribution check the top-level statement gets, so
// substitutionReachesExecutor correctly withdraws the doc-text/heredoc
// labels instead of leaving a real read downgraded to AUDIT.
//
// Before the fix, StatementMatchCandidates (which backs both
// statementMatcher's per-statement predicate and substitutionReachesExecutor's
// matchesStatement(body) check) never ran shellparse.DeglobSensitivePaths, so
// a glob-obfuscated body was invisible to attribution even though
// RegexAnalyzer's own wholeCommandForms pass already resolves the same glob
// for the initial match. `echo "$(cat ~/.?sh/id_ed25519)"` therefore matched
// (BLOCK-eligible) but stayed downgraded to AUDIT, because the attribution
// check tested only the raw, un-deglobbed body text and found no match
// inside it — so the is_doc_text label was never withdrawn.
func TestGlobEvasion_SubstitutionBodyAttribution(t *testing.T) {
	rule := RegexRule{
		ID:              "test-block-ssh-private-glob-3927",
		Decision:        "BLOCK",
		Regex:           `\.ssh/id_[a-z0-9]+`,
		IntentDowngrade: []string{LabelIsDocText, LabelInHeredoc},
	}

	cases := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "unobfuscated cmdsubst body (positive control, #3814)",
			command: `echo "$(cat ~/.ssh/id_ed25519)"`,
			want:    "BLOCK",
		},
		{
			name:    "glob-obfuscated cmdsubst body",
			command: `echo "$(cat ~/.?sh/id_ed25519)"`,
			want:    "BLOCK",
		},
		{
			name:    "glob-obfuscated backtick body",
			command: "echo \"`cat ~/.?sh/id_ed25519`\"",
			want:    "BLOCK",
		},
		{
			name:    "glob-obfuscated body inside the commit-idiom doc-text carrier",
			command: `git commit -m "$(cat ~/.?sh/id_ed25519)"`,
			want:    "BLOCK",
		},
		{
			name:    "doc text mentioning the glob-shaped path outside any substitution stays downgraded",
			command: `echo "note: rotate ~/.ssh/id_ed25519 ($(date))"`,
			want:    "AUDIT",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := runRegexAnalyzer(rule, tt.command)
			if f == nil {
				t.Fatalf("rule did not fire on %q — the decision assertion would be vacuous", tt.command)
			}
			if f.Decision != tt.want {
				t.Errorf("RegexAnalyzer.Analyze(%q) decision = %s, want %s\n  reason: %s", tt.command, f.Decision, tt.want, f.Reason)
			}
		})
	}
}
