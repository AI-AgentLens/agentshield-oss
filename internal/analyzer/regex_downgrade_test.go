package analyzer

import "testing"

// runRegexAnalyzer runs the real pipeline path for a single regex rule: the
// intent classifier populates ctx.CommandFacts + ctx.RawStatements, then the
// regex analyzer applies the rule (including the #2843 downgrade logic).
// Returns the finding for the rule, or nil if none fired.
func runRegexAnalyzer(rule RegexRule, command string) *Finding {
	ctx := &AnalysisContext{RawCommand: command}
	NewIntentClassifier().Analyze(ctx) // sets CommandFacts + RawStatements
	for _, f := range NewRegexAnalyzer([]RegexRule{rule}).Analyze(ctx) {
		if f.RuleID == rule.ID {
			ff := f
			return &ff
		}
	}
	return nil
}

// TestRegexIntentDowngrade covers the #2843 context-aware downgrade: a BLOCK
// match that sits only inside a doc-text (gh/git --body/--message) statement is
// downgraded to AUDIT — kept logged, not suppressed and not interrupting — while
// a real access, including one chained after a doc-text statement, keeps BLOCK.
func TestRegexIntentDowngrade(t *testing.T) {
	// A credential-path rule shaped like sec-block-ssh-private.
	rule := RegexRule{
		ID:              "test-block-ssh-private",
		Decision:        "BLOCK",
		Regex:           `\.ssh/id_[a-z0-9]+`,
		IntentDowngrade: []string{LabelIsDocText},
	}

	cases := []struct {
		name    string
		command string
		want    string // "" = no finding; else expected Decision
	}{
		// The 3 recurrence shapes → AUDIT (was a BLOCK FP), still logged.
		{"gh pr body", `gh pr create --body "rule fires on .ssh/id_rsa in docs"`, "AUDIT"},
		{"gh issue body", `gh issue create --title x --body "see .ssh/id_ed25519 note"`, "AUDIT"},
		{"git commit msg", `git commit -m "moved from .ssh/id_rsa path"`, "AUDIT"},
		// Real executed accesses → still BLOCK.
		{"cat key", "cat ~/.ssh/id_rsa", "BLOCK"},
		{"scp key", "scp ~/.ssh/id_ed25519 host:", "BLOCK"},
		// Compound: a real access chained AFTER a doc-text statement must stay
		// BLOCK — per-statement scoping, the cat statement is not doc-text.
		{"compound real access", `gh pr create --body "notes" && cat ~/.ssh/id_rsa`, "BLOCK"},
		// Compound: real access BEFORE the doc-text statement — also BLOCK.
		{"compound real access first", `cat ~/.ssh/id_rsa ; git commit -m "x .ssh/id_rsa"`, "BLOCK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := runRegexAnalyzer(rule, tc.command)
			if tc.want == "" {
				if f != nil {
					t.Fatalf("expected no finding, got %+v", f)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected a %s finding, got none", tc.want)
			}
			if f.Decision != tc.want {
				t.Errorf("decision = %q, want %q (command: %s)", f.Decision, tc.want, tc.command)
			}
		})
	}
}

// TestRegexIntentDowngradeOnlyBlockLevel confirms the downgrade never touches
// a rule that is already AUDIT/ALLOW (nothing to downgrade) and never fires
// where the pattern doesn't match.
func TestRegexIntentDowngradeOnlyBlockLevel(t *testing.T) {
	auditRule := RegexRule{
		ID:              "test-audit-rule",
		Decision:        "AUDIT",
		Regex:           `\.ssh/id_[a-z0-9]+`,
		IntentDowngrade: []string{LabelIsDocText},
	}
	// A doc-text match on an AUDIT rule stays AUDIT (no double-processing/crash).
	if f := runRegexAnalyzer(auditRule, `git commit -m "note .ssh/id_rsa"`); f == nil || f.Decision != "AUDIT" {
		t.Fatalf("AUDIT rule must stay AUDIT, got %+v", f)
	}
	// No match → no finding.
	if f := runRegexAnalyzer(auditRule, "ls -la"); f != nil {
		t.Fatalf("expected no finding on non-matching command, got %+v", f)
	}
}
