package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestUnicodeScanDoesNotShortCircuitEvaluation is the regression test for
// #4007: EvaluateWithParsedCwd used to `return finish(result)` immediately
// after the built-in Unicode smuggling scan found ANY threat — including a
// bare AUDIT-severity homoglyph — which skipped the protected-path check and
// RunAll/fallback entirely. One non-ASCII letter anywhere in the command
// silently downgraded every BLOCK to AUDIT and replaced the real rule
// attribution with only the homoglyph finding.
//
// Fixed shape: the Unicode finding is folded into the final decision
// most-restrictive-wins, the same rule the combiner applies to every other
// analyzer, so it can only ADD an AUDIT/BLOCK finding, never suppress a
// stricter one found downstream.
func TestUnicodeScanDoesNotShortCircuitEvaluation(t *testing.T) {
	base := DefaultPolicy()
	merged, _, err := LoadEmbeddedShellPacks(base)
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks failed: %v", err)
	}
	engine, err := NewEngineWithAnalyzers(merged, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers failed: %v", err)
	}

	eval := func(command string) EvalResult {
		normalized := normalize.NormalizeCommand(command, "")
		return engine.EvaluateWithParsed(command, normalized.Paths, normalized.Parsed)
	}

	tests := []struct {
		name         string
		command      string
		wantDecision Decision
		wantRule     string // must appear in TriggeredRules
	}{
		{
			name:         "control: ufw disable alone blocks",
			command:      "ufw disable",
			wantDecision: DecisionBlock,
			wantRule:     "ts-block-ufw-disable",
		},
		{
			// #4007's exact reproduction: a Cyrillic 'а' (U+0430) anywhere in
			// the line used to downgrade this to AUDIT with only the
			// homoglyph rule named. The real attack (ufw disable) must still
			// win — its severity (BLOCK) is strictly higher than the bare
			// homoglyph's (AUDIT).
			name:         "homoglyph elsewhere in the line cannot downgrade a real BLOCK",
			command:      "ufw disable; echo cаfа",
			wantDecision: DecisionBlock,
			wantRule:     "ts-block-ufw-disable",
		},
		{
			name:         "control: protected ssh key path alone blocks",
			command:      "cat ~/.ssh/id_rsa",
			wantDecision: DecisionBlock,
			wantRule:     "protected-path",
		},
		{
			name:         "homoglyph in a trailing comment cannot downgrade a protected-path BLOCK",
			command:      "cat ~/.ssh/id_rsa # cаfа",
			wantDecision: DecisionBlock,
			wantRule:     "protected-path",
		},
		{
			// Positive control for the merge itself: with nothing else
			// firing, a lone homoglyph must still be attested at its own
			// (AUDIT) severity — the fix must not silently drop the finding
			// when there is no stricter decision to fold it into.
			name:         "lone homoglyph with nothing else firing still attests at AUDIT",
			command:      "echo cаfа",
			wantDecision: DecisionAudit,
			wantRule:     "unicode-homoglyph-cyrillic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eval(tt.command)
			if result.Decision != tt.wantDecision {
				t.Errorf("command %q: decision = %s, want %s (rules=%v, reasons=%v)",
					tt.command, result.Decision, tt.wantDecision, result.TriggeredRules, result.Reasons)
			}
			found := false
			for _, r := range result.TriggeredRules {
				if r == tt.wantRule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("command %q: expected rule %q in TriggeredRules, got %v", tt.command, tt.wantRule, result.TriggeredRules)
			}
		})
	}
}
