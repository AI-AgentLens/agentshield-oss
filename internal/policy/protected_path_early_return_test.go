package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// TestProtectedPathEarlyReturnCannotSilenceDownstreamBlock pins the invariant
// #4011 asks for. EvaluateWithParsedCwd has (at least) two pre-checks that
// can `return finish(result)` before the registry/fallback pipeline runs:
// the Unicode smuggling scan (guarded by TestUnicodeScanDoesNotShortCircuitEvaluation,
// #4010) and the protected-path check, guarded here. The protected-path check
// is safe today ONLY because it always decides at DecisionBlock — the ceiling
// of decisionSeverity — so nothing downstream can ever be stricter and an
// early return loses nothing.
//
// That safety property is not enforced by the type system: if a future edit
// (or a new pre-check added the same way) ever returned early at a decision
// below BLOCK, RunAll/fallback would never run and a real downstream BLOCK —
// like the `ufw disable` rule below — would be silently dropped to that lower
// severity. This is the #4007 shape one level up.
//
// This test is a no-op today: checkProtectedPaths can only ever return BLOCK,
// so the combined-command case below cannot fail against the current code.
// Its purpose is to fail the moment someone changes that — a mutation-catching
// pin, not a live bug fix.
func TestProtectedPathEarlyReturnCannotSilenceDownstreamBlock(t *testing.T) {
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
			name:         "control: protected ssh key path alone blocks",
			command:      "cat ~/.ssh/id_rsa",
			wantDecision: DecisionBlock,
			wantRule:     "protected-path",
		},
		{
			name:         "control: an unrelated real rule alone blocks",
			command:      "ufw disable",
			wantDecision: DecisionBlock,
			wantRule:     "ts-block-ufw-disable",
		},
		{
			// The invariant: combining the protected-path trip with an
			// unrelated real BLOCK-rule trip must still decide BLOCK. If the
			// protected-path check ever returned early at a decision below
			// BLOCK, this combined command would decide at that lower
			// severity instead — `ufw disable` never reaches RunAll/fallback
			// because the early return skips them entirely.
			name:         "protected-path trip combined with an unrelated BLOCK still decides BLOCK",
			command:      "cat ~/.ssh/id_rsa; ufw disable",
			wantDecision: DecisionBlock,
			wantRule:     "protected-path",
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
