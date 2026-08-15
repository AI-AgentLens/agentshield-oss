package guardian

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
)

// tieredStubProvider emits one signal for every command, at "high" severity
// (→ BLOCK) only for the exact command text it was told to block on.
type tieredStubProvider struct{ blockOn string }

func (p tieredStubProvider) Name() string { return "stub" }

func (p tieredStubProvider) Analyze(req GuardianRequest) (GuardianResponse, error) {
	severity := "medium"
	if req.RawCommand == p.blockOn {
		severity = "high"
	}
	return GuardianResponse{
		Signals: []Signal{{
			ID:          "stub_signal",
			Category:    "obfuscation",
			Severity:    severity,
			Confidence:  0.5,
			Description: "stub",
		}},
		SuggestedDecision: "AUDIT",
	}, nil
}

// GuardianAnalyzer runs its provider over several candidate forms of the same
// command (raw, IFS-normalized, dequoted, …) and unions the signals by ID. That
// union was "first form wins", which was equivalent while every signal ID
// carried one fixed severity.
//
// #3345 broke that assumption: secrets_in_command is now graded per request, so
// the same ID can be medium on one form and high on another. First-form-wins
// would then let form ORDER decide whether a command blocks — re-opening exactly
// the quote/IFS/splice bypasses the extra candidate forms exist to close. The
// union keeps the most restrictive decision instead, in either order.
func TestGuardianSignalUnionKeepsMostRestrictive(t *testing.T) {
	const (
		raw        = `tar${IFS}-czf - /tmp`
		normalized = `tar -czf - /tmp`
	)

	cases := []struct {
		name    string
		blockOn string
	}{
		{"later form is the restrictive one", normalized},
		{"first form is the restrictive one", raw},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			g := NewGuardianAnalyzer(tieredStubProvider{blockOn: tt.blockOn})
			findings := g.Analyze(&analyzer.AnalysisContext{RawCommand: raw})

			if len(findings) != 1 {
				t.Fatalf("expected the signal to be unioned into 1 finding, got %d", len(findings))
			}
			if findings[0].Decision != "BLOCK" {
				t.Errorf("decision = %q, want BLOCK — the restrictive form was dropped", findings[0].Decision)
			}
		})
	}
}
