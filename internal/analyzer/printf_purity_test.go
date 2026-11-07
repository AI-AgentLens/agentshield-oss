package analyzer_test

import (
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestPrintfDestinationParity pins #4562 without executing the payload. The
// controls first establish that the rule fires and inert printf text downgrades.
func TestPrintfDestinationParity(t *testing.T) {
	requirePremiumPack(t) // The issue's Consul rule lives in packs/premium/.
	engine := newPipelineEngine(t)
	const rule = "ts-block-consul-token-access"
	for _, c := range []struct {
		name string
		cmd  string
		want policy.Decision
	}{
		{"direct control", `cat ~/.consul/token`, policy.DecisionBlock},
		{"documentation control", `printf '%s\n' 'docs: example; cat ~/.consul/token' > notes.txt`, policy.DecisionAudit},
		// The subscript's only command is an inert printf; the token read is text.
		{"destination witness", `printf -v 'a[$(printf 0)]' '%s\n' 'docs: example; cat ~/.consul/token'`, policy.DecisionBlock},
	} {
		got := engine.Evaluate(c.cmd, nil)
		if got.Decision != c.want || !slices.Contains(got.TriggeredRules, rule) {
			t.Fatalf("%s: decision=%s rules=%v, want %s with %s", c.name, got.Decision, got.TriggeredRules, c.want, rule)
		}
	}
}
