package analyzer_test

import (
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestGitEditorMessageParity pins #4554 without executing the payload. The
// controls first establish that the rule fires and inert commit text downgrades.
func TestGitEditorMessageParity(t *testing.T) {
	requirePremiumPack(t) // The issue's Consul rule lives in packs/premium/.
	engine := newPipelineEngine(t)
	const rule = "ts-block-consul-token-access"
	for _, c := range []struct {
		name string
		cmd  string
		want policy.Decision
	}{
		{"direct control", `cat ~/.consul/token`, policy.DecisionBlock},
		{"documentation control", `git commit --allow-empty -m 'docs: rotate; cat ~/.consul/token shows the old token'`, policy.DecisionAudit},
		{"editor witness", `export GIT_EDITOR=sh; git commit --allow-empty --edit -m ':; cat ~/.consul/token; exit 1'`, policy.DecisionBlock},
	} {
		got := engine.Evaluate(c.cmd, nil)
		if got.Decision != c.want || !slices.Contains(got.TriggeredRules, rule) {
			t.Fatalf("%s: decision=%s rules=%v, want %s with %s", c.name, got.Decision, got.TriggeredRules, c.want, rule)
		}
	}
}
