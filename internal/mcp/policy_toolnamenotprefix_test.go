package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// toolNameNotPrefixRule mirrors the shape comply's declared-baseline pack
// generator (AI_risk_compliance#3029/#3030) emits: scope to the MCP
// namespace with tool_name_regex, then carve out the declared servers with
// tool_name_not_prefix_any so the rule fires only on tool calls whose server
// is NOT in the declared set. Issue #2816.
func toolNameNotPrefixRule() MCPRule {
	return MCPRule{
		ID: "test-undeclared-mcp-server",
		Match: MCPMatch{
			ToolNameRegex: "^mcp__",
			ToolNameNotPrefixAny: []string{
				"mcp__github__",
				"mcp__sentry__",
			},
		},
		Decision: policy.DecisionAudit,
		Reason:   "test",
	}
}

func TestToolNameNotPrefixAny_Predicate(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := toolNameNotPrefixRule()

	cases := []struct {
		name string
		tool string
		fire bool
	}{
		{"declared server (github) does not fire", "mcp__github__create_issue", false},
		{"declared server (sentry) does not fire", "mcp__sentry__list_issues", false},
		{"undeclared server fires", "mcp__paste-anything__fetch", true},
		{"another undeclared server fires", "mcp__evil-corp__exfiltrate", true},
		{"prefix must match the whole segment, not a substring mid-name", "mcp__github-clone__list", true},
		{"outside the scoped namespace never fires", "read_file", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.matchRule(tc.tool, map[string]interface{}{}, rule)
			if got != tc.fire {
				t.Errorf("matchRule(%q) = %v, want %v", tc.tool, got, tc.fire)
			}
		})
	}
}

// TestToolNameNotPrefixAny_ComposesWithArgumentPredicates confirms the
// negative tool-name predicate is an independent AND constraint alongside
// existing argument-level predicates, not folded into the positive
// tool-name OR-group.
func TestToolNameNotPrefixAny_ComposesWithArgumentPredicates(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID: "test-undeclared-write",
		Match: MCPMatch{
			ToolNameRegex:        "^mcp__",
			ToolNameNotPrefixAny: []string{"mcp__github__"},
			ArgumentPatterns:     map[string]string{"path": "**/*.env"},
		},
		Decision: policy.DecisionAudit,
	}

	if e.matchRule("mcp__github__write_file", map[string]interface{}{"path": "/repo/.env"}, rule) {
		t.Error("declared server must not fire even when the argument pattern matches")
	}
	if !e.matchRule("mcp__unknown__write_file", map[string]interface{}{"path": "/repo/.env"}, rule) {
		t.Error("undeclared server with matching argument pattern should fire")
	}
	if e.matchRule("mcp__unknown__write_file", map[string]interface{}{"path": "/repo/README.md"}, rule) {
		t.Error("undeclared server with non-matching argument pattern should not fire")
	}
}

// TestToolNameNotPrefixAny_OnlyPredicateStillCountsAsSpecified confirms a
// rule using ONLY tool_name_not_prefix_any (no positive tool-name matcher)
// still evaluates — exercising the final nameSpecified OR-list fallback,
// same as the existing ArgumentNotContains-only case.
func TestToolNameNotPrefixAny_OnlyPredicateStillCountsAsSpecified(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID:       "test-bare-not-prefix",
		Match:    MCPMatch{ToolNameNotPrefixAny: []string{"mcp__github__"}},
		Decision: policy.DecisionAudit,
	}

	if !e.matchRule("mcp__unknown__anything", map[string]interface{}{}, rule) {
		t.Error("expected fire when tool name lacks the excluded prefix")
	}
	if e.matchRule("mcp__github__anything", map[string]interface{}{}, rule) {
		t.Error("expected suppression when tool name has the excluded prefix")
	}
}

// TestUndeclaredMCPServerDrift_InSitu simulates the full declared-baseline
// pack comply generates for a repo: an AUDIT rule scoped to the MCP
// namespace that fires only on servers outside the declared set, tagged
// with the undeclared-mcp-server taxonomy (issue #2816, capability-drift
// half of the declared-vs-observed fusion chain). This exercises the
// PolicyEvaluator end-to-end (not just matchRule) the way a real deployed
// pack would be evaluated.
func TestUndeclaredMCPServerDrift_InSitu(t *testing.T) {
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID:       "declared-baseline-drift-example-repo",
				Taxonomy: "unauthorized-execution/agent-capability/undeclared-mcp-server",
				Match: MCPMatch{
					ToolNameRegex: "^mcp__",
					ToolNameNotPrefixAny: []string{
						"mcp__github__",
						"mcp__sentry__",
					},
				},
				Decision: policy.DecisionAudit,
				Reason:   "MCP tool call to a server not present in .mcp.json's declared baseline (github, sentry) — capability drift.",
			},
		},
	}
	evaluator := NewPolicyEvaluator(p)

	declared := evaluator.EvaluateToolCall("mcp__github__create_issue", map[string]interface{}{"title": "bug"})
	if containsRule(declared.TriggeredRules, "declared-baseline-drift-example-repo") {
		t.Errorf("declared server must not trigger the drift rule; got rules=%v", declared.TriggeredRules)
	}

	undeclared := evaluator.EvaluateToolCall("mcp__paste-anything__fetch", map[string]interface{}{"url": "https://evil.example/x"})
	if !containsRule(undeclared.TriggeredRules, "declared-baseline-drift-example-repo") {
		t.Errorf("undeclared server must trigger the drift rule; got rules=%v", undeclared.TriggeredRules)
	}
	if undeclared.Decision != policy.DecisionAudit {
		t.Errorf("undeclared server call should AUDIT; got %s", undeclared.Decision)
	}
	if undeclared.TaxonomyRef != "" {
		// MCPEvalResult.TaxonomyRef is reserved for Go-implemented intercepts;
		// YAML-rule taxonomy lives on the rule itself, not the aggregate result.
		t.Errorf("expected empty aggregate TaxonomyRef for YAML-policy-evaluated results, got %q", undeclared.TaxonomyRef)
	}

	nonMCP := evaluator.EvaluateToolCall("read_file", map[string]interface{}{"path": "/tmp/x"})
	if containsRule(nonMCP.TriggeredRules, "declared-baseline-drift-example-repo") {
		t.Errorf("non-MCP-namespaced tool must not trigger the drift rule; got rules=%v", nonMCP.TriggeredRules)
	}
}
