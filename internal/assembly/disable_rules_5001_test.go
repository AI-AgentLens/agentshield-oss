package assembly

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
	"gopkg.in/yaml.v3"
)

// #5001: MCPEvaluator is the one place the shell policy's disable_rules reach
// a tool-call surface. One BLOCK rule of each id-bearing family, each reached
// by its own invented call.
const allFamilies5001 = `defaults:
  decision: AUDIT
rules:
  - id: a5001-rule
    match:
      tool_name: a5001_rule
    decision: BLOCK
    reason: rule
structural_rules:
  - id: a5001-struct
    match:
      tool_name_any: ["a5001_struct"]
      args_match:
        path:
          pattern_any: ["^/a5001/"]
    decision: BLOCK
    reason: structural
semantic_rules:
  - id: a5001-sem
    match:
      intent_any: ["code-execute"]
      confidence_min: 0.7
    decision: BLOCK
    reason: semantic
resource_rules:
  - id: a5001-resource
    match:
      scheme: a5001
    decision: BLOCK
    reason: resource
value_limits:
  - id: a5001-cap
    tool_pattern: a5001_meter
    argument: units
    max: 10
    decision: BLOCK
    reason: cap
`

func families5001(t *testing.T) *mcp.MCPPolicy {
	t.Helper()
	var p mcp.MCPPolicy
	if err := yaml.Unmarshal([]byte(allFamilies5001), &p); err != nil {
		t.Fatal(err)
	}
	return &p
}

// verdicts5001 is every family's verdict on its own call, as the surfaces
// combine them: the rule matcher, then value_limits (ApplyValueLimits), and
// the resources/read path.
func verdicts5001(ev *mcp.PolicyEvaluator) map[string]mcp.MCPEvalResult {
	call := func(tool string, args map[string]interface{}) mcp.MCPEvalResult {
		r := ev.EvaluateToolCall(tool, args)
		r, _ = ev.ApplyValueLimits(r, tool, args)
		return r
	}
	return map[string]mcp.MCPEvalResult{
		"a5001-rule":     call("a5001_rule", nil),
		"a5001-struct":   call("a5001_struct", map[string]interface{}{"path": "/a5001/x"}),
		"a5001-sem":      call("run_code", map[string]interface{}{"code": "print(1)"}),
		"a5001-cap":      call("a5001_meter", map[string]interface{}{"units": 50}),
		"a5001-resource": ev.EvaluateResourceRead("a5001://x"),
	}
}

func TestMCPEvaluator_DisableRulesReachEveryFamily5001(t *testing.T) {
	base := verdicts5001(MCPEvaluator(families5001(t), policy.ToolCallInputs{}, ""))
	for id, r := range base {
		if r.Decision != policy.DecisionBlock || !containsRule(r.TriggeredRules, id) {
			t.Fatalf("setup: %s's call decided %s %v; want BLOCK by %s", id, r.Decision, r.TriggeredRules, id)
		}
	}
	for listed := range base {
		t.Run(listed, func(t *testing.T) {
			got := verdicts5001(MCPEvaluator(families5001(t), policy.ToolCallInputs{DisableRules: []string{listed}}, ""))
			for id, r := range got {
				if id == listed {
					if r.Decision == policy.DecisionBlock || containsRule(r.TriggeredRules, id) {
						t.Errorf("%s listed: its call decided %s %v; want it switched off", id, r.Decision, r.TriggeredRules)
					}
					continue
				}
				if !reflect.DeepEqual(r, base[id]) {
					t.Errorf("%s listed: unlisted %s changed:\n  got  %+v\n  want %+v", listed, id, r, base[id])
				}
			}
		})
	}
}

// A listed BLOCK rule leaves the call to what the evaluator decides without
// it: the same verdict, field for field, as a policy that never had it.
func TestMCPEvaluator_ListedIsDeleted5001(t *testing.T) {
	for _, listed := range []string{"a5001-rule", "a5001-struct", "a5001-sem", "a5001-cap", "a5001-resource"} {
		var p mcp.MCPPolicy
		if err := yaml.Unmarshal([]byte(allFamilies5001), &p); err != nil {
			t.Fatal(err)
		}
		// The oracle is built by hand, without the filter.
		p.Rules = dropRule(p.Rules, func(r mcp.MCPRule) bool { return r.ID == listed })
		p.StructuralRules = dropRule(p.StructuralRules, func(r mcp.MCPStructuralRule) bool { return r.ID == listed })
		p.SemanticRules = dropRule(p.SemanticRules, func(r mcp.MCPSemanticRule) bool { return r.ID == listed })
		p.ResourceRules = dropRule(p.ResourceRules, func(r mcp.ResourceRule) bool { return r.ID == listed })
		p.ValueLimits = dropRule(p.ValueLimits, func(r mcp.ValueLimitRule) bool { return r.ID == listed })
		want := verdicts5001(MCPEvaluator(&p, policy.ToolCallInputs{}, ""))
		got := verdicts5001(MCPEvaluator(families5001(t), policy.ToolCallInputs{DisableRules: []string{listed}}, ""))
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s listed:\n  got  %+v\n  want %+v", listed, got, want)
		}
	}
}

// Audit-only mode and the customer's protected paths are applied as before
// when a list is also given; protected-path, a Go check, is not a rule the
// list reaches (the shell engine never lets it reach its twin either).
func TestMCPEvaluator_DisableRulesLeaveModeAndProtectedPaths5001(t *testing.T) {
	testhome.Set(t, t.TempDir())
	in := policy.ToolCallInputs{ProtectedPaths: []string{"/etc/acme/secrets/**"}, DisableRules: []string{"a5001-sem", policy.ProtectedPathRuleID}}
	ev := MCPEvaluator(families5001(t), in, "audit-only")
	if r := ev.EvaluateToolCall("a5001_rule", nil); r.Decision != policy.DecisionAudit || r.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only: %s (original %q); want AUDIT (original BLOCK)", r.Decision, r.OriginalDecision)
	}
	enf := MCPEvaluator(families5001(t), in, "")
	if r := enf.EvaluateToolCall("Read", map[string]interface{}{"file_path": "/etc/acme/" + "secrets/db.env"}); r.Decision != policy.DecisionBlock || !containsRule(r.TriggeredRules, policy.ProtectedPathRuleID) {
		t.Errorf("customer protected path with %s listed: %s %v; want BLOCK by it", policy.ProtectedPathRuleID, r.Decision, r.TriggeredRules)
	}
}

// With nothing listed, MCPEvaluator decides exactly as it did before #5001
// (mcp.NewPolicyEvaluator on the same policy), and an id no rule has changes
// nothing either.
func TestMCPEvaluator_EmptyOrUnknownListChangesNothing5001(t *testing.T) {
	main := mcp.NewPolicyEvaluator(families5001(t))
	want := verdicts5001(main)
	for _, list := range [][]string{nil, {}, {"a5001-no-such-rule", "A5001-RULE", "a5001-rule ", "a5001", ""}} {
		if got := verdicts5001(MCPEvaluator(families5001(t), policy.ToolCallInputs{DisableRules: list}, "")); !reflect.DeepEqual(got, want) {
			t.Errorf("list %q:\n  got  %+v\n  want %+v", list, got, want)
		}
	}
}

func containsRule(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}

func dropRule[T any](in []T, drop func(T) bool) []T {
	var out []T
	for _, x := range in {
		if !drop(x) {
			out = append(out, x)
		}
	}
	return out
}
