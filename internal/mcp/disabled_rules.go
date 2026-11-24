package mcp

import (
	"slices"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// withoutDisabledRules returns the policy the matcher reads once the rules
// whose id disableRules lists are switched off (#5001, PolicyEvaluator.
// DisableRules): the shell policy's disable_rules, which until #5001 switched
// off shell rules only. Rule ids are unique across shell and tool-call rules
// (the duplicate-id gate), so the one list serves both kinds.
//
// Every id-bearing rule family is filtered: rules, structural_rules,
// semantic_rules, resource_rules and value_limits (mcpPackRuleCount's five).
// An id matches exactly as the shell engine matches it: through
// policy.Policy.IsRuleDisabled, so a prefix, another case or surrounding
// whitespace switches nothing off, here as there.
//
// It decides only which rules can match, so it knows nothing about how a rule
// is written: a sentinel (engine:) or a label rule (an empty match a Go check
// names) is filtered like any other, which changes nothing, since neither
// ever matches. What a Go check's record resolves comes from the declared
// policy, never from this one (DisableRules). Unexported for that reason: an
// evaluator built on a filtered policy would resolve receipts from it.
// blocked_tools and blocked_resources carry no rule id, and data_labels are
// not rules (the shell side does not filter them either).
//
// An empty list returns p itself. Otherwise p is left unchanged and a
// filtered copy is returned.
func withoutDisabledRules(p *MCPPolicy, disableRules []string) *MCPPolicy {
	if p == nil || len(disableRules) == 0 {
		return p
	}
	listed := &policy.Policy{DisableRules: disableRules}
	out := cloneMCPPolicy(p)
	out.Rules = slices.DeleteFunc(out.Rules, func(r MCPRule) bool { return listed.IsRuleDisabled(r.ID) })
	out.StructuralRules = slices.DeleteFunc(out.StructuralRules, func(r MCPStructuralRule) bool { return listed.IsRuleDisabled(r.ID) })
	out.SemanticRules = slices.DeleteFunc(out.SemanticRules, func(r MCPSemanticRule) bool { return listed.IsRuleDisabled(r.ID) })
	out.ResourceRules = slices.DeleteFunc(out.ResourceRules, func(r ResourceRule) bool { return listed.IsRuleDisabled(r.ID) })
	out.ValueLimits = slices.DeleteFunc(out.ValueLimits, func(r ValueLimitRule) bool { return listed.IsRuleDisabled(r.ID) })
	return out
}
