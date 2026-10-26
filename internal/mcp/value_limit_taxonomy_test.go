package mcp

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// ApplyValueLimits is the value_limits pass the proxies, shield-server and
// mcp-eval share. A value-limit verdict used to carry no taxonomy on any of
// them: ValueLimitFinding dropped ValueLimitRule.Taxonomy, so the receipt
// attested only through the rule-id fallback.

func taxonomyValueLimitEvaluator() *PolicyEvaluator {
	return NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{{
			ID:       "audit-payments-rule",
			Taxonomy: "node/rule",
			Match:    MCPMatch{ToolNameAny: []string{"pay"}},
			Decision: policy.DecisionAudit,
			Reason:   "payments are audited",
		}},
		ValueLimits: []ValueLimitRule{
			{ID: "cap-amount", Taxonomy: "node/cap", ToolPattern: "pay", Argument: "amount", Max: floatPtr(100), Decision: policy.DecisionBlock, Reason: "cap"},
			{ID: "audit-amount", Taxonomy: "node/audit", ToolPattern: "pay", Argument: "amount", Max: floatPtr(10), Decision: policy.DecisionAudit, Reason: "audit"},
			{ID: "cap-amount-same-node", Taxonomy: "node/cap", ToolPattern: "pay", Argument: "amount", Max: floatPtr(50), Decision: policy.DecisionBlock, Reason: "cap twice"},
			{ID: "no-node", ToolPattern: "tip", Argument: "amount", Max: floatPtr(10), Decision: policy.DecisionAudit, Reason: "no taxonomy"},
		},
	})
}

func TestCheckValueLimits_FindingCarriesRuleTaxonomy(t *testing.T) {
	vl := taxonomyValueLimitEvaluator().CheckValueLimits("pay", map[string]interface{}{"amount": 500.0})
	var got []string
	for _, f := range vl.Findings {
		got = append(got, f.RuleID+"="+f.Taxonomy)
	}
	want := []string{"cap-amount=node/cap", "audit-amount=node/audit", "cap-amount-same-node=node/cap"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings %v, want %v", got, want)
	}
}

func TestApplyValueLimits_Taxonomy(t *testing.T) {
	e := taxonomyValueLimitEvaluator()
	cases := []struct {
		name      string
		tool      string
		amount    float64
		wantDec   policy.Decision
		wantRules []string
		wantTax   []string
	}{
		{
			// The matcher's node first, then each finding's in finding order,
			// deduped: rule ids and taxonomy are read in the same order.
			name: "BLOCK over an AUDIT rule", tool: "pay", amount: 500, wantDec: policy.DecisionBlock,
			wantRules: []string{"audit-payments-rule", "value-limit", "cap-amount", "audit-amount", "cap-amount-same-node"},
			wantTax:   []string{"node/rule", "node/cap", "node/audit"},
		},
		{
			name: "AUDIT-level finding only", tool: "pay", amount: 20, wantDec: policy.DecisionAudit,
			wantRules: []string{"audit-payments-rule", "value-limit-audit", "audit-amount"},
			wantTax:   []string{"node/rule", "node/audit"},
		},
		{
			name: "control: finding with no taxonomy adds none", tool: "tip", amount: 20, wantDec: policy.DecisionAudit,
			wantRules: []string{"value-limit-audit", "no-node"},
			wantTax:   nil,
		},
		{
			name: "no-op control: under every limit", tool: "pay", amount: 5, wantDec: policy.DecisionAudit,
			wantRules: []string{"audit-payments-rule"},
			wantTax:   []string{"node/rule"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := map[string]interface{}{"amount": tc.amount}
			got, _ := e.ApplyValueLimits(e.EvaluateToolCall(tc.tool, args), tc.tool, args)
			if got.Decision != tc.wantDec || !reflect.DeepEqual(got.TriggeredRules, tc.wantRules) {
				t.Fatalf("decision %s rules %v, want %s %v", got.Decision, got.TriggeredRules, tc.wantDec, tc.wantRules)
			}
			if !(len(got.TaxonomyRefs) == 0 && len(tc.wantTax) == 0) && !reflect.DeepEqual(got.TaxonomyRefs, tc.wantTax) {
				t.Errorf("TaxonomyRefs %v, want %v", got.TaxonomyRefs, tc.wantTax)
			}
		})
	}
}

// An already-BLOCKed verdict skips the pass entirely, as every surface's
// `if result.Decision != BLOCK` gate did: nothing is added, not even taxonomy.
func TestApplyValueLimits_SkipsBlockedVerdict(t *testing.T) {
	e := taxonomyValueLimitEvaluator()
	in := MCPEvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"r"}, TaxonomyRefs: []string{"node/r"}}
	got, vl := e.ApplyValueLimits(in, "pay", map[string]interface{}{"amount": 500.0})
	if !reflect.DeepEqual(got, in) || len(vl.Findings) != 0 {
		t.Errorf("got %+v (findings %v), want the BLOCK verdict unchanged and no pass", got, vl.Findings)
	}
}
