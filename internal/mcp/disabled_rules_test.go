package mcp

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #5001: PolicyEvaluator.DisableRules (through withoutDisabledRules) is how
// the shell policy's disable_rules reach tool-call rules
// (assembly.MCPEvaluator calls it).

func onePerFamily5001() *MCPPolicy {
	ten := 10.0
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{ID: "f-rule", Match: MCPMatch{ToolName: "f_rule"}, Decision: policy.DecisionBlock},
			{ID: "f-rule-2", Match: MCPMatch{ToolName: "f_rule"}, Decision: policy.DecisionAudit},
			{ID: "f-sentinel", Engine: "mcp-filesystem-scheme-hijack", Decision: policy.DecisionBlock},
		},
		StructuralRules: []MCPStructuralRule{{ID: "f-struct", Decision: policy.DecisionBlock}},
		SemanticRules:   []MCPSemanticRule{{ID: "f-sem", Decision: policy.DecisionBlock}},
		ResourceRules:   []ResourceRule{{ID: "f-resource", Decision: policy.DecisionBlock}},
		ValueLimits:     []ValueLimitRule{{ID: "f-cap", Argument: "n", Max: &ten, Decision: policy.DecisionBlock}},
		BlockedTools:    []string{"f_blocked"},
		DataLabels:      []policy.DataLabel{{ID: "f-label"}},
	}
}

// ids5001 lists every rule id in p, by family.
func ids5001(p *MCPPolicy) map[string][]string {
	out := map[string][]string{}
	for _, r := range p.Rules {
		out["rules"] = append(out["rules"], r.ID)
	}
	for _, r := range p.StructuralRules {
		out["structural"] = append(out["structural"], r.ID)
	}
	for _, r := range p.SemanticRules {
		out["semantic"] = append(out["semantic"], r.ID)
	}
	for _, r := range p.ResourceRules {
		out["resource"] = append(out["resource"], r.ID)
	}
	for _, r := range p.ValueLimits {
		out["value_limits"] = append(out["value_limits"], r.ID)
	}
	return out
}

func TestWithoutDisabledRules_EachFamilyExactIdOnly5001(t *testing.T) {
	for _, c := range []struct {
		listed []string
		want   map[string][]string
	}{
		{[]string{"f-rule"}, map[string][]string{"rules": {"f-rule-2", "f-sentinel"}, "structural": {"f-struct"}, "semantic": {"f-sem"}, "resource": {"f-resource"}, "value_limits": {"f-cap"}}},
		{[]string{"f-struct", "f-sem"}, map[string][]string{"rules": {"f-rule", "f-rule-2", "f-sentinel"}, "resource": {"f-resource"}, "value_limits": {"f-cap"}}},
		{[]string{"f-resource", "f-cap"}, map[string][]string{"rules": {"f-rule", "f-rule-2", "f-sentinel"}, "structural": {"f-struct"}, "semantic": {"f-sem"}}},
		// The matching policy is filtered by id alone, however a rule is
		// written: a sentinel never matches, so leaving it out changes no
		// match, and its receipt comes from the declared policy (below).
		{[]string{"f-sentinel"}, map[string][]string{"rules": {"f-rule", "f-rule-2"}, "structural": {"f-struct"}, "semantic": {"f-sem"}, "resource": {"f-resource"}, "value_limits": {"f-cap"}}},
		// Lookalikes: a prefix, a longer id, case, whitespace, empty, a glob.
		{[]string{"f-rul", "f-rule-", "F-RULE", "f-rule ", " f-rule", "f-rule\n", "", "f-*", "*", "f_rule", "blocked-tool:f_blocked", "f-label"}, ids5001(onePerFamily5001())},
	} {
		in := onePerFamily5001()
		got := withoutDisabledRules(in, c.listed)
		if g := ids5001(got); !reflect.DeepEqual(g, c.want) {
			t.Errorf("listed %q: ids %v, want %v", c.listed, g, c.want)
		}
		// What is not a rule is untouched, and the input is never modified.
		if !reflect.DeepEqual(got.BlockedTools, in.BlockedTools) || !reflect.DeepEqual(got.DataLabels, in.DataLabels) || got.Defaults != in.Defaults {
			t.Errorf("listed %q: non-rule fields changed", c.listed)
		}
		if !reflect.DeepEqual(in, onePerFamily5001()) {
			t.Errorf("listed %q: the input policy was modified", c.listed)
		}
	}
}

// With nothing listed the policy value itself comes back, and DisableRules
// leaves the evaluator exactly as NewPolicyEvaluator built it.
func TestWithoutDisabledRules_EmptyListIsIdentity5001(t *testing.T) {
	p := onePerFamily5001()
	for _, list := range [][]string{nil, {}} {
		if got := withoutDisabledRules(p, list); got != p {
			t.Errorf("list %v: returned a different policy", list)
		}
		ev := NewPolicyEvaluator(p)
		ev.DisableRules(list)
		if ev.policy != p || ev.declared != nil {
			t.Errorf("list %v: DisableRules changed the evaluator", list)
		}
	}
	if withoutDisabledRules(nil, []string{"x"}) != nil {
		t.Error("nil policy: want nil back")
	}
}

// DisableRules filters what the matcher reads and nothing else: the sentinel
// index, the rule-taxonomy index and the self-protection set keep the policy
// as loaded, and a later list replaces an earlier one.
func TestDisableRules_ReceiptIndexesKeepTheDeclaredPolicy5001(t *testing.T) {
	p := onePerFamily5001()
	p.Rules[0].Taxonomy, p.Rules[2].Taxonomy = "f/rule", "f/sentinel"
	p.ResourceRules[0].Taxonomy = "f/resource"
	base := NewPolicyEvaluator(p) // nothing listed; DisableRules below never writes p
	ev := NewPolicyEvaluator(p)
	all := []string{"f-rule", "f-rule-2", "f-sentinel", "f-struct", "f-sem", "f-resource", "f-cap"}
	ev.DisableRules(all)
	if n := len(ev.policy.Rules) + len(ev.policy.StructuralRules) + len(ev.policy.SemanticRules) + len(ev.policy.ResourceRules) + len(ev.policy.ValueLimits); n != 0 {
		t.Fatalf("every id listed: %d rules left to match", n)
	}
	if got, want := ev.RuleTaxonomyRefs(all), base.RuleTaxonomyRefs(all); !reflect.DeepEqual(got, want) || len(want) != 3 {
		t.Errorf("RuleTaxonomyRefs %v, unlisted %v", got, want)
	}
	if s := ev.LookupSentinel("mcp-filesystem-scheme-hijack"); s == nil || s.ID != "f-sentinel" {
		t.Errorf("LookupSentinel = %+v, want the declared sentinel", s)
	}
	for _, id := range all {
		if ev.IsSelfProtectionRule(id) != base.IsSelfProtectionRule(id) {
			t.Errorf("IsSelfProtectionRule(%s) changed", id)
		}
	}
	ev.DisableRules([]string{"f-cap"})
	if g := ids5001(ev.policy); len(g["rules"]) != 3 || len(g["value_limits"]) != 0 {
		t.Errorf("a second list: matching ids %v, want every rule but f-cap", g)
	}

	// A self-protection rule a Go check could label a BLOCK with: listed, it
	// still counts for the audit-only keep, as unlisted.
	guard := &MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{{ID: "f-block-agentshield-guard", Match: MCPMatch{ToolName: "f_guard"}, Decision: policy.DecisionBlock}}}
	gev := NewPolicyEvaluator(guard)
	gev.DisableRules([]string{"f-block-agentshield-guard"})
	if !gev.IsSelfProtectionRule("f-block-agentshield-guard") || !gev.KeepsSelfProtectionBlock("other_tool", nil, []string{"f-block-agentshield-guard"}) {
		t.Error("a listed self-protection rule lost its audit-only keep")
	}
	if r := gev.EvaluateToolCall("f_guard", nil); r.Decision == policy.DecisionBlock {
		t.Errorf("the listed guard rule still matched: %v", r.TriggeredRules)
	}
}

// Over every shipped MCP rule: a lookalike of any id (prefix, longer, case,
// whitespace) switches nothing off; listing every id leaves nothing to match;
// and listing one id removes exactly the rules with that id.
func TestWithoutDisabledRules_ShippedCorpus5001(t *testing.T) {
	p := newTestMCPEvaluator(t).policy
	all := ids5001(p)
	isID := map[string]bool{}
	var every []string
	for _, ids := range all {
		for _, id := range ids {
			if !isID[id] {
				isID[id] = true
				every = append(every, id)
			}
		}
	}
	// A floor the community packs alone clear (the OSS tree has no premium).
	if len(every) < 300 {
		t.Fatalf("only %d rule ids loaded: the corpus is not what this test measures", len(every))
	}

	var lookalikes []string
	for _, id := range every {
		for _, v := range []string{id[:len(id)-1], id + "x", strings.ToUpper(id), " " + id, id + " ", id + "\t", strings.ReplaceAll(id, "-", "_")} {
			if !isID[v] {
				lookalikes = append(lookalikes, v)
			}
		}
	}
	if got := withoutDisabledRules(p, lookalikes); !reflect.DeepEqual(ids5001(got), all) {
		t.Errorf("%d lookalike ids switched rules off", len(lookalikes))
	}

	got := withoutDisabledRules(p, every)
	if n := len(got.Rules) + len(got.StructuralRules) + len(got.SemanticRules) + len(got.ResourceRules) + len(got.ValueLimits); n != 0 {
		t.Errorf("every id listed: %d rules left to match", n)
	}

	// One id at a time, a stride through the corpus.
	for i := 0; i < len(every); i += len(every)/97 + 1 {
		id := every[i]
		want := map[string][]string{}
		for fam, ids := range all {
			for _, x := range ids {
				if x != id {
					want[fam] = append(want[fam], x)
				}
			}
		}
		if g := ids5001(withoutDisabledRules(p, []string{id})); !reflect.DeepEqual(g, want) {
			t.Errorf("listed %s: a rule other than its own was removed, or its own survived", id)
		}
	}
}

// Only ids no rule has (nothing listed is the identity, pinned above): every
// scenario of the MCP corpus decides exactly as main's evaluator decides it,
// record and all, on the rule matcher, the value_limits pass and
// resources/read. The filtered copy is a different policy value, so this is
// what shows the copy loses nothing.
func TestWithoutDisabledRules_ScenarioCorpusUnchanged5001(t *testing.T) {
	mainEv := newTestMCPEvaluator(t)
	unknown := NewPolicyEvaluator(mainEv.policy)
	unknown.DisableRules([]string{"zz5001-no-such-rule", "", "MCP-STRUCT-BLOCK-SENSITIVE-PATH-WRITE"})
	views := map[string]*PolicyEvaluator{"unknown": unknown}
	n := 0
	for _, sc := range scenarios.AllScenarios() {
		if sc.ToolName == "" && sc.ResourcesUpdatedURI == "" {
			continue
		}
		n++
		verdict := func(ev *PolicyEvaluator) [2]MCPEvalResult {
			var out [2]MCPEvalResult
			if sc.ToolName != "" {
				r := ev.EvaluateToolCallFull(sc.ToolName, sc.Arguments, sc.ToolDescription)
				out[0], _ = ev.ApplyValueLimits(r, sc.ToolName, sc.Arguments)
			}
			if sc.ResourcesUpdatedURI != "" {
				out[1] = ev.EvaluateResourceRead(sc.ResourcesUpdatedURI)
			}
			return out
		}
		want := verdict(mainEv)
		for name, ev := range views {
			if got := verdict(ev); !reflect.DeepEqual(got, want) {
				t.Errorf("%s (%s list): %+v, main %+v", sc.ID, name, got, want)
			}
		}
	}
	if n < 1000 {
		t.Fatalf("only %d scenarios evaluated: the corpus is not what this test measures", n)
	}
}

// A disabled sentinel cannot crash anything and does not reach its Go check:
// the scheme-hijack scan still BLOCKs and still names the sentinel it labels.
// Control: with no sentinel loaded at all, the scan still BLOCKs, unlabelled.
func TestWithoutDisabledRules_SentinelKeepsItsGoCheck5001(t *testing.T) {
	path := "http://169.254." + "169.254/latest/" + "meta-data/"
	runListed := func(p *MCPPolicy, list []string) (bool, AuditEntry) {
		var got AuditEntry
		ev := NewPolicyEvaluator(p)
		ev.DisableRules(list)
		h := &MessageHandler{Evaluator: ev, Stderr: io.Discard, OnAudit: func(e AuditEntry) { got = e }}
		msg := &Message{JSONRPC: "2.0", ID: mustRequestID(t), Method: MethodToolsCall,
			Params: mustMarshal(t, CallToolParams{Name: "read_file", Arguments: map[string]interface{}{"path": path}})}
		blocked, _ := h.HandleToolCall(msg)
		return blocked, got
	}
	run := func(p *MCPPolicy) (bool, AuditEntry) { return runListed(p, nil) }
	withSentinel := func() *MCPPolicy {
		return &MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit},
			Rules: []MCPRule{{ID: "zz5001-sentinel", Engine: "mcp-filesystem-scheme-hijack", Decision: policy.DecisionBlock, Taxonomy: "zz5001/sentinel"}}}
	}
	blocked, rec := runListed(withSentinel(), []string{"zz5001-sentinel"})
	if !blocked || rec.Decision != "BLOCK" || !containsString(rec.TriggeredRules, "filesystem-scheme-hijack-scan") || !containsString(rec.TriggeredRules, "zz5001-sentinel") {
		t.Errorf("sentinel listed: blocked=%v %s %v; want the scan's BLOCK, labelled by the sentinel", blocked, rec.Decision, rec.TriggeredRules)
	}
	_, unlisted := run(withSentinel())
	if !reflect.DeepEqual(rec.TriggeredRules, unlisted.TriggeredRules) || rec.Decision != unlisted.Decision {
		t.Errorf("sentinel listed %v, unlisted %v; want the same record", rec.TriggeredRules, unlisted.TriggeredRules)
	}
	blocked, rec = run(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}})
	if !blocked || containsString(rec.TriggeredRules, "zz5001-sentinel") {
		t.Errorf("no sentinel: blocked=%v %v; want the scan's BLOCK, unlabelled", blocked, rec.TriggeredRules)
	}
}
