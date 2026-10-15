package mcp

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// #4248 option (c): a harness file-read tool (Claude Code Read, Copilot CLI
// view) that decides AUDIT carries the read rules and taxonomy its call would
// trigger as an MCP read_file — recorded, never enforced. The contract these
// tests pin:
//
//   - no decision changes, anywhere (the guarantee that keeps this out of
//     enforcement and in attestation);
//   - the attributed AUDIT carries rules, index-paired reasons and taxonomy;
//   - OriginalDecision stays empty (AUDIT + original BLOCK means "audit-only
//     mode would have blocked" to the SaaS, which is not the case here);
//   - BLOCK, ALLOW, non-harness tools and benign paths are untouched.

const harnessAttributionMarker = "Recorded, not enforced (#4248)"

// readFamilyTPPaths collects the path of every read-family TP fixture in the
// loaded packs — the population #4248 measured (1,470 BLOCK paths).
func readFamilyTPPaths(t *testing.T, ev *PolicyEvaluator) []string {
	t.Helper()
	readTools := map[string]bool{"read_file": true, "read_text_file": true, "cat_file": true, "open_file": true, "view_file": true, "get_file_contents": true}
	seen := map[string]bool{}
	var paths []string
	collect := func(tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for _, tc := range tests.TP {
			args, err := tc.ResolvedArgs()
			if err != nil || !readTools[tc.Tool] {
				continue
			}
			if p, ok := args["path"].(string); ok && p != "" && !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}
	for _, r := range ev.policy.Rules {
		collect(r.Tests)
	}
	for _, r := range ev.policy.StructuralRules {
		collect(r.Tests)
	}
	return paths
}

// withoutAttribution is the decision path minus attributeHarnessRead — what
// main decided before #4248.
func withoutAttribution(ev *PolicyEvaluator, tool string, args map[string]interface{}) MCPEvalResult {
	for _, blocked := range ev.policy.BlockedTools {
		if matchToolName(tool, blocked) {
			return ev.EvaluateToolCall(tool, args)
		}
	}
	return applyMCPModeDowngrade(ev.evaluateReadings(tool, args, "", nil), ev.mode)
}

func attributed(r MCPEvalResult) []string {
	var out []string
	for _, reason := range r.Reasons {
		if strings.HasPrefix(reason, harnessAttributionMarker) {
			out = append(out, reason)
		}
	}
	return out
}

// TestHarnessReadAttribution_NoDecisionChanges is the guarantee: across every
// inline TP/TN fixture of every loaded MCP pack, and every read-family path
// re-cast as Read/file_path and view/path, the decision equals the decision
// without attribution.
func TestHarnessReadAttribution_NoDecisionChanges(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	type probe struct {
		tool string
		args map[string]interface{}
	}
	var probes []probe
	add := func(tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for _, tc := range append(append([]MCPTestCase{}, tests.TP...), tests.TN...) {
			if args, err := tc.ResolvedArgs(); err == nil && tc.Tool != "" {
				probes = append(probes, probe{tc.Tool, args})
			}
		}
	}
	for _, r := range ev.policy.Rules {
		add(r.Tests)
	}
	for _, r := range ev.policy.StructuralRules {
		add(r.Tests)
	}
	for _, p := range readFamilyTPPaths(t, ev) {
		probes = append(probes, probe{"Read", map[string]interface{}{"file_path": p}}, probe{"view", map[string]interface{}{"path": p}})
	}
	if len(probes) < 5000 {
		t.Fatalf("only %d probes — fixture extraction stopped matching", len(probes))
	}
	changed := 0
	for _, p := range probes {
		before := withoutAttribution(ev, p.tool, p.args)
		after := ev.EvaluateToolCall(p.tool, p.args)
		if before.Decision != after.Decision || before.OriginalDecision != after.OriginalDecision {
			changed++
			if changed <= 10 {
				t.Errorf("%s %v: decision %s/%q -> %s/%q", p.tool, p.args, before.Decision, before.OriginalDecision, after.Decision, after.OriginalDecision)
			}
		}
	}
	t.Logf("%d probes, %d decision changes", len(probes), changed)
}

// TestHarnessReadAttribution_ReceiptsCarryRulesAndTaxonomy is the #4248
// matrix: every read-family path that read_file BLOCKs and Read/view only
// AUDITs now yields an AUDIT that carries the read rules and taxonomy.
func TestHarnessReadAttribution_ReceiptsCarryRulesAndTaxonomy(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	gap, attributedCount := 0, 0
	for _, p := range readFamilyTPPaths(t, ev) {
		if ev.EvaluateToolCall("read_file", map[string]interface{}{"path": p}).Decision != policy.DecisionBlock {
			continue
		}
		for _, call := range []struct {
			tool string
			args map[string]interface{}
		}{{"Read", map[string]interface{}{"file_path": p}}, {"view", map[string]interface{}{"path": p}}} {
			before := withoutAttribution(ev, call.tool, call.args)
			if before.Decision != policy.DecisionAudit {
				continue // already BLOCKed (catch-all) or otherwise decided
			}
			gap++
			got := ev.EvaluateToolCall(call.tool, call.args)
			marks := attributed(got)
			if got.Decision != policy.DecisionAudit || got.OriginalDecision != "" {
				t.Fatalf("%s %s: decision %s / original %q, want AUDIT / empty", call.tool, p, got.Decision, got.OriginalDecision)
			}
			if len(marks) == 0 || len(got.AllTaxonomyRefs()) == 0 {
				t.Errorf("%s %s: no attribution (rules %v, taxonomy %v)", call.tool, p, got.TriggeredRules, got.AllTaxonomyRefs())
				continue
			}
			if len(got.TriggeredRules) != len(got.Reasons) {
				t.Errorf("%s %s: rules (%d) and reasons (%d) no longer index-paired", call.tool, p, len(got.TriggeredRules), len(got.Reasons))
			}
			attributedCount++
		}
	}
	// Positive control: #4248 measured 1,360 Read and 1,340 view gaps on these
	// fixtures. If the sweep finds far fewer, it is not measuring the gap.
	if gap < 2000 {
		t.Errorf("only %d Read/view AUDIT gaps found (measured ~2,700) — the sweep no longer reaches the population", gap)
	}
	t.Logf("Read/view AUDIT gaps: %d; now attributed: %d", gap, attributedCount)
}

func TestHarnessReadAttribution_LeavesOtherDecisionsAlone(t *testing.T) {
	var p MCPPolicy
	if err := yaml.Unmarshal([]byte(`
defaults:
  decision: AUDIT
rules:
  - id: t-read-secret
    taxonomy: credential-exposure/config-file-access/generic-config-access
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**/.vendor/secret.json"
    decision: BLOCK
    reason: vendor secret read
  - id: t-read-secret-2
    taxonomy: credential-exposure/config-file-access/generic-config-access
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "**/.vendor/*.json"
    decision: BLOCK
    reason: second vendor rule, different reason
  - id: t-read-own-audit
    taxonomy: test/own-read-audit
    match:
      tool_name_any: ["Read"]
      argument_patterns:
        file_path: "**/.vendor/**"
    decision: AUDIT
    reason: Read's own audit rule
  - id: t-read-device-audit
    taxonomy: test/device-read
    match:
      tool_name_any: ["read_file"]
      argument_patterns:
        path: "/dev/**"
    decision: AUDIT
    reason: device read audited
structural_rules:
  - id: t-any-tool-blocklisted
    match:
      tool_name_regex: ".*"
      args_match:
        file_path:
          pattern_any: ['/blocked/']
    decision: BLOCK
    reason: blocked dir
`), &p); err != nil {
		t.Fatal(err)
	}
	ev := NewPolicyEvaluator(&p)
	secret := "/home/u/.vendor/secret.json"

	// The positive case, on the inline policy: two equivalent BLOCK rules, plus
	// the Read call's own AUDIT rule.
	got := ev.EvaluateToolCall("Read", map[string]interface{}{"file_path": secret})
	if got.Decision != policy.DecisionAudit || !slices.Contains(got.TriggeredRules, "t-read-secret") || len(attributed(got)) != 2 {
		t.Fatalf("Read of the secret: got %s %v %v, want AUDIT attributed to both read rules", got.Decision, got.TriggeredRules, got.Reasons)
	}
	// Both the attributed taxonomy AND the Read's own AUDIT-rule taxonomy are
	// kept: attribution appends, it never replaces.
	for _, ref := range []string{"credential-exposure/config-file-access/generic-config-access", "test/own-read-audit"} {
		if !slices.Contains(got.AllTaxonomyRefs(), ref) {
			t.Errorf("taxonomy %q missing from the attributed AUDIT: %v", ref, got.AllTaxonomyRefs())
		}
	}
	// Each attributed reason carries ITS OWN rule's reason, index-paired.
	own := map[string]string{"t-read-secret": "vendor secret read", "t-read-secret-2": "second vendor rule, different reason"}
	for i, rule := range got.TriggeredRules {
		want, ok := own[rule]
		if !ok {
			continue
		}
		if !strings.HasSuffix(got.Reasons[i], " — "+want) {
			t.Errorf("reason paired with %s = %q, want it to end with its own reason %q", rule, got.Reasons[i], want)
		}
	}

	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		want policy.Decision
	}{
		{"BLOCK is untouched", "Read", map[string]interface{}{"file_path": "/blocked/.vendor/secret.json"}, policy.DecisionBlock},
		{"the MCP tool itself is not re-attributed", "read_file", map[string]interface{}{"path": secret}, policy.DecisionBlock},
		{"benign path gets nothing", "Read", map[string]interface{}{"file_path": "/home/u/project/README.md"}, policy.DecisionAudit},
		{"non-read harness tool is out of scope", "Write", map[string]interface{}{"file_path": secret}, policy.DecisionAudit},
		// The equivalent read_file decides AUDIT WITH a rule: only BLOCK
		// equivalents are attributed (the reason says "matches the BLOCK rule").
		{"AUDIT-with-rule equivalent is not attributed", "Read", map[string]interface{}{"file_path": "/dev/zero"}, policy.DecisionAudit},
	}
	for _, c := range cases {
		got := ev.EvaluateToolCall(c.tool, c.args)
		if got.Decision != c.want || len(attributed(got)) != 0 {
			t.Errorf("%s: got %s with %d attribution reason(s), want %s and none", c.name, got.Decision, len(attributed(got)), c.want)
		}
	}

	// MCP rules only raise from the default (most restrictive wins), so ALLOW
	// is reachable only with a default-ALLOW policy. There the read decides
	// ALLOW and must stay unannotated: attribution applies to AUDIT only.
	allowPolicy := p
	allowPolicy.Defaults.Decision = policy.DecisionAllow
	// Without the Read's own AUDIT rule, which would raise ALLOW to AUDIT.
	allowPolicy.Rules = slices.DeleteFunc(slices.Clone(p.Rules), func(r MCPRule) bool { return r.ID == "t-read-own-audit" })
	if r := NewPolicyEvaluator(&allowPolicy).EvaluateToolCall("Read", map[string]interface{}{"file_path": secret}); r.Decision != policy.DecisionAllow || len(attributed(r)) != 0 {
		t.Errorf("default-ALLOW policy: Read of the secret = %s with %d attribution reason(s), want ALLOW and none", r.Decision, len(attributed(r)))
	}

	// Audit-only mode: a real BLOCK is downgraded with OriginalDecision BLOCK
	// (unchanged behaviour), while an attributed read stays AUDIT with NO
	// OriginalDecision — it would not have been blocked in enforce mode either.
	ev.SetMode("audit-only")
	if r := ev.EvaluateToolCall("read_file", map[string]interface{}{"path": secret}); r.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only control: read_file original = %q, want BLOCK", r.OriginalDecision)
	}
	r := ev.EvaluateToolCall("Read", map[string]interface{}{"file_path": secret})
	if r.Decision != policy.DecisionAudit || r.OriginalDecision != "" || len(attributed(r)) != 2 {
		t.Errorf("audit-only: attributed read = %s / original %q / %d marks, want AUDIT / empty / 2", r.Decision, r.OriginalDecision, len(attributed(r)))
	}
	// Attribution runs on the ENFORCE decision, before the downgrade: a Read
	// that BLOCKs and is merely downgraded must not be annotated as "not
	// enforced" — it carries OriginalDecision BLOCK instead.
	d := ev.EvaluateToolCall("Read", map[string]interface{}{"file_path": "/blocked/.vendor/secret.json"})
	if d.Decision != policy.DecisionAudit || d.OriginalDecision != policy.DecisionBlock || len(attributed(d)) != 0 {
		t.Errorf("audit-only downgraded BLOCK: got %s / original %q / %d marks, want AUDIT / BLOCK / 0", d.Decision, d.OriginalDecision, len(attributed(d)))
	}
}

// TestHarnessReadAttribution_ReasonNamesTheRule keeps the receipt readable:
// every attributed reason names its rule and the MCP tool it was matched as.
func TestHarnessReadAttribution_ReasonNamesTheRule(t *testing.T) {
	ev := newTestMCPEvaluator(t)
	path := "/var/run/secrets/kubernetes.io/serviceaccount/" + "token"
	got := ev.EvaluateToolCall("Read", map[string]interface{}{"file_path": path})
	marks := attributed(got)
	if got.Decision != policy.DecisionAudit || len(marks) == 0 {
		t.Fatalf("got %s with %d attribution reasons; want an attributed AUDIT (rules %v)", got.Decision, len(marks), got.TriggeredRules)
	}
	for i, rule := range got.TriggeredRules {
		if strings.HasPrefix(got.Reasons[i], harnessAttributionMarker) && !strings.Contains(got.Reasons[i], fmt.Sprintf("as read_file this call matches the BLOCK rule %s", rule)) {
			t.Errorf("reason %d does not name its paired rule %s: %q", i, rule, got.Reasons[i])
		}
	}
}

// TestHarnessReadAttribution_SeparatorInArgumentName: an argument NAME is
// attacker-declared, so "file_path" with a trailing U+00A0 must still be
// resolved (resolveField, check-arg-map-lookups #3720) and attributed.
func TestHarnessReadAttribution_SeparatorInArgumentName(t *testing.T) {
	ev := newTestMCPEvaluator(t)
	path := "/var/run/secrets/kubernetes.io/serviceaccount/" + "token"
	got := ev.EvaluateToolCall("Read", map[string]interface{}{"file_path ": path})
	if got.Decision != policy.DecisionAudit || len(attributed(got)) == 0 || len(got.AllTaxonomyRefs()) == 0 {
		t.Fatalf("Read with a separator-suffixed file_path key: got %s, %d attribution reasons, taxonomy %v; want an attributed AUDIT",
			got.Decision, len(attributed(got)), got.AllTaxonomyRefs())
	}
}
