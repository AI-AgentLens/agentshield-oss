package mcp

import (
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4337 review B1. Two layers keep self-protection blocking in audit-only
// mode on the proxies: the config guard, now spelling-proof for AgentShield's
// own directory and HOME-anchored files, and the self-protection rules of the
// policy (PolicyEvaluator.IsSelfProtectionRule), which audit-only never lowers.
// The OSS build has only the first; the full build has both.

// Layer 1 in isolation: a BLOCK from a self-protection rule stays a BLOCK in
// audit-only even when the guard does not see the call. The rules below match
// a free-text argument the guard never reads as a path or command.
func TestApplyToolCallMode_SelfProtectionRuleKeepsBlock(t *testing.T) {
	note := func(pattern string) map[string]string { return map[string]string{"note": pattern} }
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{ID: "custom-guard-dir", Match: MCPMatch{ToolName: "annotate", ArgumentRegexPatterns: note(`\.agent` + `shield/`)}, Decision: policy.DecisionBlock, Reason: "names the config dir"},
			{ID: "custom-guard-hook", Match: MCPMatch{ToolName: "annotate2", ArgumentRegexPatterns: note(`\.claude/settings\.json`)}, Decision: policy.DecisionBlock, Reason: "names a hook file"},
			{ID: "custom-tamper", Taxonomy: selfProtectionTaxonomy, Match: MCPMatch{ToolName: "annotate3", ArgumentRegexPatterns: note(`stop`)}, Decision: policy.DecisionBlock, Reason: "tamper taxonomy"},
			{ID: "custom-ordinary", Match: MCPMatch{ToolName: "annotate4", ArgumentRegexPatterns: note(`\.ssh/`)}, Decision: policy.DecisionBlock, Reason: "ordinary block"},
		},
	}
	cases := []struct {
		tool, note string
		keep       bool
	}{
		{"annotate", "please look at the .agent" + "shield/ folder later", true},
		// Hook files protect by path, not by rule (#4337 review pass 2,
		// follow-up 3): a rule that names one is not a self-protection rule,
		// so this prose BLOCK is lowered. The keep rule's path reading
		// protects the hook file itself (TestKeepRule_*).
		{"annotate2", "the .claude/settings.json file is fine", false},
		{"annotate3", "stop the sensor", true},
		{"annotate4", "the .ssh/ folder", false},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			var entries []AuditEntry
			h := newMessageHandler(NewPolicyEvaluator(pol), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "t", t.TempDir(), nil, nil)
			h.Mode = "audit-only"
			args := map[string]interface{}{"note": tc.note}
			if g := CheckConfigGuard(tc.tool, args); g.Blocked {
				t.Fatalf("fixture error: the guard blocks this call, so it does not isolate the rule layer (%+v)", g.Findings)
			}
			params, _ := json.Marshal(map[string]interface{}{"name": tc.tool, "arguments": args})
			raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
			msg, _, err := ParseMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			blocked, _ := h.HandleToolCall(msg)
			if blocked != tc.keep {
				t.Fatalf("blocked = %v; want %v", blocked, tc.keep)
			}
			e := entries[len(entries)-1]
			if tc.keep && (e.Decision != "BLOCK" || e.OriginalDecision != "") {
				t.Errorf("record = %s (original %q); want BLOCK", e.Decision, e.OriginalDecision)
			}
			if !tc.keep && (e.Decision != "AUDIT" || e.OriginalDecision != "BLOCK") {
				t.Errorf("record = %s (original %q); want AUDIT with original BLOCK", e.Decision, e.OriginalDecision)
			}
		})
	}
}

// The drift ratchet for the self-protection set. The set is derived from rule
// content (IsSelfProtectionRule), so it has no id list to fall out of date;
// this pins the rules known today, requires every BLOCK rule named for
// AgentShield to be in it, and bounds its size so a broken derivation that
// swept in every rule (audit-only would then lower nothing) fails here.
func TestSelfProtectionRules_EmbeddedPacks(t *testing.T) {
	pol, _, err := LoadEmbeddedMCPPacks(DefaultMCPPolicy())
	if err != nil || pol == nil {
		t.Fatalf("LoadEmbeddedMCPPacks: %v", err)
	}
	e := NewPolicyEvaluator(pol)

	type ruleView struct {
		id       string
		decision policy.Decision
		match    interface{}
	}
	var all []ruleView
	for _, r := range pol.Rules {
		all = append(all, ruleView{r.ID, r.Decision, r.Match})
	}
	for _, r := range pol.StructuralRules {
		all = append(all, ruleView{r.ID, r.Decision, r.Match})
	}
	for _, r := range pol.SemanticRules {
		all = append(all, ruleView{r.ID, r.Decision, r.Match})
	}
	present := map[string]bool{}
	var set []string
	for _, r := range all {
		present[r.id] = true
		if _, err := json.Marshal(r.match); err != nil {
			t.Errorf("rule %s: match does not serialise (%v); it would count as self-protection by default", r.id, err)
		}
		if e.IsSelfProtectionRule(r.id) {
			set = append(set, r.id)
			if r.decision != policy.DecisionBlock {
				t.Errorf("rule %s is %s but counted as a self-protection BLOCK", r.id, r.decision)
			}
		}
		if r.decision == policy.DecisionBlock && strings.Contains(strings.ToLower(r.id), "agentshield") && !e.IsSelfProtectionRule(r.id) {
			t.Errorf("BLOCK rule %s is named for AgentShield but is not in the self-protection set", r.id)
		}
	}

	// The full build carries the premium packs; the OSS build does not.
	for _, id := range []string{
		"mcp-persist-block-agentshield-config-write",
		"mcp-persist-block-security-config-delete",
		"mcp-recon-block-agentshield-policy-read",
		"mcp-recon-block-agentshield-sensitive-files",
		"mcp-pe-block-ai-audit-log-injection",
	} {
		if present[id] && !e.IsSelfProtectionRule(id) {
			t.Errorf("known self-protection rule %s is not in the set", id)
		}
	}
	if len(set) > 20 {
		t.Errorf("self-protection set has %d rules, over the bound of 20: %v. Audit-only never lowers these, so a derivation that sweeps in ordinary rules turns audit-only back into enforce. Check selfProtectionMarkers and isSelfProtectionRule.", len(set), set)
	}
	t.Logf("self-protection rules (%d of %d): %v", len(set), len(all), set)
}

// On a managed host the shell's self-protection rules apply to command text
// on the proxy, through the matcher the CLI injects; not on an unmanaged one.
func TestHandleToolCall_ManagedSelfProtectCommand(t *testing.T) {
	matcher := func(cmd string) (string, bool) {
		if strings.Contains(cmd, "setup cursor --disable") {
			return "sp-block-setup-disable", true
		}
		return "", false
	}
	for _, tc := range []struct {
		name    string
		managed bool
		block   bool
	}{
		{"managed", true, true},
		{"unmanaged", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var entries []AuditEntry
			managed := tc.managed
			h := newMessageHandler(NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}, BlockedTools: []string{"execute_command"}}),
				func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "t", t.TempDir(), nil, func() bool { return managed })
			h.Mode = "audit-only"
			h.SelfProtectCommand = matcher
			params, _ := json.Marshal(map[string]interface{}{"name": "execute_command", "arguments": map[string]interface{}{"command": "agentshield setup cursor --disable"}})
			raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
			msg, _, _ := ParseMessage(raw)
			blocked, _ := h.HandleToolCall(msg)
			if blocked != tc.block {
				t.Fatalf("blocked = %v; want %v (record %+v)", blocked, tc.block, entries)
			}
			if tc.block && !strings.Contains(strings.Join(entries[len(entries)-1].Reasons, " "), "sp-block-setup-disable") {
				t.Errorf("record does not name the self-protection rule: %+v", entries[len(entries)-1])
			}
		})
	}
}

// spellingToPath maps every string spelling of a path to the plain path.
// The firmlink and symlinked HOME are not string spellings: absNamesTarget
// handles them by identity.
func TestSpellingToPath(t *testing.T) {
	home := "/Users/u"
	want := "/Users/u/x/y.json"
	for _, in := range []string{
		"file://" + home + "/x/y.json",
		"FILE://" + home + "/x/y.json",
		"file:" + home + "/x/y.json",
		"file:///Users/u/x/y.json",
		"file://localhost" + home + "/x/y.json",
		"file://" + home + "/x/%79.json",
		"$HOME/x/y.json",
		"${HOME}/x/y.json",
		"~/x/y.json",
		"  ~/x/y.json  ",
	} {
		if got, ok := spellingToPath(in, home); !ok || got != want {
			t.Errorf("spellingToPath(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"$HOMEDIR/x", "relative/x", "/System/Volumes/Data/Users/u/x"} {
		if got, ok := spellingToPath(in, home); !ok || got != in {
			t.Errorf("spellingToPath(%q) = %q, %v; want it unchanged", in, got, ok)
		}
	}
	for _, in := range []string{"", "a\nb", "file://otherhost/Users/u/x"} {
		if _, ok := spellingToPath(in, home); ok {
			t.Errorf("spellingToPath(%q) ok; want not a path", in)
		}
	}
}
