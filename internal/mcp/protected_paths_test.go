package mcp

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// acmeSecrets is the customer pattern of #4645's repro.
const acmeSecrets = "/etc/acme/secrets/**"

func acmeFile() string { return "/etc/acme/" + "secrets/db.env" }

// protectedTestEvaluator is an evaluator with no rules (default AUDIT) and
// the given customer protected paths, so a verdict can come only from the
// protected-path check.
func protectedTestEvaluator(t *testing.T, patterns ...string) *PolicyEvaluator {
	t.Helper()
	e := NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}})
	e.SetProtectedPaths(patterns)
	return e
}

func isProtectedPathBlock(r MCPEvalResult) bool {
	if r.Decision != policy.DecisionBlock {
		return false
	}
	for _, id := range r.TriggeredRules {
		if id == policy.ProtectedPathRuleID {
			return true
		}
	}
	return false
}

// #4645: a file-path argument naming a customer's protected path BLOCKs with
// the shell's rule id and the protected-path node, for the agent's own file
// tools and for MCP file tools.
func TestProtectedPathArgument_BlocksFileTools4645(t *testing.T) {
	e := protectedTestEvaluator(t, acmeSecrets)
	f := acmeFile()
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"Claude Code Read", "Read", map[string]interface{}{"file_path": f}},
		{"Claude Code Write", "Write", map[string]interface{}{"file_path": f, "content": "x"}},
		{"Claude Code Edit", "Edit", map[string]interface{}{"file_path": f, "old_string": "a", "new_string": "b"}},
		{"Claude Code MultiEdit", "MultiEdit", map[string]interface{}{"file_path": f, "edits": []interface{}{map[string]interface{}{"old_string": "a", "new_string": "b"}}}},
		{"Claude Code NotebookEdit", "NotebookEdit", map[string]interface{}{"notebook_path": "/etc/acme/secrets/n.ipynb", "new_source": "x"}},
		{"Claude Code Grep on the directory", "Grep", map[string]interface{}{"pattern": "password", "path": "/etc/acme/secrets"}},
		{"Copilot view", "view", map[string]interface{}{"path": f}},
		{"MCP read_file", "read_file", map[string]interface{}{"path": f}},
		{"MCP namespaced read_file", "mcp__fs__read_file", map[string]interface{}{"path": f}},
		{"MCP read_multiple_files", "read_multiple_files", map[string]interface{}{"paths": []interface{}{"/tmp/a", f}}},
		{"MCP move_file source", "move_file", map[string]interface{}{"source": f, "destination": "/tmp/x"}},
		{"MCP move_file destination", "move_file", map[string]interface{}{"source": "/tmp/x", "destination": f}},
		{"camelCase filePath", "open_file", map[string]interface{}{"filePath": f}},
		{"batch envelope", "write_files", map[string]interface{}{"files": []interface{}{map[string]interface{}{"path": f, "content": "x"}}}},
		{"dot segments resolve into the tree", "Read", map[string]interface{}{"file_path": "/etc/acme/other/../secrets/db.env"}},
		{"case variant (case-insensitive volume)", "Read", map[string]interface{}{"file_path": "/ETC/Acme/Secrets/db.env"}},
		{"macOS /private alias", "Read", map[string]interface{}{"file_path": "/private" + f}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := e.EvaluateToolCall(c.tool, c.args)
			if !isProtectedPathBlock(r) {
				t.Fatalf("decision %s rules %v; want BLOCK by %s", r.Decision, r.TriggeredRules, policy.ProtectedPathRuleID)
			}
			if got := r.AllTaxonomyRefs(); !reflect.DeepEqual(got, []string{policy.ProtectedPathNode}) {
				t.Errorf("taxonomy %v, want [%s]", got, policy.ProtectedPathNode)
			}
			if len(r.Reasons) == 0 || !strings.Contains(r.Reasons[0], acmeSecrets) {
				t.Errorf("reasons %v, want the pattern named", r.Reasons)
			}
		})
	}
}

// The check is about the path a call targets, nothing else.
func TestProtectedPathArgument_NearMissesAndMentionsDoNotBlock4645(t *testing.T) {
	e := protectedTestEvaluator(t, acmeSecrets)
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"sibling with a shared prefix", "Read", map[string]interface{}{"file_path": "/etc/acme/secrets-howto.md"}},
		{"parent directory", "Read", map[string]interface{}{"file_path": "/etc/acme/README"}},
		{"dot segments leave the tree", "Read", map[string]interface{}{"file_path": "/etc/acme/secrets/../README"}},
		{"content mentions the path", "Write", map[string]interface{}{"file_path": "/tmp/notes.md", "content": "see " + acmeFile()}},
		{"edit text mentions the path", "Edit", map[string]interface{}{"file_path": "/tmp/notes.md", "old_string": "a", "new_string": acmeFile()}},
		{"JSON written as data", "Edit", map[string]interface{}{"file_path": "/tmp/c.json", "old_string": "{}", "new_string": `{"path": "` + acmeFile() + `"}`}},
		{"query argument", "WebSearch", map[string]interface{}{"query": acmeFile()}},
		{"relative value, absolute pattern", "Read", map[string]interface{}{"file_path": "secrets/db.env"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r := e.EvaluateToolCall(c.tool, c.args); isProtectedPathBlock(r) || r.Decision == policy.DecisionBlock {
				t.Errorf("decision %s rules %v; want no BLOCK", r.Decision, r.TriggeredRules)
			}
		})
	}
}

// No-op control: with no customer paths the evaluator decides exactly as
// before, and the tilde form resolves against HOME like the shell's.
func TestProtectedPathArgument_NoPatternsNoChange4645(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	none := protectedTestEvaluator(t)
	args := map[string]interface{}{"file_path": acmeFile()}
	if r := none.EvaluateToolCall("Read", args); r.Decision != policy.DecisionAudit || len(r.TriggeredRules) != 0 {
		t.Errorf("no patterns: %s %v, want the default AUDIT with no rule", r.Decision, r.TriggeredRules)
	}
	e := protectedTestEvaluator(t, "~/company-secrets/**")
	for _, p := range []string{"~/company-secrets/a.txt", filepath.Join(home, "company-secrets", "a.txt")} {
		if r := e.EvaluateToolCall("Read", map[string]interface{}{"file_path": p}); !isProtectedPathBlock(r) {
			t.Errorf("%s: %s %v, want a protected-path BLOCK", p, r.Decision, r.TriggeredRules)
		}
	}
	if r := e.EvaluateToolCall("Read", map[string]interface{}{"file_path": filepath.Join(home, "company-secrets-old", "a")}); r.Decision == policy.DecisionBlock {
		t.Errorf("near miss under HOME blocked: %v", r.TriggeredRules)
	}
}

// Audit-only mode records the BLOCK as AUDIT with its rule and taxonomy, as
// for every other non-self-protection BLOCK.
func TestProtectedPathArgument_AuditOnlyDowngrades4645(t *testing.T) {
	e := protectedTestEvaluator(t, acmeSecrets)
	args := map[string]interface{}{"file_path": acmeFile()}
	r := e.ApplyModeKeepingSelfProtection(e.EvaluateToolCall("Read", args), "audit-only", "Read", args)
	if r.Decision != policy.DecisionAudit || r.OriginalDecision != policy.DecisionBlock || !reflect.DeepEqual(r.TriggeredRules, []string{policy.ProtectedPathRuleID}) {
		t.Errorf("audit-only: %s (original %s) %v; want AUDIT, BLOCK, [protected-path]", r.Decision, r.OriginalDecision, r.TriggeredRules)
	}
}

// The protected-path fold never rewrites the rules' record. Here a rule fires
// only in the case-folded reading while the customer pattern matches the path
// as written; folding the check inside each reading would have kept the
// as-written reading (a tie) and dropped the rule and its taxonomy.
func TestProtectedPathArgument_KeepsTheRulesRecord4645(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{{
			ID:       "zq-block-acme-read",
			Match:    MCPMatch{ToolName: "read_file", ArgumentPatterns: map[string]string{"path": "/etc/acme/secrets/*"}},
			Decision: policy.DecisionBlock,
			Reason:   "test",
			Taxonomy: "credential-exposure/config-file-access/generic-config-access",
		}},
	}
	args := map[string]interface{}{"path": "/ETC/acme/secrets/db.env"}
	main := NewPolicyEvaluator(pol).EvaluateToolCall("read_file", args)
	if main.Decision != policy.DecisionBlock || len(main.TriggeredRules) != 1 || main.TriggeredRules[0] != "zq-block-acme-read" {
		t.Fatalf("control: %s %v; want the rule's BLOCK through the case-folded reading", main.Decision, main.TriggeredRules)
	}
	e := NewPolicyEvaluator(pol)
	e.SetProtectedPaths([]string{"/ETC/acme/**"})
	got := e.EvaluateToolCall("read_file", args)
	if want := append(append([]string{}, main.TriggeredRules...), policy.ProtectedPathRuleID); !reflect.DeepEqual(got.TriggeredRules, want) {
		t.Errorf("rules %v, want main's %v then protected-path", got.TriggeredRules, main.TriggeredRules)
	}
	for _, ref := range append(main.AllTaxonomyRefs(), policy.ProtectedPathNode) {
		found := false
		for _, have := range got.AllTaxonomyRefs() {
			found = found || have == ref
		}
		if !found {
			t.Errorf("taxonomy %v lacks %s", got.AllTaxonomyRefs(), ref)
		}
	}
}

// With the shipped packs loaded, a customer path adds a BLOCK where the packs
// decided AUDIT, and on a path the packs already BLOCK it ties in beside their
// rule without displacing it.
func TestProtectedPathArgument_AlongsideShippedPacks4645(t *testing.T) {
	e := newTestMCPEvaluator(t)
	args := map[string]interface{}{"file_path": acmeFile()}
	before := e.EvaluateToolCall("Read", args)
	if before.Decision == policy.DecisionBlock {
		t.Fatalf("control: the shipped packs already BLOCK %s (%v); the test measures nothing", acmeFile(), before.TriggeredRules)
	}
	e.SetProtectedPaths([]string{acmeSecrets, "/srv/key/**"})
	if r := e.EvaluateToolCall("Read", args); !isProtectedPathBlock(r) {
		t.Errorf("customer path: %s %v, want a protected-path BLOCK", r.Decision, r.TriggeredRules)
	}
	// A path the packs block on their own: the tie keeps their rule first.
	shipped := map[string]interface{}{"path": "/home/user/" + ".vault-token"}
	base := newTestMCPEvaluator(t).EvaluateToolCall("read_file", shipped)
	if base.Decision != policy.DecisionBlock || len(base.TriggeredRules) == 0 {
		t.Fatalf("control: shipped packs do not BLOCK the vault token read: %s %v", base.Decision, base.TriggeredRules)
	}
	e.SetProtectedPaths([]string{"/home/user/**"})
	r := e.EvaluateToolCall("read_file", shipped)
	if r.Decision != policy.DecisionBlock || r.TriggeredRules[0] != base.TriggeredRules[0] {
		t.Errorf("tie: %s %v, want BLOCK led by the packs' %s", r.Decision, r.TriggeredRules, base.TriggeredRules[0])
	}
	for _, ref := range base.AllTaxonomyRefs() {
		found := false
		for _, got := range r.AllTaxonomyRefs() {
			found = found || got == ref
		}
		if !found {
			t.Errorf("tie dropped the packs' taxonomy %s: %v", ref, r.AllTaxonomyRefs())
		}
	}
}
