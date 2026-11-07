package mcp

import (
	"reflect"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4653: a relative customer pattern (`secrets/**`, `.env`) never matched a
// file tool, because Claude Code sends absolute paths and the check had no
// working directory. InWorkingDir gives it one, with the shell engine's
// semantics: a relative pattern matches a path under the directory, and a
// relative argument is read under it.
func TestProtectedPathArgument_RelativePatternsUnderWorkDir4653(t *testing.T) {
	const repo = "/work/repo"
	base := protectedTestEvaluator(t, "secrets/**", ".env", "/work/repo/vault/**")
	e := base.InWorkingDir(repo)
	rows := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"Read under secrets", "Read", map[string]interface{}{"file_path": repo + "/secrets/k.pem"}},
		{"Write under secrets", "Write", map[string]interface{}{"file_path": repo + "/secrets/new.key", "content": "x"}},
		{"Edit under secrets", "Edit", map[string]interface{}{"file_path": repo + "/secrets/k.pem", "old_string": "a", "new_string": "b"}},
		{"NotebookEdit under secrets", "NotebookEdit", map[string]interface{}{"notebook_path": repo + "/secrets/n.ipynb", "new_source": "x"}},
		{"Grep on the relative directory", "Grep", map[string]interface{}{"pattern": "password", "path": "secrets"}},
		{"Read the exact relative file", "Read", map[string]interface{}{"file_path": repo + "/.env"}},
		{"relative argument, absolute pattern", "Grep", map[string]interface{}{"pattern": "x", "path": "vault"}},
		{"case variant of a relative pattern", "Read", map[string]interface{}{"file_path": repo + "/SECRETS/k.pem"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := e.EvaluateToolCall(r.tool, r.args)
			if !isProtectedPathBlock(got) || !reflect.DeepEqual(got.AllTaxonomyRefs(), []string{policy.ProtectedPathNode}) {
				t.Fatalf("with the working dir: %s %v %v; want BLOCK protected-path [%s]", got.Decision, got.TriggeredRules, got.AllTaxonomyRefs(), policy.ProtectedPathNode)
			}
		})
	}
	// Control, main's behaviour: without a working directory the absolute
	// paths do not match a relative pattern.
	for _, r := range rows[:4] {
		if got := base.EvaluateToolCall(r.tool, r.args); isProtectedPathBlock(got) {
			t.Errorf("%s without a working dir: %v; the control should not block", r.name, got.TriggeredRules)
		}
	}
}

// What the working directory must not do: claim files outside it, follow
// `..` out of the protected tree, or take a relative directory.
func TestProtectedPathArgument_WorkDirNearMisses4653(t *testing.T) {
	e := protectedTestEvaluator(t, "secrets/**", ".env").InWorkingDir("/work/repo")
	for _, c := range []struct {
		name string
		args map[string]interface{}
	}{
		{"same pattern, another directory", map[string]interface{}{"file_path": "/elsewhere/secrets/k.pem"}},
		{"sibling of the protected directory", map[string]interface{}{"file_path": "/work/repo/secrets-howto.md"}},
		{"dot segments leave the tree", map[string]interface{}{"file_path": "/work/repo/secrets/../README.md"}},
		{"a parent of the working dir", map[string]interface{}{"file_path": "/work/.env"}},
		{"an .env.example", map[string]interface{}{"file_path": "/work/repo/.env.example"}},
		{"relative argument outside", map[string]interface{}{"file_path": "../other/secrets/k"}},
	} {
		if got := e.EvaluateToolCall("Read", c.args); got.Decision == policy.DecisionBlock {
			t.Errorf("%s: %v; want no BLOCK", c.name, got.TriggeredRules)
		}
	}
	rel := protectedTestEvaluator(t, "secrets/**").InWorkingDir("relative/dir")
	if got := rel.EvaluateToolCall("Read", map[string]interface{}{"file_path": "/x/relative/dir/secrets/k"}); got.Decision == policy.DecisionBlock {
		t.Errorf("a relative working dir was used: %v", got.TriggeredRules)
	}
}

// Raise-only: a working directory never lowers a verdict, and the view leaves
// the evaluator it came from as it was.
func TestProtectedPathArgument_WorkDirOnlyRaises4653(t *testing.T) {
	patterns := []string{"secrets/**", ".env", "/etc/acme/secrets/**", "~/company/**"}
	base := protectedTestEvaluator(t, patterns...)
	view := base.InWorkingDir("/work/repo")
	paths := []string{"/work/repo/secrets/a", "secrets/a", "/etc/acme/secrets/a", "/work/repo/.env", ".env", "/tmp/x", "~/company/a", "/work/repo/README.md"}
	raised := 0
	for _, p := range paths {
		args := map[string]interface{}{"file_path": p}
		without, with := base.EvaluateToolCall("Read", args), view.EvaluateToolCall("Read", args)
		if decisionSeverity(with.Decision) < decisionSeverity(without.Decision) {
			t.Errorf("%s: %s with the working dir, %s without", p, with.Decision, without.Decision)
		}
		if decisionSeverity(with.Decision) > decisionSeverity(without.Decision) {
			raised++
		}
	}
	if raised != 2 {
		t.Errorf("%d paths raised, want 2 (the absolute paths under the working dir)", raised)
	}
	if got := base.EvaluateToolCall("Read", map[string]interface{}{"file_path": "/work/repo/secrets/a"}); got.Decision == policy.DecisionBlock {
		t.Errorf("InWorkingDir changed the evaluator it was called on: %v", got.TriggeredRules)
	}
}

// #4654 item 3, M11: when protected-path RAISES a lower verdict, the record is
// the BLOCK's alone. The AUDIT rule that decided before is replaced, not
// carried into the BLOCK record, as for every rule that outranks another.
func TestProtectedPathArgument_RaiseReplacesTheLowerRecord4654(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{{
			ID:       "zq-audit-acme-read",
			Match:    MCPMatch{ToolName: "read_file", ArgumentPatterns: map[string]string{"path": "/etc/acme/*"}},
			Decision: policy.DecisionAudit,
			Reason:   "audit test",
			Taxonomy: "credential-exposure/config-file-access/generic-config-access",
		}},
	}
	args := map[string]interface{}{"path": "/etc/acme/db.env"}
	before := NewPolicyEvaluator(pol).EvaluateToolCall("read_file", args)
	if before.Decision != policy.DecisionAudit || !reflect.DeepEqual(before.TriggeredRules, []string{"zq-audit-acme-read"}) {
		t.Fatalf("control: %s %v; want the AUDIT rule's record", before.Decision, before.TriggeredRules)
	}
	e := NewPolicyEvaluator(pol)
	e.SetProtectedPaths([]string{"/etc/acme/**"})
	got := e.EvaluateToolCall("read_file", args)
	if got.Decision != policy.DecisionBlock {
		t.Fatalf("decision %s, want BLOCK", got.Decision)
	}
	if !reflect.DeepEqual(got.TriggeredRules, []string{policy.ProtectedPathRuleID}) || len(got.Reasons) != 1 {
		t.Errorf("rules %v reasons %v; want only protected-path and its reason", got.TriggeredRules, got.Reasons)
	}
	if !reflect.DeepEqual(got.AllTaxonomyRefs(), []string{policy.ProtectedPathNode}) {
		t.Errorf("taxonomy %v, want only [%s]", got.AllTaxonomyRefs(), policy.ProtectedPathNode)
	}
}
