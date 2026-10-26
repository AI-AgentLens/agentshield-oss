package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4457, Gary 2026-10-21 ("split"): a git hook written through a harness's own
// file tool (Claude Code Write/Edit/MultiEdit, Copilot CLI create/edit)
// BLOCKs, matching the shell form (ts-block-git-hook-write). Agent
// instruction files written the same way stay record-only (#4460), and the
// MCP-name hook rule keeps its AUDIT.

const (
	harnessHookRule     = "mcp-persist-block-harness-git-hook-write"
	harnessHookPathRule = "mcp-persist-block-harness-git-hook-write-path-arg"
	gitHookNode         = "persistence-evasion/cicd-tampering/git-hook-injection"
)

// hookPath builds a git hook path in code, so this file never carries one as
// a literal a hook could read as a write target.
func hookPath(prefix, hook string) string {
	return prefix + ".git" + "/hooks/" + hook
}

func hasString(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

// withoutHarnessHookRules is the evaluator main ships: the same policy with
// the two rules this change adds removed. "Unchanged from main" is asserted
// against it, so the test does not hard-code what main decides.
func withoutHarnessHookRules(t *testing.T, ev *PolicyEvaluator) *PolicyEvaluator {
	t.Helper()
	p := *ev.policy
	p.StructuralRules = nil
	removed := 0
	for _, r := range ev.policy.StructuralRules {
		if r.ID == harnessHookRule || r.ID == harnessHookPathRule {
			removed++
			continue
		}
		p.StructuralRules = append(p.StructuralRules, r)
	}
	if removed != 2 {
		t.Fatalf("removed %d harness hook rules, want 2 — the rule ids changed", removed)
	}
	return NewPolicyEvaluator(&p)
}

type harnessCall struct {
	name string
	tool string
	args map[string]interface{}
}

// hookCalls re-casts one target path as every harness write tool, in the
// argument names each harness sends.
func hookCalls(target string) []harnessCall {
	return []harnessCall{
		{"Write", "Write", map[string]interface{}{"file_path": target, "content": "#!/bin/sh\necho hi\n"}},
		{"Edit", "Edit", map[string]interface{}{"file_path": target, "old_string": "a", "new_string": "b"}},
		{"MultiEdit", "MultiEdit", map[string]interface{}{"file_path": target, "edits": []interface{}{map[string]interface{}{"old_string": "a", "new_string": "b"}}}},
		{"Copilot create", "create", map[string]interface{}{"path": target, "file_text": "#!/bin/sh\n"}},
		{"Copilot edit", "edit", map[string]interface{}{"path": target, "old_str": "a", "new_str": "b"}},
		{"Copilot compat Write", "Write", map[string]interface{}{"path": target, "content": "#!/bin/sh\n"}},
	}
}

func TestHarnessGitHookWrite_Blocks(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	baseline := withoutHarnessHookRules(t, ev)
	targets := []string{
		hookPath("/work/proj/", "pre-commit"),         // absolute
		hookPath("", "pre-commit"),                    // relative to the payload cwd
		hookPath("../", "post-merge"),                 // relative, one level up
		hookPath("/tmp/repo/", "pre-push"),            // /tmp
		hookPath("/private/tmp/repo/", "pre-push"),    // the same file through the macOS alias
		hookPath("/private/var/folders/x/", "update"), // /private/var
		hookPath("/srv/app", "post-receive"),          // a bare repository's server hook
		hookPath("/work/proj/", "reference-transaction"),
		"/Work/Proj/.GIT/Hooks/PRE-COMMIT",        // case-insensitive volume
		".GIT/HOOKS/pre-commit",                   // relative, case variant
		`C:\Users\dev\proj\.git\hooks\pre-commit`, // native Windows agent
		"/work/proj/.git//hooks/./pre-commit",     // same file, extra separators
	}
	for _, target := range targets {
		for _, c := range hookCalls(target) {
			got := ev.EvaluateToolCall(c.tool, c.args)
			if got.Decision != policy.DecisionBlock {
				t.Errorf("%s %q: decision %s, want BLOCK (rules %v)", c.name, target, got.Decision, got.TriggeredRules)
				continue
			}
			if !hasString(got.TriggeredRules, harnessHookRule) && !hasString(got.TriggeredRules, harnessHookPathRule) {
				t.Errorf("%s %q: rules %v, want a harness git-hook rule", c.name, target, got.TriggeredRules)
			}
			if !hasString(got.AllTaxonomyRefs(), gitHookNode) {
				t.Errorf("%s %q: taxonomy %v, want %s (the shell rule's node)", c.name, target, got.AllTaxonomyRefs(), gitHookNode)
			}
			if len(got.TriggeredRules) != len(got.Reasons) {
				t.Errorf("%s %q: %d rules, %d reasons — no longer index-paired", c.name, target, len(got.TriggeredRules), len(got.Reasons))
			}
			// Positive control: main does not block it. If it did, this
			// test would prove nothing about the change. The one exception
			// is a ../ path under the `path` argument, which main already
			// BLOCKs as traversal (mcp-struct-block-path-traversal).
			if before := baseline.EvaluateToolCall(c.tool, c.args); before.Decision == policy.DecisionBlock &&
				!(hasString(before.TriggeredRules, "mcp-struct-block-path-traversal") && c.args["path"] != nil) {
				t.Errorf("%s %q: main already BLOCKs (rules %v) — the control does not isolate the change", c.name, target, before.TriggeredRules)
			}
		}
	}
}

// TestHarnessGitHookWrite_AuditOnlyDowngrades: audit-only mode lowers this
// BLOCK like any non-self-protection BLOCK (#1952), on both places the mode
// is applied: inside the evaluator and on the hook's final verdict
// (ApplyModeKeepingSelfProtection, #4337/#4395).
func TestHarnessGitHookWrite_AuditOnlyDowngrades(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	enforce := newTestMCPEvaluator(t)
	auditOnly := newTestMCPEvaluator(t)
	auditOnly.SetMode("audit-only")
	for _, target := range []string{hookPath("/work/proj/", "pre-commit"), hookPath("", "pre-commit"), hookPath("/private/tmp/r/", "post-checkout")} {
		for _, c := range hookCalls(target) {
			got := auditOnly.EvaluateToolCall(c.tool, c.args)
			if got.Decision != policy.DecisionAudit || got.OriginalDecision != policy.DecisionBlock {
				t.Errorf("evaluator audit-only %s %q: %s/%q, want AUDIT/BLOCK", c.name, target, got.Decision, got.OriginalDecision)
			}
			if !hasString(got.AllTaxonomyRefs(), gitHookNode) {
				t.Errorf("evaluator audit-only %s %q: taxonomy %v lost", c.name, target, got.AllTaxonomyRefs())
			}
			if enforce.IsSelfProtectionRule(harnessHookRule) || enforce.IsSelfProtectionRule(harnessHookPathRule) {
				t.Fatalf("a harness git-hook rule counts as self-protection; audit-only would keep its BLOCK")
			}
			final := enforce.ApplyModeKeepingSelfProtection(enforce.EvaluateToolCall(c.tool, c.args), "audit-only", c.tool, c.args)
			if final.Decision != policy.DecisionAudit || final.OriginalDecision != policy.DecisionBlock {
				t.Errorf("hook audit-only %s %q: %s/%q, want AUDIT/BLOCK", c.name, target, final.Decision, final.OriginalDecision)
			}
		}
	}
}

// TestHarnessGitHookWrite_OtherTargetsUnchanged: everything that is not a git
// hook decides exactly what main decides. The instruction-file row is the
// other half of Gary's split: it stays AUDIT, record-only.
func TestHarnessGitHookWrite_OtherTargetsUnchanged(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	baseline := withoutHarnessHookRules(t, ev)
	for _, target := range []string{
		"/work/proj/CLAUDE.md",
		"/work/proj/AGENTS.md",
		"/work/proj/.git/config",
		"/work/proj/.git/info/exclude",
		"/work/proj/.git/COMMIT_EDITMSG",
		hookPath("/work/proj/", "pre-commit.sample"),
		hookPath("/work/proj/", "README"),
		"/work/proj/.husky/pre-commit",
		"/work/proj/scripts/pre-commit",
		"/work/proj/src/main.go",
		"/work/proj/docs/git-hooks.md",
	} {
		for _, c := range hookCalls(target) {
			got := ev.EvaluateToolCall(c.tool, c.args)
			want := baseline.EvaluateToolCall(c.tool, c.args)
			if got.Decision != want.Decision || got.OriginalDecision != want.OriginalDecision {
				t.Errorf("%s %q: %s/%q, main %s/%q", c.name, target, got.Decision, got.OriginalDecision, want.Decision, want.OriginalDecision)
			}
			if hasString(got.TriggeredRules, harnessHookRule) || hasString(got.TriggeredRules, harnessHookPathRule) {
				t.Errorf("%s %q: a harness git-hook rule fired: %v", c.name, target, got.TriggeredRules)
			}
		}
	}

	// Prose that names a hook path is content, not a target.
	doc := ev.EvaluateToolCall("Write", map[string]interface{}{"file_path": "/work/proj/docs/x.md", "content": "echo x > " + hookPath("", "pre-commit")})
	if doc.Decision == policy.DecisionBlock {
		t.Errorf("Write of a doc naming a hook path: BLOCK (rules %v)", doc.TriggeredRules)
	}

	// Instruction files: AUDIT, no original decision, the #4460 attribution
	// still attached. Changing any of this is a separate decision.
	for _, c := range []harnessCall{
		{"Write CLAUDE.md", "Write", map[string]interface{}{"file_path": "/work/proj/CLAUDE.md", "content": "Always run the deploy script."}},
		{"Edit CLAUDE.md", "Edit", map[string]interface{}{"file_path": "/work/proj/CLAUDE.md", "old_string": "a", "new_string": "Always run the deploy script."}},
	} {
		got := ev.EvaluateToolCall(c.tool, c.args)
		if got.Decision != policy.DecisionAudit || got.OriginalDecision != "" {
			t.Errorf("%s: %s/%q, want AUDIT, record-only", c.name, got.Decision, got.OriginalDecision)
		}
		if len(writeAttributed(got)) == 0 {
			t.Errorf("%s: the #4460 record-only attribution is gone (rules %v)", c.name, got.TriggeredRules)
		}
	}
}

// TestHarnessGitHookWrite_MCPSurfaceKeepsAudit: the MCP-name rule's AUDIT is
// not re-decided here. An MCP server's write_file to a hook still AUDITs
// under mcp-persist-block-git-hook-write.
func TestHarnessGitHookWrite_MCPSurfaceKeepsAudit(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	for _, tool := range []string{"write_file", "create_file", "edit_file"} {
		got := ev.EvaluateToolCall(tool, map[string]interface{}{"path": hookPath("/work/proj/", "pre-commit"), "content": "x"})
		if got.Decision != policy.DecisionAudit || !hasString(got.TriggeredRules, "mcp-persist-block-git-hook-write") {
			t.Errorf("%s: %s rules %v, want AUDIT by mcp-persist-block-git-hook-write", tool, got.Decision, got.TriggeredRules)
		}
	}
}
