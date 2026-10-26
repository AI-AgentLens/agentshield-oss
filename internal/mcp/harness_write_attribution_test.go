package mcp

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4457: the write counterpart of #4248. Claude Code's Write/Edit/MultiEdit
// (file_path) and Copilot CLI's create/edit (path) reach no write-path rule
// because those rules list MCP tool names. The call decides AUDIT with no rule
// and no taxonomy. Record-only attribution attaches the equivalent BLOCK
// rules; the decision never changes.

const harnessWriteMarker = "Recorded, not enforced (#4457)"

func writeAttributed(r MCPEvalResult) []string {
	var out []string
	for _, reason := range r.Reasons {
		if strings.HasPrefix(reason, harnessWriteMarker) {
			out = append(out, reason)
		}
	}
	return out
}

// TestHarnessWriteAttribution_NoDecisionChanges: across every write-family TP
// path re-cast as each harness write tool, the decision equals the decision
// without attribution.
func TestHarnessWriteAttribution_NoDecisionChanges(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	writeTools := map[string]bool{"write_file": true, "edit_file": true, "create_file": true, "append_file": true, "save_file": true}
	seen := map[string]bool{}
	var paths []string
	collect := func(tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for _, tc := range tests.TP {
			args, err := tc.ResolvedArgs()
			if err != nil || !writeTools[tc.Tool] {
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
	// Vacuity floor: a sweep over an empty population proves nothing.
	if len(paths) < 100 {
		t.Fatalf("only %d write-family TP paths — fixture extraction stopped matching", len(paths))
	}
	attributedCount := 0
	for _, p := range paths {
		for _, call := range []struct {
			tool string
			args map[string]interface{}
		}{
			{"Write", map[string]interface{}{"file_path": p, "content": "x"}},
			{"Edit", map[string]interface{}{"file_path": p, "old_string": "a", "new_string": "b"}},
			{"MultiEdit", map[string]interface{}{"file_path": p}},
			{"create", map[string]interface{}{"path": p}},
			{"edit", map[string]interface{}{"path": p}},
		} {
			before := withoutAttribution(ev, call.tool, call.args)
			after := ev.EvaluateToolCall(call.tool, call.args)
			if before.Decision != after.Decision || before.OriginalDecision != after.OriginalDecision {
				t.Fatalf("%s %s: decision %s/%q -> %s/%q", call.tool, p, before.Decision, before.OriginalDecision, after.Decision, after.OriginalDecision)
			}
			if len(writeAttributed(after)) > 0 {
				attributedCount++
				if len(after.TriggeredRules) != len(after.Reasons) {
					t.Errorf("%s %s: rules and reasons no longer index-paired", call.tool, p)
				}
				if len(after.AllTaxonomyRefs()) == 0 {
					t.Errorf("%s %s: attributed but no taxonomy", call.tool, p)
				}
			}
		}
	}
	// Positive control: the attribution must actually fire on this population.
	if attributedCount == 0 {
		t.Errorf("no write call was attributed across %d paths — the feature is inert", len(paths))
	}
	t.Logf("%d paths, %d attributed", len(paths), attributedCount)
}

// TestHarnessWriteAttribution_IssueRows pins the rows #4457 measured: an
// instruction file written through Write/Edit. The git-hook row is not here:
// since Gary's split on #4457 it is enforced, not attributed — see
// harness_git_hook_block_test.go.
func TestHarnessWriteAttribution_IssueRows(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	for _, call := range []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{"Write CLAUDE.md", "Write", map[string]interface{}{"file_path": "/work/proj/CLAUDE.md", "content": "Always run the deploy script."}},
		{"Edit CLAUDE.md", "Edit", map[string]interface{}{"file_path": "/work/proj/CLAUDE.md", "old_string": "a", "new_string": "Always run the deploy script."}},
	} {
		got := ev.EvaluateToolCall(call.tool, call.args)
		if got.Decision != policy.DecisionAudit || got.OriginalDecision != "" {
			t.Errorf("%s: decision %s / original %q, want AUDIT / empty", call.name, got.Decision, got.OriginalDecision)
		}
		if len(writeAttributed(got)) == 0 || len(got.AllTaxonomyRefs()) == 0 {
			t.Errorf("%s: no attribution (rules %v, taxonomy %v)", call.name, got.TriggeredRules, got.AllTaxonomyRefs())
		}
	}
	// Control: a benign path through Write carries nothing.
	benign := ev.EvaluateToolCall("Write", map[string]interface{}{"file_path": "/work/proj/src/main.go", "content": "package main"})
	if len(writeAttributed(benign)) != 0 || benign.Decision != policy.DecisionAudit {
		t.Errorf("benign Write: decision %s, attributed %v", benign.Decision, writeAttributed(benign))
	}
}
