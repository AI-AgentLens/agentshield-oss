package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Regression tests for the nested single-object envelope bypass (issue
// #3177), the singular sibling gap #3156 left open: a REST-style tool whose
// argument is wrapped in a single OBJECT (e.g. {"path": "...", "content":
// "..."}) under a CONTAINER KEY NAME with no naming relationship to the
// field itself ("request", "input", "data", "body" — as opposed to the
// covered "paths" plural-of-"path" and the array-of-objects "entries" case).
// Before this fix, {"request": {"path": "/home/user/.ssh/id_rsa"}} silently
// dropped from BLOCK to AUDIT — the exact same credential-theft target as
// {"path": "/home/user/.ssh/id_rsa"}, just wrapped one level deeper under an
// arbitrary singular container name. Covers both match engines: flat
// ArgumentPatterns (policy.go) and structural args_match (structural.go).

func TestNestedObjectBypass_FlatArgumentPatterns(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy()) // "block-ssh-read": path glob on read_file/cat_file

	tests := []struct {
		name   string
		args   map[string]interface{}
		expect policy.Decision
	}{
		{
			name:   "arbitrary container name wrapping a single object — the bypass, must now block",
			args:   map[string]interface{}{"request": map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "another arbitrary container name — input",
			args:   map[string]interface{}{"input": map[string]interface{}{"path": "/home/user/.ssh/id_rsa", "encoding": "utf-8"}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "arbitrary container, benign object — must NOT block",
			args:   map[string]interface{}{"request": map[string]interface{}{"path": "/workspace/README.md"}},
			expect: policy.DecisionAudit,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := e.EvaluateToolCall("read_file", tc.args)
			if result.Decision != tc.expect {
				t.Errorf("args=%v: expected %v, got %v (rules=%v)", tc.args, tc.expect, result.Decision, result.TriggeredRules)
			}
		})
	}
}

func TestNestedObjectBypass_StructuralArgsMatch(t *testing.T) {
	rule := MCPStructuralMatch{
		ToolNameRegex: ".*", // mirrors mcp-struct-block-credential-path-access's tool-agnostic scope
		ArgsMatch: map[string]ArgFieldMatch{
			"path": {
				PatternAny: []string{`\.ssh/.*`, `\.ssh/?$`},
			},
		},
	}

	tests := []struct {
		name   string
		tool   string
		args   map[string]interface{}
		expect bool
	}{
		{
			name:   "arbitrary container name wrapping a single object — the bypass",
			tool:   "read_file",
			args:   map[string]interface{}{"request": map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}},
			expect: true,
		},
		{
			name:   "uncovered tool name + nested object — worst case, still caught by tool_name_regex: \".*\"",
			tool:   "fetch_resource",
			args:   map[string]interface{}{"body": map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}},
			expect: true,
		},
		{
			name:   "arbitrary container, benign object — must NOT match",
			tool:   "read_file",
			args:   map[string]interface{}{"request": map[string]interface{}{"path": "/workspace/README.md"}},
			expect: false,
		},
		{
			name:   "nested object with no matching field name at all — must NOT match",
			tool:   "read_file",
			args:   map[string]interface{}{"request": map[string]interface{}{"filename": "/home/user/.ssh/id_rsa"}},
			expect: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchStructural(tc.tool, tc.args, rule)
			if got != tc.expect {
				t.Errorf("tool=%q args=%v: expected match=%v, got %v", tc.tool, tc.args, tc.expect, got)
			}
		})
	}
}

// Guards against a plausible false positive: an unrelated nested-object
// argument that happens to reuse a common key name ("path") for a
// different, non-filesystem concept (e.g. a REST route in an API log tool)
// must not be conflated with a filesystem credential path just because the
// key name matches. The regex/glob pattern itself is what saves us here —
// this test documents that the resolution mechanism finding the value is not
// itself sufficient to cause a false BLOCK; the value must still match.
func TestNestedObjectBypass_UnrelatedKeyReuseDoesNotFalselyBlock(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	args := map[string]interface{}{
		"log_entry": map[string]interface{}{"path": "/api/v1/users", "status": 200},
	}
	result := e.EvaluateToolCall("read_file", args)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("REST route reusing the 'path' key must not trigger a credential-path BLOCK: got %v (rules=%v)", result.Decision, result.TriggeredRules)
	}
}

// Guards the additive-not-replacing claim: form 3 (array of objects) and
// form 4 (single object) must both keep working when arguments legitimately
// contain a mix of both shapes.
func TestNestedObjectBypass_CoexistsWithArrayForm(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	args := map[string]interface{}{
		"metadata": map[string]interface{}{"source": "cli"},
		"entries":  []interface{}{map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}},
	}
	result := e.EvaluateToolCall("read_file", args)
	if result.Decision != policy.DecisionBlock {
		t.Errorf("array-of-objects form must still block alongside an unrelated nested object: got %v (rules=%v)", result.Decision, result.TriggeredRules)
	}
}
