package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Regression tests for the nested object-array batch bypass (issue #3156),
// the sibling gap #3155 left open: a batch tool whose array holds OBJECTS
// (e.g. {"path": "...", "content": "..."}) under a CONTAINER KEY NAME with no
// naming relationship to the field itself ("entries", "operations",
// "requests" — as opposed to the covered "paths" plural-of-"path"). Before
// this fix, {"entries": [{"path": "/home/user/.ssh/id_rsa"}]} silently
// dropped from BLOCK to AUDIT — the exact same credential-theft target as
// {"path": "/home/user/.ssh/id_rsa"}, just wrapped one level deeper under an
// arbitrary container name. Covers both match engines: flat ArgumentPatterns
// (policy.go) and structural args_match (structural.go).

func TestNestedArrayObjectBypass_FlatArgumentPatterns(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy()) // "block-ssh-read": path glob on read_file/cat_file

	tests := []struct {
		name   string
		args   map[string]interface{}
		expect policy.Decision
	}{
		{
			name:   "arbitrary container name wrapping objects — the bypass, must now block",
			args:   map[string]interface{}{"entries": []interface{}{map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "another arbitrary container name — operations",
			args:   map[string]interface{}{"operations": []interface{}{map[string]interface{}{"path": "/home/user/.ssh/id_rsa", "content": "x"}}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "sensitive target buried among benign objects in the array",
			args:   map[string]interface{}{"requests": []interface{}{map[string]interface{}{"path": "/workspace/README.md"}, map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "arbitrary container, all benign objects — must NOT block",
			args:   map[string]interface{}{"entries": []interface{}{map[string]interface{}{"path": "/workspace/README.md"}, map[string]interface{}{"path": "/workspace/src/main.go"}}},
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

func TestNestedArrayObjectBypass_StructuralArgsMatch(t *testing.T) {
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
			name:   "arbitrary container name wrapping objects — the bypass",
			tool:   "read_file",
			args:   map[string]interface{}{"entries": []interface{}{map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}}},
			expect: true,
		},
		{
			name:   "uncovered tool name + nested object array — worst case, still caught by tool_name_regex: \".*\"",
			tool:   "batch_get_files",
			args:   map[string]interface{}{"items": []interface{}{map[string]interface{}{"path": "/home/user/.ssh/id_rsa"}}},
			expect: true,
		},
		{
			name:   "arbitrary container, benign object — must NOT match",
			tool:   "read_file",
			args:   map[string]interface{}{"entries": []interface{}{map[string]interface{}{"path": "/workspace/README.md"}}},
			expect: false,
		},
		{
			name:   "array of plain strings (not objects) under an arbitrary name — no nested field to find, must NOT match",
			tool:   "read_file",
			args:   map[string]interface{}{"entries": []interface{}{"/workspace/README.md"}},
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

// Guards against a plausible false positive: an unrelated array-of-objects
// argument that happens to reuse a common key name ("path") for a
// different, non-filesystem concept (e.g. a REST route in an API log tool)
// must not be conflated with a filesystem credential path just because the
// key name matches. The regex/glob pattern itself is what saves us here —
// this test documents that the resolution mechanism finding the value is not
// itself sufficient to cause a false BLOCK; the value must still match.
func TestNestedArrayObjectBypass_UnrelatedKeyReuseDoesNotFalselyBlock(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	args := map[string]interface{}{
		"log_entries": []interface{}{
			map[string]interface{}{"path": "/api/v1/users", "status": 200},
		},
	}
	result := e.EvaluateToolCall("read_file", args)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("REST route reusing the 'path' key must not trigger a credential-path BLOCK: got %v (rules=%v)", result.Decision, result.TriggeredRules)
	}
}
