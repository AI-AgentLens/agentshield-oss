package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Regression tests for the batch/array-argument bypass (issue #3155): every
// path/URL-matching MCP rule in the corpus is authored against a singular
// scalar argument ("path", holding one string). A batch/bulk tool call
// exposes the identical operation over several targets under a PLURAL ARRAY
// argument instead ("paths": [...]) — before the fix, this silently defeated
// every rule keyed on the singular name, dropping the decision for the exact
// same credential-theft target from BLOCK to AUDIT. Covers both match
// engines that key off arguments: flat ArgumentPatterns (policy.go, used by
// community mcp-secrets.yaml) and structural args_match (structural.go, used
// by mcp-struct-block-credential-path-access).

func TestBatchArgumentBypass_FlatArgumentPatterns(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy()) // "block-ssh-read": path glob on read_file/cat_file

	tests := []struct {
		name   string
		args   map[string]interface{}
		expect policy.Decision
	}{
		{
			name:   "singular path — baseline still blocks",
			args:   map[string]interface{}{"path": "/home/user/.ssh/id_rsa"},
			expect: policy.DecisionBlock,
		},
		{
			name:   "plural array key — the bypass, must now block",
			args:   map[string]interface{}{"paths": []interface{}{"/home/user/.ssh/id_rsa"}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "singular key holding an array value — must now block",
			args:   map[string]interface{}{"path": []interface{}{"/home/user/.ssh/id_rsa"}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "plural array with the sensitive target buried among benign ones",
			args:   map[string]interface{}{"paths": []interface{}{"/workspace/README.md", "/home/user/.ssh/id_rsa"}},
			expect: policy.DecisionBlock,
		},
		{
			name:   "plural array, all benign — must NOT block",
			args:   map[string]interface{}{"paths": []interface{}{"/workspace/README.md", "/workspace/src/main.go"}},
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

func TestBatchArgumentBypass_StructuralArgsMatch(t *testing.T) {
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
			name:   "singular path — baseline",
			tool:   "read_file",
			args:   map[string]interface{}{"path": "/home/user/.ssh/id_rsa"},
			expect: true,
		},
		{
			name:   "plural array key — the bypass",
			tool:   "read_file",
			args:   map[string]interface{}{"paths": []interface{}{"/home/user/.ssh/id_rsa"}},
			expect: true,
		},
		{
			name:   "uncovered tool name + plural array — worst case, still caught by tool_name_regex: \".*\"",
			tool:   "get_files",
			args:   map[string]interface{}{"paths": []interface{}{"/home/user/.ssh/id_rsa"}},
			expect: true,
		},
		{
			name:   "plural array, all benign — must NOT match",
			tool:   "read_file",
			args:   map[string]interface{}{"paths": []interface{}{"/workspace/README.md"}},
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

// Guards the additive design of resolveFieldValues (#3155): some existing
// rules deliberately match against the WHOLE array (an aggregate property
// like "3+ recipients", or a pattern spanning two elements of the same
// array), not any single element in isolation. Per-element expansion must
// never replace that aggregate candidate, only add to it.
func TestBatchArgumentBypass_AggregateMatchingStillWorks(t *testing.T) {
	// Mirrors mcp-excessive-agency-bulk-email-send-audit: fires on 3+ email
	// addresses in the "to" argument, a property no single element carries.
	rule := MCPStructuralMatch{
		ToolNameAny: []string{"send_email"},
		ArgsMatch: map[string]ArgFieldMatch{
			"to": {
				PatternAny: []string{`@.*@.*@`}, // crude "3+ email addresses" stand-in, same shape as the real rule
			},
		},
	}

	bulk := map[string]interface{}{
		"to": []interface{}{"alice@corp.com", "bob@corp.com", "charlie@corp.com"},
	}
	if !matchStructural("send_email", bulk, rule) {
		t.Error("bulk recipient list must still match the aggregate 3+-address pattern")
	}

	single := map[string]interface{}{
		"to": []interface{}{"alice@corp.com"},
	}
	if matchStructural("send_email", single, rule) {
		t.Error("single recipient must not match the 3+-address pattern")
	}
}

// Regression tests for issue #3312 — the SCALAR half of the plural-key bypass.
//
// #3155 (above) taught resolveFieldValues to look up `fieldName+"s"`, but only
// accepted the plural value when it was a JSON array. A tool declaring `paths`
// as `string | string[]` and passed a single string therefore fell straight
// through, and Shield emitted AUDIT for a call that read an SSH private key —
// a record affirmatively attesting "no violation" for an action its own rules
// say to block. That falsifies the attestation rather than merely missing a
// detection, which is why this is enforcement integrity and not coverage.
//
// #3312 reported this as "the plural key bypasses every credential-path rule"
// and prescribed adding seven plural keys to the premium alt-path pack. The
// prescription rested on a repro run through `mcp-eval --arg`, which stores
// values as plain strings and never parses JSON — so `--arg 'paths=["..."]'`
// exercised a string that merely looked like an array. TestPluralArgumentKey_
// ArrayShapeWasAlreadyCovered pins the half that already worked, so nobody
// re-derives the wrong diagnosis from the issue text.
func TestPluralArgumentKey_ScalarValue(t *testing.T) {
	rule := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ArgsMatch: map[string]ArgFieldMatch{
			"path": {PatternAny: []string{`\.ssh/.*`, `\.ssh/?$`}},
		},
	}

	tests := []struct {
		name   string
		args   map[string]interface{}
		expect bool
	}{
		{
			name:   "plural key holding a bare string — the #3312 gap",
			args:   map[string]interface{}{"paths": "/home/user/.ssh/id_rsa"},
			expect: true,
		},
		{
			name:   "plural key, bare string, benign — must NOT match",
			args:   map[string]interface{}{"paths": "/workspace/README.md"},
			expect: false,
		},
		{
			name:   "plural key holding a single-element array — covered before #3312, must stay covered",
			args:   map[string]interface{}{"paths": []interface{}{"/home/user/.ssh/id_rsa"}},
			expect: true,
		},
		{
			name:   "singular key, bare string — the baseline that always worked",
			args:   map[string]interface{}{"path": "/home/user/.ssh/id_rsa"},
			expect: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchStructural("read_files", tc.args, rule); got != tc.expect {
				t.Errorf("args=%v: expected match=%v, got %v", tc.args, tc.expect, got)
			}
		})
	}
}

// The premium alt-key pack keys on `file`, `filepath`, `src`, `source`,
// `location`, `target`, `filename`. Fixing this in resolveFieldValues rather
// than in the pack means every one of those gains its plural for free — which
// is the argument for the one-line engine fix over ~500 lines of duplicated
// pattern lists that would have covered exactly seven keys and helped no other
// structural rule.
func TestPluralArgumentKey_AppliesToEveryAltKey(t *testing.T) {
	for _, key := range []string{"file", "filepath", "filename", "src", "source", "location", "target"} {
		t.Run(key+" -> "+key+"s", func(t *testing.T) {
			rule := MCPStructuralMatch{
				ToolNameRegex: ".*",
				ArgsMatch: map[string]ArgFieldMatch{
					key: {PatternAny: []string{`\.aws/credentials`}},
				},
			}
			args := map[string]interface{}{key + "s": "/home/user/.aws/credentials"}
			if !matchStructural("batch_read", args, rule) {
				t.Errorf("plural of %q did not match a credential path: %v", key, args)
			}
		})
	}
}

// A plural key must not become a wildcard. The fallback resolves exactly
// fieldName+"s" — not any key sharing a prefix — or a rule on `path` would
// start matching unrelated arguments like `pathspec` or `path_filter`.
func TestPluralArgumentKey_DoesNotMatchUnrelatedPrefixedKeys(t *testing.T) {
	rule := MCPStructuralMatch{
		ToolNameRegex: ".*",
		ArgsMatch: map[string]ArgFieldMatch{
			"path": {PatternAny: []string{`\.ssh/.*`}},
		},
	}
	for _, key := range []string{"pathspec", "path_filter", "pathological", "spath"} {
		t.Run(key, func(t *testing.T) {
			args := map[string]interface{}{key: "/home/user/.ssh/id_rsa"}
			if matchStructural("read_files", args, rule) {
				t.Errorf("key %q must not be treated as the plural of \"path\"", key)
			}
		})
	}
}
