package mcp

import (
	"encoding/base64"
	"testing"

	"gopkg.in/yaml.v3"
)

// b64 is a test helper: base64 of a raw JSON args string, as `encode-fixture`
// would emit. Kept benign (a plain /etc path) so this test file never carries
// attack phrasing — the mechanism it proves is payload-agnostic.
func b64(jsonArgs string) string {
	return base64.StdEncoding.EncodeToString([]byte(jsonArgs))
}

func TestResolvedArgs_InlinePassthrough(t *testing.T) {
	tc := MCPTestCase{Tool: "write_file", Args: map[string]interface{}{"path": "/etc/hosts"}}
	got, err := tc.ResolvedArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["path"] != "/etc/hosts" {
		t.Errorf("inline args not passed through: got %v", got)
	}
}

func TestResolvedArgs_EmptyIsNeverNil(t *testing.T) {
	got, err := MCPTestCase{Tool: "list_dir"}.ResolvedArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == nil {
		t.Fatal("ResolvedArgs must never return a nil map")
	}
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestResolvedArgs_Base64Decode(t *testing.T) {
	tc := MCPTestCase{Tool: "write_file", ArgsB64: b64(`{"path":"/etc/shadow","content":"x"}`)}
	got, err := tc.ResolvedArgs()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["path"] != "/etc/shadow" || got["content"] != "x" {
		t.Errorf("decoded args wrong: got %v", got)
	}
}

func TestResolvedArgs_BothSetIsError(t *testing.T) {
	tc := MCPTestCase{
		Tool:    "write_file",
		Args:    map[string]interface{}{"path": "/etc/hosts"},
		ArgsB64: b64(`{"path":"/etc/shadow"}`),
	}
	if _, err := tc.ResolvedArgs(); err == nil {
		t.Fatal("expected error when both args and args_b64 are set")
	}
}

func TestResolvedArgs_BadBase64IsError(t *testing.T) {
	tc := MCPTestCase{Tool: "write_file", ArgsB64: "not!!valid!!base64"}
	if _, err := tc.ResolvedArgs(); err == nil {
		t.Fatal("expected error on invalid base64")
	}
}

func TestResolvedArgs_NonObjectJSONIsError(t *testing.T) {
	// A JSON array is valid JSON but not an args object → must error, not panic.
	tc := MCPTestCase{Tool: "write_file", ArgsB64: b64(`[1,2,3]`)}
	if _, err := tc.ResolvedArgs(); err == nil {
		t.Fatal("expected error when decoded blob is not a JSON object")
	}
}

// TestFixtureIndirection_EndToEnd proves the full path a rule author exercises:
// YAML pack → Unmarshal → ResolvedArgs → matchRule, and that the args_b64 form
// is behaviorally identical to the inline form for the same payload.
func TestFixtureIndirection_EndToEnd(t *testing.T) {
	const pack = `
name: test-fixture-indirection
version: "1.0.0"
rules:
  - id: fi-etc-write-inline
    match:
      tool_name_any: ["write_file"]
      argument_patterns:
        path: "/etc/**"
    decision: BLOCK
    reason: test
  - id: fi-etc-write-b64
    match:
      tool_name_any: ["write_file"]
      argument_patterns:
        path: "/etc/**"
    decision: BLOCK
    reason: test
`
	var p MCPPolicy
	if err := yaml.Unmarshal([]byte(pack), &p); err != nil {
		t.Fatalf("unmarshal pack: %v", err)
	}
	if len(p.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(p.Rules))
	}

	evaluator := &PolicyEvaluator{}
	inlineArgs := map[string]interface{}{"path": "/etc/shadow"}

	// Inline form fires.
	if !evaluator.matchRule("write_file", inlineArgs, p.Rules[0]) {
		t.Fatal("inline TP should fire the BLOCK rule")
	}

	// args_b64 form decodes to the same args and fires identically.
	tc := MCPTestCase{Tool: "write_file", ArgsB64: b64(`{"path":"/etc/shadow"}`)}
	decoded, err := tc.ResolvedArgs()
	if err != nil {
		t.Fatalf("ResolvedArgs: %v", err)
	}
	if !evaluator.matchRule(tc.Tool, decoded, p.Rules[1]) {
		t.Fatal("args_b64 TP should fire the BLOCK rule identically to inline")
	}

	// Parity: a benign path must NOT fire in either form.
	benign := map[string]interface{}{"path": "/workspace/README.md"}
	if evaluator.matchRule("write_file", benign, p.Rules[0]) {
		t.Error("benign path should not fire (inline)")
	}
	benignTC := MCPTestCase{Tool: "write_file", ArgsB64: b64(`{"path":"/workspace/README.md"}`)}
	benignDecoded, err := benignTC.ResolvedArgs()
	if err != nil {
		t.Fatalf("ResolvedArgs benign: %v", err)
	}
	if evaluator.matchRule("write_file", benignDecoded, p.Rules[1]) {
		t.Error("benign path should not fire (args_b64)")
	}
}
