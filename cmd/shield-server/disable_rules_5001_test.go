package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5001 part A at the agentless surface: an id in the shell policy's
// disable_rules switches that rule off as a tool-call rule too. The server's
// shell engine applies the list with no managed-host check (loadShellEngine
// mirrors check.go, which has none), so its tool-call evaluator does the same:
// the managed row below pins both. Uses only symbols that exist on main, where
// every "listed" row fails.

const (
	srvTool      = "zz5001_probe"
	srvMeterTool = "zz5001_meter"
	srvBlock     = "zz5001-block-probe"
	srvAudit     = "zz5001-audit-probe"
	srvCap       = "zz5001-cap-units"
	srvShellRule = "zz5001-shell-block"
	srvShellCmd  = "zz5001-shell now"
)

var srvMCPRules = []struct{ id, yaml string }{
	{srvBlock, `  - id: zz5001-block-probe
    taxonomy: "zz5001/test/held-target"
    match:
      tool_name: zz5001_probe
      argument_patterns:
        target: "held-*"
    decision: BLOCK
    reason: "zz5001: a held target"
`},
	{srvAudit, `  - id: zz5001-audit-probe
    match:
      tool_name: zz5001_probe
    decision: AUDIT
    reason: "zz5001: every probe is recorded"
`},
}

// srvMCPPolicy writes the test's MCP policy without the rules named in without
// (the oracle: deleted rather than listed) and returns its path.
func srvMCPPolicy(t *testing.T, without ...string) string {
	t.Helper()
	skip := map[string]bool{}
	for _, id := range without {
		skip[id] = true
	}
	var b strings.Builder
	b.WriteString("defaults:\n  decision: \"AUDIT\"\nrules:\n")
	for _, r := range srvMCPRules {
		if !skip[r.id] {
			b.WriteString(r.yaml)
		}
	}
	if !skip[srvCap] {
		b.WriteString("value_limits:\n  - id: zz5001-cap-units\n    tool_pattern: zz5001_meter\n    argument: units\n    max: 10\n    decision: BLOCK\n    reason: \"zz5001: units over the cap\"\n")
	}
	p := filepath.Join(t.TempDir(), "mcp-policy.yaml")
	if err := os.WriteFile(p, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// srvShellPolicyYAML is a shell policy with one rule (the twin) and the list.
func srvShellPolicyYAML(t *testing.T, list []string) []byte {
	t.Helper()
	pol := map[string]interface{}{
		"version": "0.1",
		"rules": []map[string]interface{}{{
			"id":       srvShellRule,
			"match":    map[string]interface{}{"command_regex": `^zz5001-shell\b`},
			"decision": "BLOCK",
			"reason":   "zz5001: the shell twin",
		}},
	}
	if list != nil {
		pol["disable_rules"] = list
	}
	out, err := yaml.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// srvWith5001 is a server whose shell policy (--policy) lists list and whose
// MCP policy (--mcp-policy) is mcpPolicy.
func srvWith5001(t *testing.T, list []string, mcpPolicy string) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	shell := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(shell, srvShellPolicyYAML(t, list), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Options{Version: "test", PolicyPath: shell, MCPPolicyPath: mcpPolicy, LogPath: filepath.Join(dir, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// srvVerdict is the part of a response a decision and its receipt are made of.
type srvVerdict struct {
	Decision, Original string
	Rules, Reasons     []string
	Taxonomy           []string
}

func srvEval(t *testing.T, ts *httptest.Server, req evaluateRequest) (srvVerdict, evaluateResponse) {
	t.Helper()
	code, resp := postEval(t, ts, req)
	if code != 200 {
		t.Fatalf("status %d for %+v", code, req)
	}
	return srvVerdict{resp.Decision, resp.OriginalDecision, resp.Rules, resp.Reasons, resp.Taxonomy}, resp
}

func probeReq() evaluateRequest {
	return evaluateRequest{ToolName: srvTool, Arguments: map[string]interface{}{"target": "held-1"}}
}

func meterReq() evaluateRequest {
	return evaluateRequest{ToolName: srvMeterTool, Arguments: map[string]interface{}{"units": 50}}
}

func TestEvaluateDisableRules5001(t *testing.T) {
	full := srvMCPPolicy(t)
	base := srvWith5001(t, nil, full)
	if v, _ := srvEval(t, base, probeReq()); v.Decision != "BLOCK" || !contains(v.Rules, srvBlock) {
		t.Fatalf("setup, no list: %+v; want BLOCK by %s", v, srvBlock)
	}
	if v, _ := srvEval(t, base, meterReq()); v.Decision != "BLOCK" || !contains(v.Rules, srvCap) {
		t.Fatalf("setup, value limit: %+v; want BLOCK by %s", v, srvCap)
	}
	if v, _ := srvEval(t, base, evaluateRequest{Command: srvShellCmd}); v.Decision != "BLOCK" || !contains(v.Rules, srvShellRule) {
		t.Fatalf("setup, shell twin: %+v; want BLOCK by %s", v, srvShellRule)
	}

	listed := srvWith5001(t, []string{srvBlock, srvCap, srvShellRule}, full)
	deleted := srvWith5001(t, nil, srvMCPPolicy(t, srvBlock))
	got, _ := srvEval(t, listed, probeReq())
	want, _ := srvEval(t, deleted, probeReq())
	if got.Decision != "AUDIT" || contains(got.Rules, srvBlock) || !contains(got.Rules, srvAudit) || !reflect.DeepEqual(got, want) {
		t.Errorf("listed rule: %+v; want the deleted rule's %+v", got, want)
	}
	if v, _ := srvEval(t, listed, meterReq()); v.Decision == "BLOCK" || contains(v.Rules, srvCap) || contains(v.Rules, "value-limit") {
		t.Errorf("listed value limit: %+v; want it switched off", v)
	}
	if v, _ := srvEval(t, listed, evaluateRequest{Command: srvShellCmd}); contains(v.Rules, srvShellRule) {
		t.Errorf("shell twin listed: %+v; want it switched off", v)
	}

	// The unlisted rule on the same call is unchanged.
	if v, _ := srvEval(t, srvWith5001(t, []string{srvAudit}, full), probeReq()); v.Decision != "BLOCK" || !contains(v.Rules, srvBlock) {
		t.Errorf("neighbour listed: %+v; want %s's BLOCK unchanged", v, srvBlock)
	}

	// Lookalikes and unknown ids decide exactly as no list.
	lookalikes := []string{"zz5001-block", srvBlock + "-x", strings.ToUpper(srvBlock), srvBlock + " ", "", "zz5001-no-such-rule", "*"}
	noList, _ := srvEval(t, base, probeReq())
	if v, _ := srvEval(t, srvWith5001(t, lookalikes, full), probeReq()); !reflect.DeepEqual(v, noList) {
		t.Errorf("lookalike ids: %+v; want no list's %+v", v, noList)
	}
}

// The hint in a tool-call BLOCK's response names the rule, and following it
// (the id in the shell policy's disable_rules, which is what `agentshield rule
// disable` writes) switches the rule off on this surface.
func TestEvaluateDisableRules5001_HintIsTrue(t *testing.T) {
	full := srvMCPPolicy(t)
	_, resp := srvEval(t, srvWith5001(t, nil, full), probeReq())
	if !strings.Contains(resp.Remediation, srvBlock) {
		t.Fatalf("remediation %q does not name %s", resp.Remediation, srvBlock)
	}
	m := regexp.MustCompile(`agentshield rule disable (\S+)`).FindStringSubmatch(resp.Remediation)
	if m == nil {
		// The account's real home is managed, so the hint says to ask the
		// administrator instead; there is no local command to follow.
		t.Skipf("this host reads as managed (hint %q)", resp.Remediation)
	}
	if v, _ := srvEval(t, srvWith5001(t, []string{m[1]}, full), probeReq()); v.Decision == "BLOCK" || contains(v.Rules, srvBlock) {
		t.Errorf("after listing %s: %+v; want it switched off", m[1], v)
	}
}

// A managed host: the server's shell engine still reads the local list (no
// managed check in loadShellEngine), so its tool-call evaluator reads it too.
// Both are pinned; a change to either side has to change both.
func TestEvaluateDisableRules5001_ManagedHostMirrorsTheServersShell(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), srvShellPolicyYAML(t, []string{srvBlock, srvShellRule}), 0o600); err != nil {
		t.Fatal(err)
	}
	testhome.Set(t, home)
	srv, err := NewServer(Options{Version: "test", MCPPolicyPath: srvMCPPolicy(t), LogPath: filepath.Join(home, "audit.jsonl"), Mode: "enforce"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	if v, _ := srvEval(t, ts, evaluateRequest{Command: srvShellCmd}); contains(v.Rules, srvShellRule) {
		t.Fatalf("shell twin on a managed host: %+v; the server's shell engine stopped reading the local list, so this row must change with it", v)
	}
	if v, _ := srvEval(t, ts, probeReq()); v.Decision == "BLOCK" || contains(v.Rules, srvBlock) {
		t.Errorf("tool call on a managed host: %+v; want %s switched off, as the server's shell side switches its twin off", v, srvBlock)
	}
}
