package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

// TestEvaluateRoutingCharacterization pins how /v1/evaluate routes a request
// that carries no route key (ADR-001 step 0, #4245): a command-only request
// takes the shell pipeline, and a tool_name request takes MCP policy, whatever
// the tool is called and whatever its arguments carry. Both fields, or
// neither, is a 400.
//
// Each input decides differently on the two paths, so a request that changed
// path changes its decision: `rm -rf /` BLOCKs on the shell pipeline and
// decides AUDIT as a PowerShell tool's argument; `ls -la` ALLOWs on the shell
// pipeline, and a tool named Bash BLOCKs under MCP policy on its name alone
// (mcp-sem-block-code-execute). Step 2 routes a request that carries the key
// through the table (routing_test.go); without the key this is the
// version-skew path, and a change here is a regression
// (TestVersionSkew_UnkeyedRequestDecidesAsMain holds it to main's code).
func TestEvaluateRoutingCharacterization(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	rows := []struct {
		name     string
		req      evaluateRequest
		decision string
		rule     string // a rule id the verdict must carry; "" asserts none in particular
	}{
		{"command only, destructive: shell pipeline",
			evaluateRequest{Command: destructiveCommand()}, "BLOCK", "ts-block-rm-root"},
		{"command only, benign: shell pipeline",
			evaluateRequest{Command: "ls -la"}, "ALLOW", "ts-allow-readonly"},
		{"tool PowerShell carrying a destructive command: MCP policy",
			evaluateRequest{ToolName: "PowerShell", Arguments: map[string]interface{}{"command": destructiveCommand()}}, "AUDIT", ""},
		{"tool Bash carrying a benign command: MCP policy",
			evaluateRequest{ToolName: "Bash", Arguments: map[string]interface{}{"command": "ls -la"}}, "BLOCK", "mcp-sem-block-code-execute"},
		{"tool mcp__srv__tool carrying a destructive command: MCP policy",
			evaluateRequest{ToolName: "mcp__srv__tool", Arguments: map[string]interface{}{"command": destructiveCommand()}}, "AUDIT", ""},
	}
	for _, r := range rows {
		code, resp := postEval(t, ts, r.req)
		if code != http.StatusOK {
			t.Errorf("%s: status %d, want 200", r.name, code)
			continue
		}
		if resp.Decision != r.decision {
			t.Errorf("%s: decision %q, want %q (rules %v)", r.name, resp.Decision, r.decision, resp.Rules)
		}
		if r.rule != "" && !slices.Contains(resp.Rules, r.rule) {
			t.Errorf("%s: rules %v lack %q", r.name, resp.Rules, r.rule)
		}
	}

	// Both fields, even a tool named Bash with the same command: refused,
	// never guessed. Neither field: refused.
	for name, req := range map[string]evaluateRequest{
		"command and tool_name Bash": {Command: "ls -la", ToolName: "Bash", Arguments: map[string]interface{}{"command": "ls -la"}},
		"neither":                    {Cwd: "/repo", Arguments: map[string]interface{}{"command": "ls -la"}},
	} {
		if code, _ := postEval(t, ts, req); code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, code)
		}
	}
}
