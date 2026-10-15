package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// #4351 parity. Claude Code names an MCP server's tool mcp__<server>__<tool>,
// and the pack rules are authored against the bare <tool>. The hook evaluates
// both readings. shield-server is what the enterprise gateway calls for every
// non-shell tool, so it must too: otherwise a call the hook blocks reaches the
// gateway's agent as AUDIT, with no rule on the record.

func TestEvaluateMCPNamespacedToolNameMatchesBareRules(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	args := map[string]interface{}{"path": credentialPath()}

	_, bare := postEval(t, ts, evaluateRequest{ToolName: "read_file", Arguments: args})
	if bare.Decision != "BLOCK" || len(bare.Rules) == 0 {
		t.Fatalf("control: bare read_file = %q (rules %v), want BLOCK with a rule", bare.Decision, bare.Rules)
	}
	for _, tool := range []string{"mcp__fs__read_file", "mcp__my_srv__read_file"} {
		code, wire := postEval(t, ts, evaluateRequest{ToolName: tool, Arguments: args})
		if code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200", tool, code)
		}
		if wire.Decision != "BLOCK" {
			t.Errorf("%s: decision = %q (rules %v), want BLOCK like the bare name", tool, wire.Decision, wire.Rules)
		}
		if !reflect.DeepEqual(wire.Rules, bare.Rules) {
			t.Errorf("%s: rules = %v, want the bare name's %v", tool, wire.Rules, bare.Rules)
		}
	}
}

func TestEvaluateMCPNamespacedBenignStaysUnblocked(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	_, resp := postEval(t, ts, evaluateRequest{
		ToolName:  "mcp__fs__read_file",
		Arguments: map[string]interface{}{"path": "/workspace/project/README.md"},
	})
	if resp.Decision == "BLOCK" {
		t.Fatalf("benign namespaced read_file was BLOCKed (rules: %v, reasons: %v)", resp.Rules, resp.Reasons)
	}
}

// Gateway observe mode runs shield-server in audit-only. The would-be block
// must still be on the record, with its rule, or observe mode shows nothing.
func TestEvaluateMCPNamespacedRecordedUnderAuditOnly(t *testing.T) {
	srv, err := NewServer(Options{Version: "test", Mode: "audit-only"})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	args := map[string]interface{}{"path": credentialPath()}

	_, bare := postEval(t, ts, evaluateRequest{ToolName: "read_file", Arguments: args})
	if bare.Decision != "AUDIT" || bare.OriginalDecision != "BLOCK" {
		t.Fatalf("control: bare read_file = %q/%q, want AUDIT/BLOCK", bare.Decision, bare.OriginalDecision)
	}
	_, wire := postEval(t, ts, evaluateRequest{ToolName: "mcp__fs__read_file", Arguments: args})
	if wire.Decision != "AUDIT" || wire.OriginalDecision != "BLOCK" || !reflect.DeepEqual(wire.Rules, bare.Rules) {
		t.Fatalf("namespaced read_file = %q/%q rules %v, want AUDIT/BLOCK with %v",
			wire.Decision, wire.OriginalDecision, wire.Rules, bare.Rules)
	}
}
