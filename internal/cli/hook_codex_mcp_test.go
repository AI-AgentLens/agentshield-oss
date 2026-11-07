package cli

import (
	"encoding/json"
	"testing"
)

// codexMCPPayload is the PreToolUse payload Codex sends for an MCP tool call:
// Claude Code's shape plus turn_id, with tool_name mcp__<server>__<tool> and
// the tool's arguments as tool_input (codex-rs/core/src/tools/handlers/mcp.rs).
func codexMCPPayload(t *testing.T, tool string, args map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"session_id":      "codex-mcp",
		"turn_id":         "turn-1",
		"transcript_path": "/tmp/t.jsonl",
		"cwd":             "/tmp",
		"hook_event_name": "PreToolUse",
		"tool_name":       tool,
		"tool_input":      args,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The hook the MCP group runs must stop a Codex MCP call the MCP policy
// blocks, and record it as Codex's.
func TestHook_CodexMCPCallBlockedAndLabelled(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	payload := codexMCPPayload(t, "mcp__fs__read_file", map[string]interface{}{"path": "/home/user/" + ".vault-token"})

	code, _, stderr := runHookChild(t, home, payload)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (BLOCK). stderr:\n%s", code, stderr)
	}
	ev := lastAuditEvent(t, home)
	if ev["decision"] != "BLOCK" || ev["source"] != "codex-mcp-hook" {
		t.Errorf("recorded decision %v source %v, want BLOCK from codex-mcp-hook", ev["decision"], ev["source"])
	}
}

func TestHook_CodexMCPBenignCallAllowedAndLabelled(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	code, _, stderr := runHookChild(t, home, codexMCPPayload(t, "mcp__open_brain__stats", map[string]interface{}{}))
	if code != 0 {
		t.Fatalf("exit %d, want 0. stderr:\n%s", code, stderr)
	}
	if ev := lastAuditEvent(t, home); ev["source"] != "codex-mcp-hook" {
		t.Errorf("source %v, want codex-mcp-hook", ev["source"])
	}
}
