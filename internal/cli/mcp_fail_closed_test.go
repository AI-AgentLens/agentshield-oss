package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The MCP hook path (every non-Bash tool) had no fail-closed boundary
// (adversarial review, 2026-09-02): a corrupt ~/.agentshield/mcp-policy.yaml
// was a warning plus a silent fallback to the embedded rules. These re-exec
// the real entry point with an MCP tool call and assert the exit code.

const mcpReadPayload = `{"hook_event_name":"PreToolUse","tool_name":"mcp__fs__read_file","session_id":"mcp-fc","tool_input":{"path":"/tmp/notes.txt"}}`

func writeCorruptMCPPolicy(t *testing.T, configDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(configDir, "mcp-policy.yaml"), []byte("rules: [\n  - not: valid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestHook_CorruptMCPPolicy_ExitsTwoUnderManagedFailClosed(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	writeCorruptMCPPolicy(t, configDir)

	code, stderr := runHookInChildProcess(t, home, mcpReadPayload)
	if code != 2 {
		t.Fatalf("exit %d; want 2 — a corrupt MCP policy on a managed fail_closed host must block, not fall back. stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "fail_closed") {
		t.Errorf("stderr does not explain the fail-closed block:\n%s", stderr)
	}
	if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, failClosedRuleID) {
		t.Errorf("audit.jsonl does not record the MCP fail-closed block:\n%s", log)
	}
}

func TestHook_CorruptMCPPolicy_WarnsAndEvaluatesWhenNotManaged(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	writeCorruptMCPPolicy(t, configDir)

	code, stderr := runHookInChildProcess(t, home, mcpReadPayload)
	if code != 0 {
		t.Fatalf("exit %d; want 0 outside managed mode (benign read of /tmp/notes.txt). stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "degraded") {
		t.Errorf("the degraded ruleset must be said out loud:\n%s", stderr)
	}
}

// Control: a managed fail_closed host with a healthy (absent) MCP policy still
// lets a benign MCP read through — absent is not corrupt.
func TestHook_HealthyMCPPolicy_ManagedBenignReadPasses(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	code, stderr := runHookInChildProcess(t, home, mcpReadPayload)
	if code != 0 {
		t.Fatalf("exit %d; want 0 for a benign MCP read with no MCP policy file. stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "degraded") {
		t.Errorf("an absent MCP policy must not be reported as degraded:\n%s", stderr)
	}
}
