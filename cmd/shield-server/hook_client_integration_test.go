package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Integration contract test for clients/agentshield-remote-hook.py — the
// agentless Claude Code / Codex thin client. It exercises the REAL script
// against the REAL server handler: stdin payloads shaped exactly like the
// harness sends them (see internal/cli/hook.go hookInput), asserting on the
// exit-code contract the harness enforces (0 = allow/audit, 2 = block).
//
// This is the answer to "the server exists, but can a harness actually use
// it?" — everything between Claude Code and a verdict is under test except
// Claude Code itself, whose side of the contract (stdin JSON in, exit code
// out) is pinned here in the payload fixtures.

const clientScript = "../../clients/agentshield-remote-hook.py"

func python3(t *testing.T) string {
	t.Helper()
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH — remote-hook client test skipped")
	}
	return py
}

// runHookClient executes the client script with the given stdin payload and
// environment overrides, returning the exit code and stderr.
func runHookClient(t *testing.T, env map[string]string, payload map[string]interface{}) (int, string) {
	t.Helper()
	scriptPath, err := filepath.Abs(clientScript)
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(python3(t), scriptPath)
	cmd.Stdin = bytes.NewReader(stdin)
	// Minimal, explicit environment: the client must work from nothing but
	// its documented variables (plus HOME for getpass on some platforms).
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH"), "USER=" + os.Getenv("USER"), "LOGNAME=" + os.Getenv("LOGNAME")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running client: %v (stderr: %s)", err, stderr.String())
	}
	return code, stderr.String()
}

// claudeBashPayload mirrors the PreToolUse JSON Claude Code sends for a Bash
// tool call (internal/cli/hook.go hookInput). codex=true adds turn_id, which
// is the only difference in Codex CLI's payload.
func claudeBashPayload(command, sessionID string, codex bool) map[string]interface{} {
	p := map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]interface{}{"command": command},
		"session_id":      sessionID,
	}
	if codex {
		p["turn_id"] = "turn-0001"
	}
	return p
}

func TestRemoteHookClaudeCodeAllowsBenign(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		claudeBashPayload("ls -la", "it-benign", false))
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, stderr)
	}
	if strings.Contains(stderr, "BLOCKED") {
		t.Errorf("benign command produced a block message: %s", stderr)
	}
}

func TestRemoteHookClaudeCodeBlocksDestructive(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		claudeBashPayload(destructiveCommand(), "it-destructive", false))
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "AgentShield BLOCKED this command") {
		t.Errorf("block message missing the hook.go-parity header: %s", stderr)
	}
	if !strings.Contains(stderr, "Rule:") {
		t.Errorf("block message missing triggered rules: %s", stderr)
	}
}

func TestRemoteHookCodexBlocksDestructive(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		claudeBashPayload(destructiveCommand(), "it-codex", true))
	if code != 2 {
		t.Fatalf("Codex payload: exit = %d, want 2 (stderr: %s)", code, stderr)
	}
}

func TestRemoteHookBlocksMCPToolCall(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()

	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		map[string]interface{}{
			"hook_event_name": "PreToolUse",
			"tool_name":       "read_file",
			"tool_input":      map[string]interface{}{"path": credentialPath()},
			"session_id":      "it-mcp",
		})
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, stderr)
	}
	if !strings.Contains(stderr, "BLOCKED MCP tool call") {
		t.Errorf("MCP block message missing: %s", stderr)
	}
}

func TestRemoteHookSendsBearerToken(t *testing.T) {
	// Shallow copy shares the loaded engine but carries a token, so the
	// authenticated path is tested without a second pipeline build.
	authed := *sharedServer
	authed.token = "it-token"
	ts := httptest.NewServer(authed.Handler())
	defer ts.Close()

	// With the token: verdicts flow.
	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL, "AGENTSHIELD_SERVER_TOKEN": "it-token"},
		claudeBashPayload(destructiveCommand(), "it-auth", false))
	if code != 2 {
		t.Fatalf("with token: exit = %d, want 2 (stderr: %s)", code, stderr)
	}

	// Without it: 401 → fail-open (allow) with a warning, never a silent pass.
	code, stderr = runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		claudeBashPayload(destructiveCommand(), "it-auth-miss", false))
	if code != 0 {
		t.Fatalf("missing token: exit = %d, want 0 (fail open)", code)
	}
	if !strings.Contains(stderr, "warning") {
		t.Errorf("missing-token fail-open must warn on stderr, got: %s", stderr)
	}
}

func TestRemoteHookFailOpenAndFailClosed(t *testing.T) {
	deadURL := "http://127.0.0.1:1" // nothing listens on port 1

	code, stderr := runHookClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": deadURL, "AGENTSHIELD_REMOTE_TIMEOUT_SECONDS": "1"},
		claudeBashPayload(destructiveCommand(), "it-down", false))
	if code != 0 {
		t.Fatalf("server down, default: exit = %d, want 0 (fail open)", code)
	}
	if !strings.Contains(stderr, "fail open") {
		t.Errorf("fail-open warning missing: %s", stderr)
	}

	code, stderr = runHookClient(t,
		map[string]string{
			"AGENTSHIELD_SERVER_URL":             deadURL,
			"AGENTSHIELD_REMOTE_TIMEOUT_SECONDS": "1",
			"AGENTSHIELD_REMOTE_FAIL_CLOSED":     "1",
		},
		claudeBashPayload(destructiveCommand(), "it-down-closed", false))
	if code != 2 {
		t.Fatalf("server down, fail-closed: exit = %d, want 2 (stderr: %s)", code, stderr)
	}
}

func TestRemoteHookPassesThroughNonHookInput(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	// Empty command — nothing to evaluate.
	code, _ := runHookClient(t, env, claudeBashPayload("", "it-empty", false))
	if code != 0 {
		t.Errorf("empty command: exit = %d, want 0", code)
	}

	// Not a PreToolUse payload at all.
	code, _ = runHookClient(t, env, map[string]interface{}{"something": "else"})
	if code != 0 {
		t.Errorf("non-hook payload: exit = %d, want 0", code)
	}
}
