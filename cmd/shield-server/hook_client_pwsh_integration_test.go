package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Integration contract test for clients/agentshield-remote-hook.ps1 — the
// PowerShell twin of the Python thin client, built for GitHub Copilot CLI on
// Windows (#4244). Same shape as hook_client_integration_test.go: the REAL
// script against the REAL server handler, with stdin payloads shaped as
// Copilot documents them, asserting the harness contract:
//
//   - exit 0 and EMPTY stdout = allow / audit (Copilot parses stdout as JSON);
//   - exit 2 plus {"permissionDecision":"deny",...} on stdout = block;
//   - every failure ends in exit 0 unless fail-closed is asked for, because
//     Copilot DENIES on any other non-zero exit.
//
// Runs wherever `pwsh` is on PATH. It skips otherwise — except when
// AGENTSHIELD_REQUIRE_PWSH=1, which turns a missing pwsh into a failure so a
// CI job meant to run this suite can never pass vacuously.
//
// Not covered here: Windows PowerShell 5.1 itself (the script is kept
// 5.1-compatible and checked with PSScriptAnalyzer's 5.1 profiles), Windows
// console encodings, and a live Copilot CLI. See docs/shield-server.md.

const pwshClientScript = "../../clients/agentshield-remote-hook.ps1"

func pwshBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("pwsh")
	if err != nil {
		if os.Getenv("AGENTSHIELD_REQUIRE_PWSH") == "1" {
			t.Fatal("AGENTSHIELD_REQUIRE_PWSH=1 but pwsh is not on PATH")
		}
		t.Skip("pwsh not on PATH — PowerShell remote-hook client test skipped")
	}
	return p
}

func runPwshClient(t *testing.T, env map[string]string, payload interface{}) (int, string, string) {
	t.Helper()
	scriptPath, err := filepath.Abs(pwshClientScript)
	if err != nil {
		t.Fatal(err)
	}
	return runClientProcess(t, []string{pwshBin(t), "-NoProfile", "-NonInteractive", "-File", scriptPath}, env, payload)
}

// copilotCompatPayload is Copilot CLI's Claude-compatible PreToolUse input
// (PascalCase event): snake_case fields, and its `bash` AND `powershell`
// tools both arrive as tool_name "Bash".
func copilotCompatPayload(toolName string, toolInput map[string]interface{}, sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      sessionID,
		"timestamp":       "2026-10-07T12:00:00Z",
		"cwd":             "/repo",
		"tool_name":       toolName,
		"tool_input":      toolInput,
	}
}

// copilotNativePayload is Copilot CLI's native preToolUse input (camelCase
// event): toolName / toolArgs with runtime tool names.
func copilotNativePayload(toolName string, toolArgs map[string]interface{}, sessionID string) map[string]interface{} {
	return map[string]interface{}{
		"sessionId": sessionID,
		"timestamp": 1791398400000,
		"cwd":       "/repo",
		"toolName":  toolName,
		"toolArgs":  toolArgs,
	}
}

func cmdInput(c string) map[string]interface{} { return map[string]interface{}{"command": c} }

// posixCredentialFile is covered by mcp-struct-block-credential-path-access
// for ANY tool name, so it exercises the harness file-tool path.
func posixCredentialFile() string { return "/home/user/" + ".aws/" + "credentials" }

// windowsCredentialPath is a credential file in native Windows spelling —
// assembled at runtime for the same dogfooding reason as credentialPath().
func windowsCredentialPath() string { return `C:\Users\dev\` + `.aws\` + "credentials" }

// assertDeny checks the block contract: exit 2 and a parseable Copilot deny.
func assertDeny(t *testing.T, label string, code int, stdout, stderr string) {
	t.Helper()
	if code != 2 {
		t.Fatalf("%s: exit = %d, want 2 (stdout: %q stderr: %s)", label, code, stdout, stderr)
	}
	var out struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("%s: stdout is not the Copilot deny JSON: %v (stdout: %q)", label, err, stdout)
	}
	if out.PermissionDecision != "deny" {
		t.Errorf("%s: permissionDecision = %q, want deny", label, out.PermissionDecision)
	}
	if !strings.Contains(out.PermissionDecisionReason, "AgentShield BLOCKED") {
		t.Errorf("%s: permissionDecisionReason lacks the block header: %q", label, out.PermissionDecisionReason)
	}
	if !strings.Contains(stderr, "AgentShield BLOCKED") {
		t.Errorf("%s: stderr lacks the hook.go-parity block message (Claude Code reads stderr on exit 2): %s", label, stderr)
	}
}

// assertAllow checks the allow contract: exit 0 and nothing on stdout.
func assertAllow(t *testing.T, label string, code int, stdout, stderr string) {
	t.Helper()
	if code != 0 {
		t.Fatalf("%s: exit = %d, want 0 (stderr: %s)", label, code, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("%s: stdout must be empty on allow (Copilot parses it as JSON), got %q", label, stdout)
	}
}

func TestPwshHookAllowsBenign(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	code, stdout, stderr := runPwshClient(t, env, copilotCompatPayload("Bash", cmdInput("ls -la"), "pw-benign"))
	assertAllow(t, "compat Bash ls", code, stdout, stderr)
	if strings.Contains(stderr, "BLOCKED") {
		t.Errorf("benign command produced a block message: %s", stderr)
	}
}

func TestPwshHookBlocksDestructiveBothDialects(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	code, stdout, stderr := runPwshClient(t, env, copilotCompatPayload("Bash", cmdInput(destructiveCommand()), "pw-compat"))
	assertDeny(t, "compat Bash", code, stdout, stderr)
	if !strings.Contains(stderr, "Rule:") {
		t.Errorf("block message missing triggered rules: %s", stderr)
	}

	for _, tool := range []string{"bash", "powershell"} {
		code, stdout, stderr = runPwshClient(t, env, copilotNativePayload(tool, cmdInput(destructiveCommand()), "pw-native-"+tool))
		assertDeny(t, "native "+tool, code, stdout, stderr)
	}
}

func TestPwshHookBlocksCredentialReadThroughFileTools(t *testing.T) {
	// A harness Read of a credential file BLOCKs only through the premium
	// mcp-prem-block-cred-path-filepath-key. Community rules record it as AUDIT
	// with the read rules attached (#4248, record-not-enforce), so in the
	// published tree this test would only fail.
	ossbuild.SkipPremiumSized(t)
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	// Claude-compatible mode: Copilot's `view` arrives as Read. The path must be
	// one the tool-agnostic catch-all covers — most credential rules match only
	// MCP tool names, so Read of e.g. a vault token is AUDIT today (#4248).
	code, stdout, stderr := runPwshClient(t, env,
		copilotCompatPayload("Read", map[string]interface{}{"file_path": posixCredentialFile()}, "pw-read"))
	assertDeny(t, "compat Read", code, stdout, stderr)
	if !strings.Contains(stderr, "BLOCKED MCP tool call: Read") {
		t.Errorf("MCP block message missing: %s", stderr)
	}

	// Native mode with a native Windows path (#4243).
	code, stdout, stderr = runPwshClient(t, env,
		copilotNativePayload("view", map[string]interface{}{"path": windowsCredentialPath()}, "pw-view-win"))
	assertDeny(t, "native view, Windows path", code, stdout, stderr)
}

func TestPwshHookBearerToken(t *testing.T) {
	authed := *sharedServer
	authed.token = "pw-token"
	ts := httptest.NewServer(authed.Handler())
	defer ts.Close()

	code, stdout, stderr := runPwshClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL, "AGENTSHIELD_SERVER_TOKEN": "pw-token"},
		copilotCompatPayload("Bash", cmdInput(destructiveCommand()), "pw-auth"))
	assertDeny(t, "with token", code, stdout, stderr)

	// Without it: 401 → fail open with a warning, never a silent pass.
	code, stdout, stderr = runPwshClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL},
		copilotCompatPayload("Bash", cmdInput(destructiveCommand()), "pw-auth-miss"))
	assertAllow(t, "missing token", code, stdout, stderr)
	if !strings.Contains(stderr, "warning") {
		t.Errorf("missing-token fail-open must warn on stderr, got: %s", stderr)
	}
}

func TestPwshHookFailOpenAndFailClosed(t *testing.T) {
	deadURL := "http://127.0.0.1:1" // nothing listens on port 1
	payload := copilotCompatPayload("Bash", cmdInput(destructiveCommand()), "pw-down")

	code, stdout, stderr := runPwshClient(t,
		map[string]string{"AGENTSHIELD_SERVER_URL": deadURL, "AGENTSHIELD_REMOTE_TIMEOUT_SECONDS": "1"}, payload)
	assertAllow(t, "server down, default", code, stdout, stderr)
	if !strings.Contains(stderr, "fail open") {
		t.Errorf("fail-open warning missing: %s", stderr)
	}

	code, stdout, stderr = runPwshClient(t, map[string]string{
		"AGENTSHIELD_SERVER_URL":             deadURL,
		"AGENTSHIELD_REMOTE_TIMEOUT_SECONDS": "1",
		"AGENTSHIELD_REMOTE_FAIL_CLOSED":     "1",
	}, payload)
	assertDeny(t, "server down, fail-closed", code, stdout, stderr)
}

func TestPwshHookPassesThroughAndWarns(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	cases := []struct {
		name    string
		payload interface{}
		warn    string // substring expected on stderr; "" = none required
	}{
		{"empty command", copilotCompatPayload("Bash", cmdInput(""), "pw-empty"), ""},
		{"not a hook payload", map[string]interface{}{"something": "else"}, ""},
		{"post-tool event", map[string]interface{}{"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": cmdInput(destructiveCommand())}, ""},
		{"unparseable stdin", []byte("not json {"), "could not parse hook input"},
		// A shell call with NO command field is a payload shape this client
		// was not built for: allowed, but never silently.
		{"shell tool without command field", copilotCompatPayload("Bash", map[string]interface{}{"script": "x"}, "pw-shape"), "payload shape not recognised"},
	}
	for _, c := range cases {
		code, stdout, stderr := runPwshClient(t, env, c.payload)
		assertAllow(t, c.name, code, stdout, stderr)
		if c.warn != "" && !strings.Contains(stderr, c.warn) {
			t.Errorf("%s: expected warning %q on stderr, got: %s", c.name, c.warn, stderr)
		}
	}
}

// TestPwshHookIdentityAndUTF8 captures what the client actually sends: the
// identity plane (#3111) for both dialects, and a non-ASCII command arriving
// byte-identical (Windows PowerShell 5.1 would send a string body as
// ISO-8859-1; the client sends UTF-8 bytes).
func TestPwshHookIdentityAndUTF8(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]interface{}
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
	}))
	defer capture.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": capture.URL}

	nonASCII := "echo h\u00e9llo \u2713 \u65e5\u672c"
	type identityRun struct {
		env     map[string]string
		payload map[string]interface{}
		agent   string
		session string
	}
	runs := []identityRun{
		{env, copilotCompatPayload("Bash", cmdInput(nonASCII), "s-compat"), "copilot-cli", "s-compat"},
		{env, copilotNativePayload("powershell", cmdInput("Get-ChildItem"), "s-native"), "copilot-cli", "s-native"},
		{map[string]string{"AGENTSHIELD_SERVER_URL": capture.URL, "AGENTSHIELD_AGENT_ID": "claude-code"},
			copilotCompatPayload("Bash", cmdInput("ls"), "s-override"), "claude-code", "s-override"},
	}
	codexPayload := copilotCompatPayload("Bash", cmdInput("ls"), "s-codex")
	codexPayload["turn_id"] = "turn-0001"
	runs = append(runs, identityRun{env, codexPayload, "codex", "s-codex"})

	for _, r := range runs {
		code, stdout, stderr := runPwshClient(t, r.env, r.payload)
		assertAllow(t, r.session, code, stdout, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != len(runs) {
		t.Fatalf("server saw %d requests, want %d", len(bodies), len(runs))
	}
	for i, r := range runs {
		b := bodies[i]
		if b["agent_id"] != r.agent || b["source"] != r.agent+"-remote-hook" || b["session_id"] != r.session {
			t.Errorf("request %d identity = agent_id %v, source %v, session_id %v; want %s / %s-remote-hook / %s",
				i, b["agent_id"], b["source"], b["session_id"], r.agent, r.agent, r.session)
		}
		if s, _ := b["principal"].(string); s == "" {
			t.Errorf("request %d carries no principal", i)
		}
	}
	if bodies[0]["command"] != nonASCII {
		t.Errorf("non-ASCII command altered in transit: got %q, want %q", bodies[0]["command"], nonASCII)
	}
}

// TestPwshHookParityWithPythonClient: the two thin clients must reach the
// same verdict exit code on every Claude-shaped payload — they are one
// contract in two languages.
func TestPwshHookParityWithPythonClient(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}

	payloads := map[string]map[string]interface{}{
		"benign shell":      copilotCompatPayload("Bash", cmdInput("git status"), "par-1"),
		"destructive shell": copilotCompatPayload("Bash", cmdInput(destructiveCommand()), "par-2"),
		"credential read":   copilotCompatPayload("read_file", map[string]interface{}{"path": credentialPath()}, "par-3"),
		"benign read":       copilotCompatPayload("read_file", map[string]interface{}{"path": "/workspace/project/README.md"}, "par-4"),
		"empty command":     copilotCompatPayload("Bash", cmdInput(""), "par-5"),
		"non-hook":          {"something": "else"},
	}
	for name, p := range payloads {
		pyCode, _ := runHookClient(t, env, p)
		psCode, _, psStderr := runPwshClient(t, env, p)
		if pyCode != psCode {
			t.Errorf("%s: python exit %d, pwsh exit %d (pwsh stderr: %s)", name, pyCode, psCode, psStderr)
		}
	}
}

// TestPwshHookForwardsStringToolInput pins payload shapes captured from a live
// Copilot CLI 1.0.93 session: edits made through apply_patch arrive with
// tool_input (compat) / toolArgs (native) as the raw patch TEXT, not an
// object. The client must forward that text, not evaluate an empty map; a
// JSON-encoded toolArgs string must still be decoded into an object.
func TestPwshHookForwardsStringToolInput(t *testing.T) {
	var mu sync.Mutex
	var bodies []map[string]interface{}
	capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"AUDIT"}`))
	}))
	defer capture.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": capture.URL}

	patch := "*** Begin Patch\n*** Update File: out.txt\n@@\n-hi\n+hello\n*** End Patch\n"
	compat := copilotCompatPayload("Edit", nil, "s-patch-compat")
	compat["tool_input"] = patch
	native := copilotNativePayload("apply_patch", nil, "s-patch-native")
	native["toolArgs"] = patch
	encoded := copilotNativePayload("view", nil, "s-encoded")
	encoded["toolArgs"] = `{"path":"/repo/notes.txt"}`
	plain := copilotNativePayload("custom_tool", nil, "s-plain")
	plain["toolArgs"] = "free text argument"

	for _, p := range []map[string]interface{}{compat, native, encoded, plain} {
		code, stdout, stderr := runPwshClient(t, env, p)
		assertAllow(t, fmt.Sprint(p["session_id"], p["sessionId"]), code, stdout, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 4 {
		t.Fatalf("server saw %d requests, want 4", len(bodies))
	}
	args := func(i int) map[string]interface{} {
		a, _ := bodies[i]["arguments"].(map[string]interface{})
		return a
	}
	for i, tool := range []string{"Edit", "apply_patch"} {
		if bodies[i]["tool_name"] != tool || args(i)["patch"] != patch {
			t.Errorf("%s: arguments = %v, want {patch: <the patch text>}", tool, args(i))
		}
	}
	if args(2)["path"] != "/repo/notes.txt" {
		t.Errorf("JSON-encoded toolArgs not decoded: arguments = %v", args(2))
	}
	if args(3)["input"] != "free text argument" {
		t.Errorf("plain string toolArgs not forwarded under input: arguments = %v", args(3))
	}
}
