package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
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
	code, _, stderr := runClientProcess(t, []string{python3(t), scriptPath}, env, payload)
	return code, stderr
}

// runClientProcess runs one thin-client process (argv) with payload on stdin
// — a []byte is sent verbatim, anything else JSON-encoded — and returns the
// exit code, stdout and stderr. Shared by the Python and PowerShell clients so
// both are held to one harness contract.
func runClientProcess(t *testing.T, argv []string, env map[string]string, payload interface{}) (int, string, string) {
	t.Helper()
	stdin, ok := payload.([]byte)
	if !ok {
		var err error
		if stdin, err = json.Marshal(payload); err != nil {
			t.Fatal(err)
		}
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = bytes.NewReader(stdin)
	// Minimal, explicit environment: the client must work from nothing but
	// its documented variables (plus HOME for getpass on some platforms).
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=" + os.Getenv("PATH"), "USER=" + os.Getenv("USER"), "LOGNAME=" + os.Getenv("LOGNAME")}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("running client: %v (stderr: %s)", err, stderr.String())
	}
	return code, stdout.String(), stderr.String()
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

// TestRemoteHookRoutesOnlyBashAsAShell pins the Python client's request shape
// (ADR-001 step 0, #4245): only tool_name "Bash" is sent as a command; every
// other tool, Claude Code's PowerShell included, is sent as a tool call. That
// shape is what a server without the routing key routes on; this server
// routes on the key the client also sends (step 2), and each input below
// decides as its row says: a destructive command BLOCKs as Bash and decides
// AUDIT as Claude Code's PowerShell (MCP policy and the PowerShell lane: no
// step-5 PowerShell rule covers `rm -rf /`, a bash spelling); `ls -la` ALLOWs
// as Bash and BLOCKs as a call to a tool named bash, which no row names (MCP
// policy).
func TestRemoteHookRoutesOnlyBashAsAShell(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}
	call := func(tool, command string) map[string]interface{} {
		return map[string]interface{}{
			"hook_event_name": "PreToolUse",
			"tool_name":       tool,
			"tool_input":      map[string]interface{}{"command": command},
			"session_id":      "it-route",
		}
	}

	code, stderr := runHookClient(t, env, call("PowerShell", destructiveCommand()))
	if code != 0 || !strings.Contains(stderr, "AUDIT MCP tool: PowerShell") {
		t.Errorf("PowerShell: exit %d, want 0 with the MCP AUDIT line (sent as a tool call). stderr: %s", code, stderr)
	}

	code, stderr = runHookClient(t, env, call("bash", "ls -la"))
	if code != 2 || !strings.Contains(stderr, "BLOCKED MCP tool call: bash") {
		t.Errorf("bash (lower case): exit %d, want 2 from MCP policy (sent as a tool call). stderr: %s", code, stderr)
	}

	// Control: the same benign command under "Bash" is a shell command.
	if code, stderr = runHookClient(t, env, call("Bash", "ls -la")); code != 0 || strings.Contains(stderr, "BLOCKED") {
		t.Errorf("Bash: exit %d, want 0 (sent as a command). stderr: %s", code, stderr)
	}
}

// TestRemoteHookSendsRoutingKey captures what the client sends (ADR-001 step
// 2): the routing key on every request (harness, the tool exactly as the
// harness named it, this host's OS) and the whole tool_input as arguments,
// while the shape stays the one a server without the key reads: Bash as a
// command, every other tool as a tool call.
func TestRemoteHookSendsRoutingKey(t *testing.T) {
	bodies, capture := captureServer(t)
	env := map[string]string{"AGENTSHIELD_SERVER_URL": capture.URL}
	call := func(tool string, input map[string]interface{}, codex bool) map[string]interface{} {
		p := map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "session_id": "s", "cwd": "/repo"}
		if codex {
			p["turn_id"] = "turn-0001"
		}
		return p
	}
	runs := []struct {
		payload  map[string]interface{}
		harness  string
		command  bool // sent as a command
		toolName string
	}{
		{call("Bash", map[string]interface{}{"command": "ls -la", "description": "list"}, false), "claude-code", true, ""},
		{call("PowerShell", map[string]interface{}{"command": "Get-ChildItem"}, false), "claude-code", false, "PowerShell"},
		{call("Bash", map[string]interface{}{"command": "ls"}, true), "codex", true, ""},
		{call("Read", map[string]interface{}{"file_path": "/repo/a"}, false), "claude-code", false, "Read"},
	}
	for _, r := range runs {
		if code, stderr := runHookClient(t, env, r.payload); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr)
		}
	}
	got := bodies()
	if len(got) != len(runs) {
		t.Fatalf("server saw %d requests, want %d", len(got), len(runs))
	}
	for i, r := range runs {
		b := got[i]
		tool := r.payload["tool_name"]
		rk, _ := b["route"].(map[string]interface{})
		if rk["harness"] != r.harness || rk["tool"] != tool || rk["os"] != clientHostOS() {
			t.Errorf("%v: route %v, want harness %s, tool %v, os %s", tool, b["route"], r.harness, tool, clientHostOS())
		}
		if r.command != (b["command"] != nil) || (b["tool_name"] != nil) == r.command {
			t.Errorf("%v: command %v tool_name %v; want it sent as a command: %v", tool, b["command"], b["tool_name"], r.command)
		}
		if !reflect.DeepEqual(b["arguments"], r.payload["tool_input"]) {
			t.Errorf("%v: arguments %v, want the whole tool_input %v", tool, b["arguments"], r.payload["tool_input"])
		}
	}
}

// TestRemoteHookClaudeCodePowerShellReachesItsRow: end to end through the
// script, Claude Code's PowerShell tool is read by MCP policy and its row's
// PowerShell lane, which blocks a key read MCP policy alone, main's path for
// this client, recorded as AUDIT. Control: a benign command passes.
func TestRemoteHookClaudeCodePowerShellReachesItsRow(t *testing.T) {
	ts := httptest.NewServer(sharedServer.Handler())
	defer ts.Close()
	env := map[string]string{"AGENTSHIELD_SERVER_URL": ts.URL}
	call := func(command string) map[string]interface{} {
		return map[string]interface{}{"hook_event_name": "PreToolUse", "tool_name": "PowerShell",
			"tool_input": map[string]interface{}{"command": command}, "session_id": "it-row", "cwd": "/repo"}
	}
	code, stderr := runHookClient(t, env, call(psKeyRead()))
	if code != 2 || !strings.Contains(stderr, "protected-path") {
		t.Errorf("key read: exit %d, want 2 by protected-path. stderr: %s", code, stderr)
	}
	if code, stderr = runHookClient(t, env, call("Get-Date")); code != 0 || strings.Contains(stderr, "BLOCKED") {
		t.Errorf("Get-Date: exit %d, want 0. stderr: %s", code, stderr)
	}
}

// TestRemoteHookHostOS: the client spells the host OS as Go's runtime.GOOS,
// the routing table's key, for every sys.platform it may run on.
func TestRemoteHookHostOS(t *testing.T) {
	scriptPath, err := filepath.Abs(clientScript)
	if err != nil {
		t.Fatal(err)
	}
	prog := `import importlib.util, sys
spec = importlib.util.spec_from_file_location("hook", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
for p in sys.argv[2:]:
    sys.platform = p
    print(p, m.host_os())
`
	rows := map[string]string{"win32": "windows", "cygwin": "windows", "msys": "windows", "darwin": "darwin",
		"linux": "linux", "linux2": "linux", "freebsd13": "freebsd", "openbsd7": "openbsd", "aix": "aix"}
	args := []string{"-I", "-c", prog, scriptPath}
	for p := range rows {
		args = append(args, p)
	}
	out, err := exec.Command(python3(t), args...).CombinedOutput()
	if err != nil {
		t.Fatalf("python: %v\n%s", err, out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		p, goos, _ := strings.Cut(line, " ")
		if rows[p] != goos {
			t.Errorf("sys.platform %q -> %q, want %q", p, goos, rows[p])
		}
		delete(rows, p)
	}
	if len(rows) != 0 {
		t.Errorf("no answer for %v", rows)
	}
}

// clientHostOS is this host's OS as the clients spell it in the route key.
func clientHostOS() string { return runtime.GOOS }

// captureServer records every request body and answers ALLOW.
func captureServer(t *testing.T) (func() []map[string]interface{}, *httptest.Server) {
	t.Helper()
	var mu sync.Mutex
	var bodies []map[string]interface{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]interface{}
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"ALLOW"}`))
	}))
	t.Cleanup(ts.Close)
	return func() []map[string]interface{} {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]interface{}(nil), bodies...)
	}, ts
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
