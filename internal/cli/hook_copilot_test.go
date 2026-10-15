package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GitHub Copilot CLI support for the local hook (#4251). The payload shapes
// below are the ones captured from a live Copilot CLI 1.0.93 session; before
// this change the native dialect (numeric timestamp) and every apply_patch
// edit (string tool_input) failed to parse as a whole — a fail-safe AUDIT, or
// a BLOCK on a managed fail_closed host, with nothing evaluated.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).

func copilotCompatPayload(t *testing.T, session, tool string, input interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"session_id":      session,
		"timestamp":       "2026-10-07T16:41:43.120Z",
		"cwd":             "/repo",
		"tool_name":       tool,
		"tool_input":      input,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func copilotNativePayload(t *testing.T, session, tool string, args interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"sessionId": session,
		"timestamp": 1791391303120,
		"cwd":       "/repo",
		"toolName":  tool,
		"toolArgs":  args,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func shellArgs(command string) map[string]interface{} {
	return map[string]interface{}{"command": command, "description": "Run a command"}
}

const capturedPatch = "*** Begin Patch\n*** Update File: out.txt\n@@\n-hi\n+hello\n*** End Patch\n"

func destructiveShell() string { return "rm -rf " + "/" }

// catchAllCredentialPath is matched by the tool-name-agnostic credential rule,
// so it BLOCKs through any harness file tool.
func catchAllCredentialPath() string { return "/home/user/" + ".aws/" + "credentials" }

// runHookChild runs the real hook entry point in a child process with HOME set,
// AGENTSHIELD_AGENT_ID cleared, and extra env applied — the full contract a
// harness sees: exit code, stdout, stderr.
func runHookChild(t *testing.T, home, payload string, extraEnv ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "AGENTSHIELD_AGENT_ID=") {
			env = append(env, kv)
		}
	}
	cmd.Env = append(append(env, "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home), extraEnv...)
	cmd.Stdin = strings.NewReader(payload)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err == nil {
		return 0, out.String(), errb.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errb.String()
	}
	t.Fatalf("running hook helper: %v", err)
	return -1, "", ""
}

// jsonLines returns stdout lines that look like JSON objects.
func jsonLines(stdout string) []string {
	var out []string
	for _, l := range strings.Split(stdout, "\n") {
		if l = strings.TrimSpace(l); strings.HasPrefix(l, "{") {
			out = append(out, l)
		}
	}
	return out
}

type copilotDeny struct {
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

func requireCopilotDeny(t *testing.T, label string, code int, stdout, stderr, wantInReason string) {
	t.Helper()
	if code != 2 {
		t.Fatalf("%s: exit %d, want 2 (stderr: %s)", label, code, stderr)
	}
	lines := jsonLines(stdout)
	if len(lines) != 1 {
		t.Fatalf("%s: want exactly one JSON verdict on stdout, got %d:\n%s", label, len(lines), stdout)
	}
	var d copilotDeny
	if err := json.Unmarshal([]byte(lines[0]), &d); err != nil {
		t.Fatalf("%s: stdout verdict is not JSON: %v (%s)", label, err, lines[0])
	}
	if d.PermissionDecision != "deny" || !strings.Contains(d.PermissionDecisionReason, wantInReason) {
		t.Errorf("%s: verdict = %+v, want deny with %q in the reason", label, d, wantInReason)
	}
	if !strings.Contains(stderr, "AgentShield BLOCKED") {
		t.Errorf("%s: stderr lacks the block message: %s", label, stderr)
	}
}

type auditLine struct {
	SessionID      string                 `json:"session_id"`
	Decision       string                 `json:"decision"`
	Source         string                 `json:"source"`
	ToolName       string                 `json:"tool_name"`
	TriggeredRules []string               `json:"triggered_rules"`
	Arguments      map[string]interface{} `json:"arguments"`
}

func auditBySession(t *testing.T, configDir, session string) []auditLine {
	t.Helper()
	var out []auditLine
	for _, l := range strings.Split(readFailSafeAuditLog(t, configDir), "\n") {
		var e auditLine
		if json.Unmarshal([]byte(l), &e) == nil && e.SessionID == session {
			out = append(out, e)
		}
	}
	return out
}

// TestCopilotCapturedPayloadsAreEvaluated: every captured shape parses and is
// evaluated — benign calls exit 0, write no verdict, and leave an audit event.
// On main the compat edit and all three native shapes printed "hook input
// parse failed" instead.
func TestCopilotCapturedPayloadsAreEvaluated(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	cases := []struct {
		name, payload, session string
	}{
		{"compat Bash", copilotCompatPayload(t, "c-bash", "Bash", shellArgs("echo copilot-capture")), "c-bash"},
		{"compat Read", copilotCompatPayload(t, "c-read", "Read", map[string]interface{}{"path": "/repo/notes.txt"}), "c-read"},
		{"compat Edit (patch string)", copilotCompatPayload(t, "c-edit", "Edit", capturedPatch), "c-edit"},
		{"native bash", copilotNativePayload(t, "n-bash", "bash", shellArgs("echo copilot-capture")), "n-bash"},
		{"native view", copilotNativePayload(t, "n-view", "view", map[string]interface{}{"path": "/repo/notes.txt"}), "n-view"},
		{"native apply_patch (patch string)", copilotNativePayload(t, "n-patch", "apply_patch", capturedPatch), "n-patch"},
	}
	for _, c := range cases {
		code, stdout, stderr := runHookChild(t, home, c.payload)
		if code != 0 {
			t.Errorf("%s: exit %d, want 0 (stderr: %s)", c.name, code, stderr)
		}
		if strings.Contains(stderr, "hook input parse failed") {
			t.Errorf("%s: payload failed to parse — not evaluated: %s", c.name, stderr)
		}
		if lines := jsonLines(stdout); len(lines) != 0 {
			t.Errorf("%s: a non-block must write no verdict on stdout, got %v", c.name, lines)
		}
		if ev := auditBySession(t, configDir, c.session); len(ev) == 0 {
			t.Errorf("%s: no audit event — the call was not evaluated", c.name)
		}
	}
}

// TestCopilotPayloadsUnderManagedFailClosed: on a managed fail_closed host the
// same benign payloads used to BLOCK (parse failure → fail-safe). They are now
// evaluated, and benign calls run. A malformed shell command still fails safe.
func TestCopilotPayloadsUnderManagedFailClosed(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	for name, p := range map[string]string{
		"native bash":        copilotNativePayload(t, "m-bash", "bash", shellArgs("echo ok")),
		"compat Edit":        copilotCompatPayload(t, "m-edit", "Edit", capturedPatch),
		"native apply_patch": copilotNativePayload(t, "m-patch", "apply_patch", capturedPatch),
	} {
		if code, _, stderr := runHookChild(t, home, p); code != 0 {
			t.Errorf("%s: exit %d under managed fail_closed, want 0 (evaluated, benign): %s", name, code, stderr)
		}
	}
	// The strictness that matters is unchanged: a shell call whose command is
	// not a string cannot be evaluated, so it still fails safe — in both
	// dialects, with a Copilot verdict for the dialect that names itself.
	badCompat := copilotCompatPayload(t, "m-bad", "Bash", map[string]interface{}{"command": 123})
	if code, _, stderr := runHookChild(t, home, badCompat); code != 2 {
		t.Errorf("compat Bash with a non-string command: exit %d, want 2 (fail-safe BLOCK): %s", code, stderr)
	}
	badNative := copilotNativePayload(t, "m-bad2", "bash", map[string]interface{}{"command": 123})
	code, stdout, stderr := runHookChild(t, home, badNative)
	requireCopilotDeny(t, "native bash with a non-string command", code, stdout, stderr, "AgentShield BLOCKED")
}

func TestCopilotBlocksExplainToTheAgent(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)

	code, stdout, stderr := runHookChild(t, home, copilotNativePayload(t, "b1", "bash", shellArgs(destructiveShell())))
	requireCopilotDeny(t, "native bash", code, stdout, stderr, "AgentShield BLOCKED this command | Rule: ")

	code, stdout, stderr = runHookChild(t, home, copilotCompatPayload(t, "b2", "Bash", shellArgs(destructiveShell())),
		"AGENTSHIELD_AGENT_ID=copilot-cli")
	requireCopilotDeny(t, "compat Bash (setup's env)", code, stdout, stderr, "AgentShield BLOCKED this command | Rule: ")

	code, stdout, stderr = runHookChild(t, home, copilotNativePayload(t, "b3", "view", map[string]interface{}{"path": catchAllCredentialPath()}))
	requireCopilotDeny(t, "native view of a credential", code, stdout, stderr, "AgentShield BLOCKED MCP tool call: view | Rule: ")
}

// TestClaudeCodeOutputUnchanged: the Copilot verdict is never written for a
// Claude Code or Codex payload — their stdout stays empty on a block.
func TestClaudeCodeOutputUnchanged(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	claude := `{"session_id":"cc","transcript_path":"/tmp/t.jsonl","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + destructiveShell() + `"}}`
	codex := `{"session_id":"cx","turn_id":"t1","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + destructiveShell() + `"}}`
	for name, p := range map[string]string{"Claude Code": claude, "Codex": codex} {
		code, stdout, stderr := runHookChild(t, home, p)
		if code != 2 || !strings.Contains(stderr, "AgentShield BLOCKED") {
			t.Errorf("%s: exit %d, want 2 with the block message (stderr: %s)", name, code, stderr)
		}
		if lines := jsonLines(stdout); len(lines) != 0 {
			t.Errorf("%s: stdout must stay empty on a block, got %v", name, lines)
		}
	}
}

func TestCopilotReceiptAttribution(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	readme := map[string]interface{}{"path": "/repo/README.md"}
	cases := []struct {
		name, payload, session, wantSource string
		env                                []string
	}{
		{"native shell", copilotNativePayload(t, "a1", "bash", shellArgs("echo a")), "a1", "copilot-cli-hook", nil},
		{"native file tool", copilotNativePayload(t, "a2", "view", readme), "a2", "copilot-cli-mcp-hook", nil},
		{"compat + setup env", copilotCompatPayload(t, "a3", "Bash", shellArgs("echo a")), "a3", "copilot-cli-hook", []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}},
		{"compat file tool + env", copilotCompatPayload(t, "a4", "Read", readme), "a4", "copilot-cli-mcp-hook", []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}},
		// Without the env the compat dialect cannot be told from Claude Code.
		{"compat, no env", copilotCompatPayload(t, "a5", "Bash", shellArgs("echo a")), "a5", "claude-code-hook", nil},
		// A label that is not a plain id is ignored, never written into receipts.
		{"invalid env ignored", copilotCompatPayload(t, "a6", "Bash", shellArgs("echo a")), "a6", "claude-code-hook", []string{`AGENTSHIELD_AGENT_ID=Bad ID"x`}},
		// Codex labels are unchanged by the generalised MCP suffix.
		{"codex shell", `{"session_id":"a7","turn_id":"t","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo a"}}`, "a7", "codex-hook", nil},
		{"codex file tool", `{"session_id":"a8","turn_id":"t","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/repo/README.md"}}`, "a8", "codex-mcp-hook", nil},
		{"claude file tool", `{"session_id":"a9","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/repo/README.md"}}`, "a9", "claude-code-mcp-hook", nil},
	}
	for _, c := range cases {
		if code, _, stderr := runHookChild(t, home, c.payload, c.env...); code != 0 {
			t.Fatalf("%s: exit %d (stderr: %s)", c.name, code, stderr)
		}
		ev := auditBySession(t, configDir, c.session)
		if len(ev) == 0 || ev[len(ev)-1].Source != c.wantSource {
			t.Errorf("%s: audit source = %v, want %q", c.name, ev, c.wantSource)
		}
	}
}

// TestCopilotPatchTextIsEvaluatedAsArgument: an apply_patch edit reaches MCP
// policy with its text under "patch", not as an empty argument map.
func TestCopilotPatchTextIsEvaluatedAsArgument(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	for session, p := range map[string]string{
		"p1": copilotCompatPayload(t, "p1", "Edit", capturedPatch),
		"p2": copilotNativePayload(t, "p2", "apply_patch", capturedPatch),
		"p3": copilotNativePayload(t, "p3", "custom_tool", "free text"),
	} {
		if code, _, stderr := runHookChild(t, home, p); code != 0 {
			t.Fatalf("%s: exit %d (stderr: %s)", session, code, stderr)
		}
		ev := auditBySession(t, configDir, session)
		if len(ev) == 0 {
			t.Fatalf("%s: no audit event", session)
		}
		args := ev[len(ev)-1].Arguments
		wantKey := "patch"
		if session == "p3" {
			wantKey = "input"
		}
		if _, ok := args[wantKey]; !ok {
			t.Errorf("%s: audited arguments %v lack %q", session, args, wantKey)
		}
	}
}

// TestCopilotUnparseablePayloadVerdict: a payload that is not JSON at all,
// from a hook that names itself Copilot, gets Copilot's verdict format when the
// managed fail-safe blocks it.
func TestCopilotUnparseablePayloadVerdict(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	code, stdout, stderr := runHookChild(t, home, "{not json", "AGENTSHIELD_AGENT_ID=copilot-cli")
	requireCopilotDeny(t, "unparseable + copilot env", code, stdout, stderr, "AgentShield BLOCKED")

	code, stdout, _ = runHookChild(t, home, "{not json")
	if code != 2 || len(jsonLines(stdout)) != 0 {
		t.Errorf("unparseable, no env: exit %d stdout %q; want 2 and no Copilot verdict (dialect unknown)", code, stdout)
	}
}

// ---- setup copilot-cli ------------------------------------------------------

func withCopilotSetup(t *testing.T, disable bool) (home, copilotDir string) {
	t.Helper()
	home = t.TempDir()
	copilotDir = filepath.Join(home, "copilot-home")
	t.Setenv("HOME", home)
	t.Setenv("COPILOT_HOME", copilotDir)
	prev := disableFlag
	disableFlag = disable
	t.Cleanup(func() { disableFlag = prev })
	return home, copilotDir
}

func TestSetupCopilotCLI_WritesOwnedHookFile(t *testing.T) {
	_, copilotDir := withCopilotSetup(t, false)
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(copilotDir, "hooks", "agentshield.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("hook file not written: %v", err)
	}
	var doc struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Type       string            `json:"type"`
			Bash       string            `json:"bash"`
			Env        map[string]string `json:"env"`
			TimeoutSec int               `json:"timeoutSec"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("hook file is not JSON: %v", err)
	}
	entries := doc.Hooks["PreToolUse"]
	if doc.Version != 1 || len(entries) != 1 {
		t.Fatalf("hook file = %s; want version 1 with one PreToolUse (Claude-compatible dialect) entry", data)
	}
	e := entries[0]
	// The binary path is wherever resolveAgentShieldPath finds one: the
	// installed agentshield on a dev machine, the test binary on CI.
	if e.Type != "command" || !strings.HasSuffix(e.Bash, " hook") || e.Env["AGENTSHIELD_AGENT_ID"] != "copilot-cli" || e.TimeoutSec != 30 {
		t.Errorf("hook entry = %+v", e)
	}
	if ours, _ := isAgentShieldCopilotHookFile(path); !ours {
		t.Error("the file setup wrote is not recognised as ours")
	}

	// Idempotent: a second run leaves the bytes alone.
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(data) {
		t.Errorf("second setup rewrote the file:\n%s\nvs\n%s", again, data)
	}
}

// TestCopilotHookFileOwnership pins what "a file setup wrote" means, without
// depending on where this machine keeps the agentshield binary. CI resolves
// the test binary (…/cli.test), so a check on the binary's name alone
// disowned the file setup had just written.
func TestCopilotHookFileOwnership(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		ours bool
	}{
		{"setup output, installed binary", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"/opt/homebrew/bin/agentshield hook","env":{"AGENTSHIELD_AGENT_ID":"copilot-cli"}}]}}`, true},
		{"setup output, any binary path", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"/tmp/go-build1/b254/cli.test hook","env":{"AGENTSHIELD_AGENT_ID":"copilot-cli"}}]}}`, true},
		{"hand-written agentshield hook, no marker", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"agentshield hook"}]}}`, true},
		{"marker but not a hook command", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"my-own-guard","env":{"AGENTSHIELD_AGENT_ID":"copilot-cli"}}]}}`, false},
		{"hook command without the marker", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"/usr/bin/other-tool hook"}]}}`, false},
		{"another agent id", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"/tmp/x hook","env":{"AGENTSHIELD_AGENT_ID":"claude-code"}}]}}`, false},
		{"foreign guard", `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"my-own-guard"}]}}`, false},
		{"not JSON", `not json`, false},
	}
	dir := t.TempDir()
	for i, tc := range cases {
		path := filepath.Join(dir, fmt.Sprintf("h%d.json", i))
		if err := os.WriteFile(path, []byte(tc.doc), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := isAgentShieldCopilotHookFile(path)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.ours {
			t.Errorf("%s: ours = %v, want %v", tc.name, got, tc.ours)
		}
	}
}

func TestSetupCopilotCLI_NeverTouchesAForeignFile(t *testing.T) {
	_, copilotDir := withCopilotSetup(t, false)
	path := filepath.Join(copilotDir, "hooks", "agentshield.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"my-own-guard"}]}}`
	if err := os.WriteFile(path, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := setupCopilotCLICommand(nil, nil); err == nil {
		t.Error("setup overwrote a hook file it did not write")
	}
	disableFlag = true
	if err := setupCopilotCLICommand(nil, nil); err == nil {
		t.Error("disable removed a hook file it did not write")
	}
	if data, _ := os.ReadFile(path); string(data) != foreign {
		t.Errorf("foreign file changed: %s", data)
	}
}

func TestSetupCopilotCLI_DisableRemovesOnlyOurs(t *testing.T) {
	_, copilotDir := withCopilotSetup(t, false)
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(copilotDir, "hooks", "other.json")
	if err := os.WriteFile(sibling, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	disableFlag = true
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(copilotDir, "hooks", "agentshield.json")); !os.IsNotExist(err) {
		t.Errorf("our hook file survived --disable: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Errorf("--disable touched a sibling hook file: %v", err)
	}
	// Disabling again is a no-op, not an error.
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Errorf("second --disable: %v", err)
	}
}

func TestSetupCopilotCLI_DisableRefusedWhenManaged(t *testing.T) {
	home, copilotDir := withCopilotSetup(t, false)
	if err := setupCopilotCLICommand(nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".agentshield"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".agentshield", "managed.json"), []byte(`{"managed": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	disableFlag = true
	if err := setupCopilotCLICommand(nil, nil); err == nil {
		t.Error("--disable succeeded in managed mode")
	}
	if _, err := os.Stat(filepath.Join(copilotDir, "hooks", "agentshield.json")); err != nil {
		t.Errorf("managed-mode --disable removed the hook: %v", err)
	}
}

// TestCopilotStringShellInputFailsSafe: a string tool_input is accepted for
// edits only. For a shell call it would read as an empty command and pass
// unevaluated and unrecorded, so it keeps the pre-#4251 fail-safe path — BLOCK
// under managed fail_closed, a loud warning otherwise — in both dialects.
func TestCopilotStringShellInputFailsSafe(t *testing.T) {
	payloads := func(t *testing.T) map[string]string {
		return map[string]string{
			"compat Bash":  copilotCompatPayload(t, "s1", "Bash", "echo hi"),
			"native bash":  copilotNativePayload(t, "s2", "bash", "echo hi"),
			"native shell": copilotNativePayload(t, "s3", "powershell", "Get-ChildItem"),
		}
	}
	managed, _ := newFailSafeHome(t, true, failSafePolicyGood)
	for name, p := range payloads(t) {
		if code, _, stderr := runHookChild(t, managed, p); code != 2 {
			t.Errorf("%s with a string tool_input under managed fail_closed: exit %d, want 2 (fail-safe): %s", name, code, stderr)
		}
	}
	plain, _ := newFailSafeHome(t, false, failSafePolicyGood)
	for name, p := range payloads(t) {
		code, _, stderr := runHookChild(t, plain, p)
		if code != 0 || !strings.Contains(stderr, "hook input parse failed") {
			t.Errorf("%s with a string tool_input: exit %d, stderr %q; want 0 with the fail-safe warning, never a silent pass", name, code, stderr)
		}
	}
}

// TestStringToolInputGateMatchesMain (#4251 review, finding 1): a string
// tool_input is accepted only for a Claude-shaped PreToolUse call to a
// non-shell tool. For a Gemini run_shell_command or a Claude Bash call it fails
// the parse exactly as on main — never a silent allow.
func TestStringToolInputGateMatchesMain(t *testing.T) {
	gemini := `{"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":"` + destructiveShell() + `"}`
	claudeBash := `{"session_id":"g2","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":"` + destructiveShell() + `"}`
	managed, _ := newFailSafeHome(t, true, failSafePolicyGood)
	plain, _ := newFailSafeHome(t, false, failSafePolicyGood)
	for name, p := range map[string]string{"Gemini run_shell_command": gemini, "Claude Bash": claudeBash} {
		if code, stdout, stderr := runHookChild(t, managed, p); code != 2 {
			t.Errorf("%s, string tool_input, managed fail_closed: exit %d stdout %q, want 2 (fail-safe): %s", name, code, stdout, stderr)
		}
		code, stdout, stderr := runHookChild(t, plain, p)
		if code != 0 || !strings.Contains(stderr, "hook input parse failed") || strings.Contains(stdout, `"allow"`) {
			t.Errorf("%s, string tool_input: exit %d stdout %q stderr %q; want the fail-safe warning, never an allow verdict", name, code, stdout, stderr)
		}
	}
}

// TestNativeDialectCheckedAfterCursorAndWindsurf (#4251 review, follow-up 1):
// a stray toolName key on a Cursor or Windsurf payload must not reroute it to
// the Copilot handler — its shell command is still evaluated (and blocked).
func TestNativeDialectCheckedAfterCursorAndWindsurf(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	cursor := `{"command":"` + destructiveShell() + `","cwd":"/repo","toolName":"x"}`
	windsurf := `{"agent_action_name":"pre_run_command","tool_info":{"command_line":"` + destructiveShell() + `","cwd":"/repo"},"toolName":"x"}`
	// Each harness's own block signal: Cursor answers in JSON on exit 0,
	// Windsurf exits 2. Rerouted to the Copilot handler, neither appears.
	if _, stdout, stderr := runHookChild(t, home, cursor); !strings.Contains(stdout, `"permission":"deny"`) {
		t.Errorf("Cursor payload with a stray toolName: stdout %q (stderr %q), want Cursor's deny verdict", stdout, stderr)
	}
	if code, stdout, stderr := runHookChild(t, home, windsurf); code != 2 {
		t.Errorf("Windsurf payload with a stray toolName: exit %d (stdout %q, stderr %q), want 2", code, stdout, stderr)
	}
}

// TestAgentIDEnvTakesPrecedence pins the documented precedence: the hook
// entry's AGENTSHIELD_AGENT_ID names the harness, ahead of Codex's turn_id.
func TestAgentIDEnvTakesPrecedence(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	p := `{"session_id":"pr1","turn_id":"t","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo a"}}`
	if code, _, stderr := runHookChild(t, home, p, "AGENTSHIELD_AGENT_ID=copilot-cli"); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if ev := auditBySession(t, configDir, "pr1"); len(ev) == 0 || ev[0].Source != "copilot-cli-hook" {
		t.Errorf("source = %v, want copilot-cli-hook (env ahead of turn_id)", ev)
	}
}

// TestManagedHostProtectsCopilotHookFile (#4251 review, finding 2): on a
// managed host, deleting the Copilot hook file through the shell is blocked
// exactly as deleting Claude Code's or Codex's hook config is.
func TestManagedHostProtectsCopilotHookFile(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	rmHook := "rm " + "~/.copilot/hooks/" + "agentshield.json"
	code, stdout, stderr := runHookChild(t, home, copilotCompatPayload(t, "sp1", "Bash", shellArgs(rmHook)), "AGENTSHIELD_AGENT_ID=copilot-cli")
	requireCopilotDeny(t, "rm of the Copilot hook file on a managed host", code, stdout, stderr, "enterprise-self-protect")
}
