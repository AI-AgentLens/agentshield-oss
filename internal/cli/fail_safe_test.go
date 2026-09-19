package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// These tests pin the error-to-decision boundary (#3619). Each one drives
// evaluateCommand — the function every harness handler calls — through a
// specific evaluation failure and asserts the DECISION, not the error, because
// the error is what used to leak out as a silent allow.
//
// The policy with a typo'd intent label is the canonical trigger: the pipeline
// deliberately refuses to build on an unknown label ("fail loud"), and before
// #3619 that refusal became `return nil // fail open` in every dialect.

const failSafePolicyBadLabel = `version: "0.1"
defaults:
  decision: "AUDIT"
rules:
  - id: "fail-safe-test-bad-label"
    match:
      command_regex: "^zzz-never-matches-anything"
      command_intent_exclude: ["bogus_label_typo"]
    decision: "AUDIT"
    reason: "carries an invalid intent label so engine construction fails"
`

const failSafePolicyGood = `version: "0.1"
defaults:
  decision: "AUDIT"
rules: []
`

// newFailSafeHome points HOME at a fresh directory holding the given
// policy.yaml and, when managed is true, a managed.json with fail_closed set.
// It also pins the package-level flag variables to their defaults so config
// resolution goes through HOME.
func newFailSafeHome(t *testing.T, managed bool, policyYAML string) (home, configDir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	configDir = filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if managed {
		managedJSON := `{"managed": true, "fail_closed": true}`
		if err := os.WriteFile(filepath.Join(configDir, "managed.json"), []byte(managedJSON), 0o600); err != nil {
			t.Fatalf("WriteFile managed.json: %v", err)
		}
	}
	if policyYAML != "" {
		if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policyYAML), 0o600); err != nil {
			t.Fatalf("WriteFile policy.yaml: %v", err)
		}
	}
	prevPolicy, prevLog, prevMode := policyPath, logPath, mode
	policyPath, logPath, mode = "", "", ""
	t.Cleanup(func() { policyPath, logPath, mode = prevPolicy, prevLog, prevMode })
	return home, configDir
}

func readFailSafeAuditLog(t *testing.T, configDir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(configDir, "audit.jsonl"))
	if err != nil {
		return ""
	}
	return string(data)
}

func TestFailSafeDecision_EngineInitBlocksUnderManagedFailClosed(t *testing.T) {
	_, configDir := newFailSafeHome(t, true, failSafePolicyBadLabel)

	result, event := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "sess-3619")

	if result.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK — engine init failed under managed fail_closed and the command was not blocked (this is the #3619 fail-open)", result.Decision)
	}
	if !containsStr(result.TriggeredRules, failClosedRuleID) {
		t.Errorf("TriggeredRules = %v; want %q so the block is attributable to the boundary, not to a rule", result.TriggeredRules, failClosedRuleID)
	}
	if event == nil {
		t.Fatal("event = nil; the boundary must produce an audit event so the failure is visible")
	}
	if event.Decision != "BLOCK" || !event.Flagged {
		t.Errorf("event Decision/Flagged = %q/%v; want BLOCK/true", event.Decision, event.Flagged)
	}
	if !strings.Contains(event.Error, "unknown intent label") {
		t.Errorf("event.Error = %q; want the engine-init error carried on the event", event.Error)
	}
	if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, failClosedRuleID) {
		t.Errorf("audit.jsonl does not record the fail-closed block:\n%s", log)
	}
}

func TestFailSafeDecision_AuditLogInitBlocksUnderManagedFailClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permission bits")
	}
	_, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	auditPath := filepath.Join(configDir, "audit.jsonl")
	if err := os.WriteFile(auditPath, nil, 0o000); err != nil {
		t.Fatalf("WriteFile audit.jsonl: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(auditPath, 0o600) })

	result, event := evaluateCommand("rm -rf /", "/tmp", "cursor-hook", "")

	if result.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK — an unwritable audit log under managed fail_closed must block, not allow unlogged", result.Decision)
	}
	if !containsStr(result.TriggeredRules, failClosedRuleID) {
		t.Errorf("TriggeredRules = %v; want %q", result.TriggeredRules, failClosedRuleID)
	}
	if event == nil || event.Error == "" {
		t.Errorf("event = %+v; want a non-nil event carrying the logger error even though it could not be written", event)
	}
}

func TestFailSafeDecision_PolicyLoadBlocksUnderManagedFailClosed(t *testing.T) {
	newFailSafeHome(t, true, "rules: [\n") // unparseable YAML

	result, _ := evaluateCommand("rm -rf /", "/tmp", "windsurf-hook", "")

	if result.Decision != policy.DecisionBlock || !containsStr(result.TriggeredRules, failClosedRuleID) {
		t.Fatalf("Decision/TriggeredRules = %v/%v; want BLOCK via %q", result.Decision, result.TriggeredRules, failClosedRuleID)
	}
}

func TestFailSafeDecision_EngineInitIsFlaggedAuditWhenNotManaged(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyBadLabel)

	result, event := evaluateCommand("rm -rf /", "/tmp", "gemini-cli-hook", "")

	if result.Decision != policy.DecisionAudit {
		t.Fatalf("Decision = %v; want AUDIT — outside managed fail_closed the fail-safe default applies, not BLOCK and not a bare error", result.Decision)
	}
	if !containsStr(result.TriggeredRules, evalErrorRuleID) {
		t.Errorf("TriggeredRules = %v; want %q so the audit entry says WHY it was not enforced", result.TriggeredRules, evalErrorRuleID)
	}
	if event == nil || !event.Flagged || event.Error == "" {
		t.Fatalf("event = %+v; want a flagged event carrying the error — the whole point is that the failure is no longer silent", event)
	}
	if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, evalErrorRuleID) {
		t.Errorf("audit.jsonl does not record the evaluation error:\n%s", log)
	}
}

// TestFailSafeDecision_DoesNotFireOnHealthyEvaluation is the negative control:
// with a valid policy the boundary must stay out of the way — a destructive
// command is blocked by rules (not by the sentinel) and a benign one passes.
func TestFailSafeDecision_DoesNotFireOnHealthyEvaluation(t *testing.T) {
	newFailSafeHome(t, true, failSafePolicyGood)

	blocked, _ := evaluateCommand("rm -rf /", "/tmp", "claude-code-hook", "")
	if blocked.Decision != policy.DecisionBlock {
		t.Fatalf("control: Decision = %v; want BLOCK from the embedded community rules", blocked.Decision)
	}
	if len(blocked.TriggeredRules) == 0 || containsStr(blocked.TriggeredRules, failClosedRuleID) || containsStr(blocked.TriggeredRules, evalErrorRuleID) {
		t.Errorf("control: TriggeredRules = %v; want real rule ids and neither boundary sentinel", blocked.TriggeredRules)
	}

	benign, _ := evaluateCommand("ls -la", "/tmp", "claude-code-hook", "")
	if benign.Decision == policy.DecisionBlock {
		t.Fatalf("benign: Decision = BLOCK for `ls -la`; rules = %v", benign.TriggeredRules)
	}
	if containsStr(benign.TriggeredRules, failClosedRuleID) || containsStr(benign.TriggeredRules, evalErrorRuleID) {
		t.Errorf("benign: boundary sentinel present on a healthy evaluation: %v", benign.TriggeredRules)
	}
}

// TestHelperHookProcess is the re-exec target for the exit-code tests below.
// It runs the real `agentshield hook` entry point on stdin and exits with the
// code the harness would see. It is a no-op unless invoked by the parent.
func TestHelperHookProcess(t *testing.T) {
	if os.Getenv("AGENTSHIELD_FAILSAFE_HOOK_HELPER") != "1" {
		return
	}
	if err := hookCommand(nil, nil); err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
	os.Exit(0)
}

// runHookInChildProcess executes the hook entry point in a child process with
// HOME pointed at home and the given Claude Code payload on stdin, returning
// the exit code and stderr. Exit code is the only contract a harness sees, so
// it is what the regression test must assert on.
func runHookInChildProcess(t *testing.T, home, payload string) (exitCode int, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Env = append(os.Environ(), "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home)
	cmd.Stdin = strings.NewReader(payload)
	var errBuf strings.Builder
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return 0, errBuf.String()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), errBuf.String()
	}
	t.Fatalf("running hook helper: %v", err)
	return -1, ""
}

const claudeCodePayloadDestructive = `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"exit-code-test","tool_input":{"command":"rm -rf /"}}`

// TestHook_EngineInitFailure_ExitsTwoUnderManagedFailClosed is the end-to-end
// regression for #3619: the exact reproduction (managed fail_closed, one
// invalid intent label, `rm -rf /`) must exit 2 through the real hook.
func TestHook_EngineInitFailure_ExitsTwoUnderManagedFailClosed(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyBadLabel)

	code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)

	if code != 2 {
		t.Fatalf("hook exit code = %d; want 2 (BLOCK). stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "fail_closed") {
		t.Errorf("stderr does not explain the fail-closed block:\n%s", stderr)
	}
}

// TestHook_EngineInitFailure_ExitsZeroButWarnsWhenNotManaged pins the other
// half of the contract: outside managed mode the command still runs (exit 0),
// but the failure is spelled out instead of swallowed.
func TestHook_EngineInitFailure_ExitsZeroButWarnsWhenNotManaged(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyBadLabel)

	code, stderr := runHookInChildProcess(t, home, claudeCodePayloadDestructive)

	if code != 0 {
		t.Fatalf("hook exit code = %d; want 0 (fail-safe AUDIT outside managed mode). stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "evaluated as AUDIT") {
		t.Errorf("stderr does not say the evaluation failed and was not enforced:\n%s", stderr)
	}
	if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, evalErrorRuleID) {
		t.Errorf("audit.jsonl in the child's HOME does not record the evaluation error:\n%s", log)
	}
}
