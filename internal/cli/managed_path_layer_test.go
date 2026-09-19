package cli

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Path layer of #3620, end to end through evaluateCommand and the real hook.
// Helpers live in fail_safe_test.go.

const policyProtectingSSH = `version: "0.1"
defaults:
  decision: "AUDIT"
  protected_paths: ["~/.ssh/**"]
rules: []
`

// TestProtectedPaths_SeeHomeVariableAndInterpreterLiterals pins the general
// fix: three shapes that exited 0 on 2026-09-02 with protected_paths set.
func TestProtectedPaths_SeeHomeVariableAndInterpreterLiterals(t *testing.T) {
	newFailSafeHome(t, false, policyProtectingSSH)
	cases := []string{
		`P=$HOME/.ssh; cat $P/id_rsa`,
		`P=$HOME/.ssh; python3 -c "print(open('$P/id_rsa').read())"`,
		`python3 -c "print(open('$HOME/.ssh/id_rsa').read())"`,
	}
	for _, cmd := range cases {
		res, _ := evaluateCommand(cmd, "/tmp", "claude-code-hook", "")
		if res.Decision != policy.DecisionBlock {
			t.Errorf("not blocked: %s\n  rules=%v", cmd, res.TriggeredRules)
			continue
		}
		joined := strings.Join(res.TriggeredRules, ",")
		if !strings.Contains(joined, "protected-path") {
			t.Errorf("blocked, but not by the protected-path check: %s → %v", cmd, res.TriggeredRules)
		}
	}
	// Control: mentioning the path is not accessing it.
	doc, _ := evaluateCommand(`python3 -c "print('see ~/.ssh/id_rsa for the key')"`, "/tmp", "claude-code-hook", "")
	if strings.Contains(strings.Join(doc.TriggeredRules, ","), "protected-path") {
		t.Errorf("doc-text mention of a protected path was blocked as an access: %v", doc.TriggeredRules)
	}
}

// TestManagedMode_ConfigDirIsProtectedByPath is the managed half: the config
// directory becomes a protected path for every command that is not a plain
// read, so a write that names the directory nowhere in its text is caught.
func TestManagedMode_ConfigDirIsProtectedByPath(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)

	blocked := []string{
		`CFG=$HOME/.agentshield; python3 -c "open('$CFG/policy.yaml','w').write('disable_rules: [block-rm-root]')"`,
		`D=$HOME/.agentshield; cp /tmp/p.yaml $D/policy.yaml`,
		`cd ` + home + `/.agentshield && python3 -c "open('policy.yaml','w').write('x')"`,
	}
	for _, cmd := range blocked {
		res, _ := evaluateCommand(cmd, home, "claude-code-hook", "")
		if res.Decision != policy.DecisionBlock {
			t.Errorf("managed host, not blocked: %s\n  rules=%v", cmd, res.TriggeredRules)
		}
	}

	allowed := []string{
		`cat ` + home + `/.agentshield/policy.yaml`,
		`tail -n 5 ` + home + `/.agentshield/audit.jsonl`,
		`ls -la ` + home + `/.agentshield`,
	}
	for _, cmd := range allowed {
		res, _ := evaluateCommand(cmd, home, "claude-code-hook", "")
		if res.Decision == policy.DecisionBlock {
			t.Errorf("plain read blocked on a managed host: %s → %v", cmd, res.Reasons)
		}
	}

	// Unmanaged control: the same variable-indirected write is not a
	// protected-path hit, so the test is measuring the managed guard.
	newFailSafeHome(t, false, failSafePolicyGood)
	res, _ := evaluateCommand(blocked[0], home, "claude-code-hook", "")
	if strings.Contains(strings.Join(res.TriggeredRules, ","), "protected-path") {
		t.Errorf("unmanaged control: config dir treated as protected: %v", res.TriggeredRules)
	}
}

// TestHook_ManagedVariableIndirectedConfigWrite_ExitsTwo is the exact
// reproduction through the real hook entry point.
func TestHook_ManagedVariableIndirectedConfigWrite_ExitsTwo(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	payload := `{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"t1","tool_input":{"command":"CFG=$HOME/.agentshield; python3 -c \"open('$CFG/policy.yaml','w').write('disable_rules: [block-rm-root]')\""}}`
	code, stderr := runHookInChildProcess(t, home, payload)
	if code != 2 {
		t.Fatalf("hook exit code = %d; want 2. stderr:\n%s", code, stderr)
	}
}
