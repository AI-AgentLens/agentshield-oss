package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

func withFakeHomeForRule(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	oldP, oldL, oldM := policyPath, logPath, mode
	t.Cleanup(func() { policyPath, logPath, mode = oldP, oldL, oldM })
	policyPath, logPath, mode = "", "", "enforce"
	return home
}

func readPolicyFile(t *testing.T, path string) *policy.Policy {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read policy: %v", err)
	}
	var pol policy.Policy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		t.Fatalf("unmarshal policy: %v", err)
	}
	return &pol
}

// TestRule_Disable_AddsToFile — happy path. After `disable foo`, the file
// exists, contains foo in disable_rules, and the engine honors it.
func TestRule_Disable_AddsToFile(t *testing.T) {
	home := withFakeHomeForRule(t)
	policyFile := filepath.Join(home, ".agentshield", "policy.yaml")

	var stdout, stderr bytes.Buffer
	if err := ruleMutate(&stdout, &stderr, "block-rm-root", ruleOpDisable); err != nil {
		t.Fatalf("disable: %v", err)
	}

	pol := readPolicyFile(t, policyFile)
	if !pol.IsRuleDisabled("block-rm-root") {
		t.Errorf("policy.yaml should contain block-rm-root in disable_rules; got %+v", pol.DisableRules)
	}
	if !strings.Contains(stdout.String(), "disabled") {
		t.Errorf("stdout missing confirmation; got: %s", stdout.String())
	}
}

// TestRule_Disable_Idempotent — disable the same rule twice; file must not
// gain duplicate entries.
func TestRule_Disable_Idempotent(t *testing.T) {
	home := withFakeHomeForRule(t)
	policyFile := filepath.Join(home, ".agentshield", "policy.yaml")

	var out, errBuf bytes.Buffer
	for i := 0; i < 2; i++ {
		if err := ruleMutate(&out, &errBuf, "foo", ruleOpDisable); err != nil {
			t.Fatalf("disable iteration %d: %v", i, err)
		}
	}

	pol := readPolicyFile(t, policyFile)
	count := 0
	for _, id := range pol.DisableRules {
		if id == "foo" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("foo appears %d times in disable_rules, want exactly 1", count)
	}
}

// TestRule_Allow_RemovesFromFile — disable then allow; the file no longer
// lists the rule.
func TestRule_Allow_RemovesFromFile(t *testing.T) {
	home := withFakeHomeForRule(t)
	policyFile := filepath.Join(home, ".agentshield", "policy.yaml")

	var out, errBuf bytes.Buffer
	if err := ruleMutate(&out, &errBuf, "foo", ruleOpDisable); err != nil {
		t.Fatalf("disable: %v", err)
	}
	out.Reset()
	if err := ruleMutate(&out, &errBuf, "foo", ruleOpAllow); err != nil {
		t.Fatalf("allow: %v", err)
	}

	pol := readPolicyFile(t, policyFile)
	if pol.IsRuleDisabled("foo") {
		t.Error("foo should not be in disable_rules after allow")
	}
	if !strings.Contains(out.String(), "re-enabled") {
		t.Errorf("stdout missing re-enabled message; got: %s", out.String())
	}
}

// TestRule_Allow_NotPreviouslyDisabled — allowing a rule that was never
// disabled should not error and should print a clear message.
func TestRule_Allow_NotPreviouslyDisabled(t *testing.T) {
	withFakeHomeForRule(t)

	var out, errBuf bytes.Buffer
	if err := ruleMutate(&out, &errBuf, "ghost", ruleOpAllow); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if !strings.Contains(out.String(), "was not disabled") {
		t.Errorf("expected 'was not disabled' message; got: %s", out.String())
	}
}

// TestRule_ManagedMode_RefusesDisable — the load-bearing security test. In
// managed mode, the user (or prompt injection asking the agent to "just
// disable that rule") cannot subvert an admin's policy.
func TestRule_ManagedMode_RefusesDisable(t *testing.T) {
	home := withFakeHomeForRule(t)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"),
		[]byte(`{"managed": true, "fail_closed": true}`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	err := ruleMutate(&out, &errBuf, "block-rm-root", ruleOpDisable)
	if err == nil {
		t.Fatal("expected error in managed mode, got nil")
	}
	if !strings.Contains(err.Error(), "managed") {
		t.Errorf("error message should explain managed mode; got: %v", err)
	}

	// The policy file must NOT have been written.
	if _, err := os.Stat(filepath.Join(configDir, "policy.yaml")); err == nil {
		t.Error("policy.yaml should NOT exist after refused disable in managed mode")
	}
}

// TestRule_PreservesExistingRules — if the user has hand-authored rules,
// disabling something via the subcommand must not drop those rules.
func TestRule_PreservesExistingRules(t *testing.T) {
	home := withFakeHomeForRule(t)
	configDir := filepath.Join(home, ".agentshield")
	policyFile := filepath.Join(configDir, "policy.yaml")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	existing := `version: "0.1"
defaults:
  decision: AUDIT
rules:
  - id: my-custom-rule
    decision: BLOCK
    reason: "custom"
    match:
      command_regex: "secret"
`
	if err := os.WriteFile(policyFile, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	if err := ruleMutate(&out, &errBuf, "noisy-community-rule", ruleOpDisable); err != nil {
		t.Fatalf("disable: %v", err)
	}

	pol := readPolicyFile(t, policyFile)
	if len(pol.Rules) != 1 || pol.Rules[0].ID != "my-custom-rule" {
		t.Errorf("custom rule lost: rules = %+v", pol.Rules)
	}
	if !pol.IsRuleDisabled("noisy-community-rule") {
		t.Error("disable_rules should contain noisy-community-rule")
	}
}

// TestRule_HadComments_WarnsOnRewrite — comment preservation is a v2; the
// user must be told before a write would silently drop their comments.
func TestRule_HadComments_WarnsOnRewrite(t *testing.T) {
	home := withFakeHomeForRule(t)
	configDir := filepath.Join(home, ".agentshield")
	policyFile := filepath.Join(configDir, "policy.yaml")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	withComments := `# This is my carefully tuned policy
version: "0.1"
rules: []
`
	if err := os.WriteFile(policyFile, []byte(withComments), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	if err := ruleMutate(&out, &errBuf, "x", ruleOpDisable); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !strings.Contains(errBuf.String(), "comments") {
		t.Errorf("expected comment-loss warning on stderr; got: %s", errBuf.String())
	}
}

// TestRule_List_PrintsDisabledRules — list reflects disabled state.
func TestRule_List_PrintsDisabledRules(t *testing.T) {
	withFakeHomeForRule(t)

	var sink bytes.Buffer
	if err := ruleMutate(&sink, &sink, "a", ruleOpDisable); err != nil {
		t.Fatal(err)
	}
	if err := ruleMutate(&sink, &sink, "b", ruleOpDisable); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := ruleList(&out); err != nil {
		t.Fatalf("list: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Errorf("list missing entries; got: %s", got)
	}
}

// TestRule_List_EmptyPrintsNotice — empty disable list shows a friendly note,
// not an empty output (which a Reddit user might mistake for a crash).
func TestRule_List_EmptyPrintsNotice(t *testing.T) {
	withFakeHomeForRule(t)
	var out bytes.Buffer
	if err := ruleList(&out); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out.String(), "no rules disabled") {
		t.Errorf("expected friendly empty-list message; got: %q", out.String())
	}
}

// Tests for the BLOCK self-help text moved to
// internal/policy/remediation/remediation_test.go alongside the
// SuggestForShell / SuggestForMCP helpers in PR #1640.
