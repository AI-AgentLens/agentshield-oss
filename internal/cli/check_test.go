package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// withFakeHomeForCheck mirrors the helper in mcp_policy_test.go but resets
// the check command's flag globals too.
func withFakeHomeForCheck(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldPolicyPath, oldLogPath, oldMode := policyPath, logPath, mode
	oldShell, oldCheckPolicy, oldFixture := checkShell, checkPolicyPath, checkFixture
	t.Cleanup(func() {
		policyPath, logPath, mode = oldPolicyPath, oldLogPath, oldMode
		checkShell, checkPolicyPath, checkFixture = oldShell, oldCheckPolicy, oldFixture
	})
	policyPath, logPath, mode = "", "", "policy-only"
	checkShell, checkPolicyPath, checkFixture = "", "", ""

	return home
}

func writePolicyFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// --- Shell evaluation tests ------------------------------------------------

// TestEvaluateShellCommand_BlocksDestructive — the embedded community packs
// must block "rm -rf /" out of the box. This is the demo Reddit users will
// type first; if it doesn't BLOCK, the wedge is broken.
func TestEvaluateShellCommand_BlocksDestructive(t *testing.T) {
	withFakeHomeForCheck(t)

	result, err := evaluateShellCommand("rm -rf /", "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision != policy.DecisionBlock {
		t.Errorf("decision = %s, want BLOCK", result.Decision)
	}
	if len(result.TriggeredRules) == 0 {
		t.Error("expected at least one triggered rule")
	}
}

// TestEvaluateShellCommand_DedupesIdenticalRulesAndReasons — pre-PR, the same
// rule fired three times for "rm -rf /". Lock the dedupe in place.
func TestEvaluateShellCommand_DedupesIdenticalRulesAndReasons(t *testing.T) {
	withFakeHomeForCheck(t)

	result, err := evaluateShellCommand("rm -rf /", "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}

	seen := map[string]bool{}
	for i, rule := range result.TriggeredRules {
		reason := ""
		if i < len(result.Reasons) {
			reason = result.Reasons[i]
		}
		key := rule + "\x00" + reason
		if seen[key] {
			t.Errorf("duplicate (rule, reason) in output: %s — %s", rule, reason)
		}
		seen[key] = true
	}
}

// TestEvaluateShellCommand_CustomPolicyOverridesDefault — user can supply a
// rule via --policy that fires on a command the default policy does not block.
func TestEvaluateShellCommand_CustomPolicyOverridesDefault(t *testing.T) {
	home := withFakeHomeForCheck(t)
	customPolicy := writePolicyFile(t, home, "custom.yaml", `version: "0.1"
defaults:
  decision: "AUDIT"
rules:
  - id: "block-prod-psql"
    decision: "BLOCK"
    reason: "Production DB access blocked."
    match:
      command_regex: "psql\\s+prod\\."
`)

	result, err := evaluateShellCommand("psql prod.db", customPolicy)
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision != policy.DecisionBlock {
		t.Errorf("decision = %s, want BLOCK from custom rule", result.Decision)
	}
	foundCustom := false
	for _, r := range result.TriggeredRules {
		if r == "block-prod-psql" {
			foundCustom = true
		}
	}
	if !foundCustom {
		t.Errorf("TriggeredRules = %v, expected to include 'block-prod-psql'", result.TriggeredRules)
	}
}

// TestEvaluateShellCommand_READMEOSSLocalRuleExample locks the README_oss.md
// "Add A Local Rule" example. If the docs drift from the CLI policy shape, this
// should fail before a user copies a broken snippet.
func TestEvaluateShellCommand_READMEOSSLocalRuleExample(t *testing.T) {
	home := withFakeHomeForCheck(t)
	policyPath := writePolicyFile(t, filepath.Join(home, ".agentshield"), "policy.yaml", `version: "0.1"
rules:
  - id: block-production-db
    match:
      command_regex: "psql.*prod"
    decision: "BLOCK"
    reason: "Direct production database access is not allowed."
`)

	result, err := evaluateShellCommand("psql prod.db", policyPath)
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision != policy.DecisionBlock {
		t.Errorf("decision = %s, want BLOCK from README local rule", result.Decision)
	}
	if !slices.Contains(result.TriggeredRules, "block-production-db") {
		t.Errorf("TriggeredRules = %v, expected README rule block-production-db", result.TriggeredRules)
	}
	if !slices.Contains(result.Reasons, "Direct production database access is not allowed.") {
		t.Errorf("Reasons = %v, expected README rule reason", result.Reasons)
	}
}

// TestEvaluateShellCommand_NonexistentPolicy_ReturnsError — must not silently
// fall back to embedded; user explicitly named a policy that should be loaded.
func TestEvaluateShellCommand_NonexistentPolicy_ReturnsError(t *testing.T) {
	withFakeHomeForCheck(t)
	_, err := evaluateShellCommand("ls", "/nonexistent/policy.yaml")
	if err == nil {
		t.Fatal("expected error for missing policy file, got nil")
	}
}

func TestPrintShellResult_RendersAllSections(t *testing.T) {
	r := policy.EvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"a", "b"},
		Reasons:        []string{"reason 1", "reason 2"},
	}
	var buf bytes.Buffer
	printShellResult(&buf, r)

	out := buf.String()
	for _, want := range []string{"BLOCK", "Rules: a, b", "Reason: reason 1", "Reason: reason 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// --- Fixture tests ---------------------------------------------------------

func writeFixture(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "fixture.test.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

// TestRunFixtureFile_AllPass — happy path. A fixture with two TP and one TN
// case all behave as expected; report.failed is zero and the case results
// align with the YAML order.
func TestRunFixtureFile_AllPass(t *testing.T) {
	home := withFakeHomeForCheck(t)
	pol := writePolicyFile(t, home, "rule.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "block-rm-root"
    decision: "BLOCK"
    reason: "rm root blocked"
    match:
      command_regex: "rm\\s+-rf\\s+/"
`)
	fixture := writeFixture(t, home, `cases:
  - name: "TP: rm -rf /"
    shell: "rm -rf /"
    expect: BLOCK
  - name: "TN: ls"
    shell: "ls -la"
    expect: ALLOW
`)

	report, err := runFixtureFile(fixture, pol)
	if err != nil {
		t.Fatalf("runFixtureFile: %v", err)
	}
	if report.failed != 0 {
		t.Errorf("failed = %d, want 0; results = %+v", report.failed, report.results)
	}
	if report.passed != 2 {
		t.Errorf("passed = %d, want 2", report.passed)
	}
	if len(report.results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(report.results))
	}
	for _, res := range report.results {
		if !res.pass {
			t.Errorf("case %q failed: expected %s, got %s", res.name, res.expect, res.actual)
		}
	}
}

// TestRunFixtureFile_FailReportsLineNumber — a failing case must surface its
// exact line in the YAML so VS Code's problemMatcher (and humans grepping the
// output) can jump to it.
func TestRunFixtureFile_FailReportsLineNumber(t *testing.T) {
	home := withFakeHomeForCheck(t)
	pol := writePolicyFile(t, home, "rule.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "block-rm-root"
    decision: "BLOCK"
    reason: "rm root blocked"
    match:
      command_regex: "rm\\s+-rf\\s+/"
`)
	// Line 1: cases:
	// Line 2:   - name: "wrong expect"
	// Line 3:     shell: "ls -la"
	// Line 4:     expect: BLOCK   <-- this is wrong; ls is ALLOW
	fixture := writeFixture(t, home, `cases:
  - name: "wrong expect"
    shell: "ls -la"
    expect: BLOCK
`)

	report, err := runFixtureFile(fixture, pol)
	if err != nil {
		t.Fatalf("runFixtureFile: %v", err)
	}
	if report.failed != 1 {
		t.Fatalf("failed = %d, want 1", report.failed)
	}
	if len(report.results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(report.results))
	}
	res := report.results[0]
	if res.line != 2 {
		t.Errorf("line = %d, want 2 (the case start line)", res.line)
	}
	if res.pass {
		t.Error("case should be marked failed")
	}

	// Verify the rendered output contains "path:line: FAIL" — the exact form
	// VS Code's problemMatcher pattern expects.
	var buf bytes.Buffer
	printFixtureReport(&buf, report)
	expected := fixture + ":2: FAIL"
	if !strings.Contains(buf.String(), expected) {
		t.Errorf("output missing %q (so VS Code problemMatcher will not jump correctly)\noutput:\n%s",
			expected, buf.String())
	}
}

// TestRunFixtureFile_PolicyFieldResolvesRelative — fixture's `policy:` field
// must resolve relative to the fixture's own directory, so a rule + its tests
// can ship as a self-contained pair.
func TestRunFixtureFile_PolicyFieldResolvesRelative(t *testing.T) {
	home := withFakeHomeForCheck(t)
	subDir := filepath.Join(home, "myrule")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writePolicyFile(t, subDir, "myrule.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "my-rule"
    decision: "BLOCK"
    reason: "blocked"
    match:
      command_regex: "secret-command"
`)
	fixture := writeFixture(t, subDir, `policy: ./myrule.yaml
cases:
  - name: "TP"
    shell: "secret-command"
    expect: BLOCK
`)

	report, err := runFixtureFile(fixture, "")
	if err != nil {
		t.Fatalf("runFixtureFile: %v", err)
	}
	if report.failed != 0 {
		t.Errorf("failed = %d, want 0; first case actual = %s",
			report.failed, report.results[0].actual)
	}
}

// TestRunFixtureFile_CLIPolicyOverridesFixturePolicy — when both
// --policy and the fixture's policy: field are set, --policy wins. This
// matches the principle of least surprise (CLI always overrides config).
func TestRunFixtureFile_CLIPolicyOverridesFixturePolicy(t *testing.T) {
	home := withFakeHomeForCheck(t)

	fixturePolicy := writePolicyFile(t, home, "fixture-policy.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "fixture-rule"
    decision: "BLOCK"
    reason: "fixture blocked"
    match:
      command_regex: "fixture-cmd"
`)
	cliPolicy := writePolicyFile(t, home, "cli-policy.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "cli-rule"
    decision: "BLOCK"
    reason: "cli blocked"
    match:
      command_regex: "cli-cmd"
`)
	_ = fixturePolicy

	fixture := writeFixture(t, home, `policy: ./fixture-policy.yaml
cases:
  - name: "fires under CLI policy, not fixture policy"
    shell: "cli-cmd"
    expect: BLOCK
  - name: "would fire under fixture policy but should NOT under CLI policy"
    shell: "fixture-cmd"
    expect: ALLOW
`)

	report, err := runFixtureFile(fixture, cliPolicy)
	if err != nil {
		t.Fatalf("runFixtureFile: %v", err)
	}
	if report.failed != 0 {
		t.Errorf("--policy override should win over fixture policy; failed = %d, results = %+v",
			report.failed, report.results)
	}
}

// TestRunFixtureFile_InvalidExpect — a typo in the expect field surfaces as a
// per-case failure, not a fixture-wide error. Lets a developer with one bad
// case still see results from the rest of the fixture.
func TestRunFixtureFile_InvalidExpect(t *testing.T) {
	home := withFakeHomeForCheck(t)
	fixture := writeFixture(t, home, `cases:
  - name: "typo"
    shell: "ls"
    expect: WHATEVER
`)

	report, err := runFixtureFile(fixture, "")
	if err != nil {
		t.Fatalf("runFixtureFile: %v", err)
	}
	if report.failed != 1 {
		t.Errorf("failed = %d, want 1", report.failed)
	}
	if report.results[0].err == nil {
		t.Error("expected per-case error for invalid expect, got nil")
	}
}

// TestParseExpectedDecision_CaseInsensitive — accept BLOCK, block, Block.
func TestParseExpectedDecision_CaseInsensitive(t *testing.T) {
	tests := []struct {
		in   string
		want policy.Decision
	}{
		{"BLOCK", policy.DecisionBlock},
		{"block", policy.DecisionBlock},
		{"  Audit  ", policy.DecisionAudit},
		{"allow", policy.DecisionAllow},
	}
	for _, tt := range tests {
		got, err := parseExpectedDecision(tt.in)
		if err != nil {
			t.Errorf("parseExpectedDecision(%q): %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("parseExpectedDecision(%q) = %s, want %s", tt.in, got, tt.want)
		}
	}
	if _, err := parseExpectedDecision("garbage"); err == nil {
		t.Error("parseExpectedDecision(garbage): want error, got nil")
	}
}
