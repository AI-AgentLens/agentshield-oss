package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// withFakeHomeForCheck mirrors the helper in mcp_policy_test.go but resets
// the check command's flag globals too.
func withFakeHomeForCheck(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldPolicyPath, oldLogPath, oldMode := policyPath, logPath, mode
	oldShell, oldCheckPolicy, oldFixture, oldFormat := checkShell, checkPolicyPath, checkFixture, checkFormat
	t.Cleanup(func() {
		policyPath, logPath, mode = oldPolicyPath, oldLogPath, oldMode
		checkShell, checkPolicyPath, checkFixture, checkFormat = oldShell, oldCheckPolicy, oldFixture, oldFormat
	})
	policyPath, logPath, mode = "", "", "enforce"
	checkShell, checkPolicyPath, checkFixture, checkFormat = "", "", "", "text"

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

// TestEvaluateShellCommand_RespectsEnforcementMode — the `agentshield check`
// command's whole job is to be a faithful predictor of what the production
// hook will do. Before this fix, a developer testing their policy with
// `check` would see BLOCK on a rule that audit-only mode would actually
// downgrade to AUDIT — the dev-loop lying about production behavior, which
// is the worst possible failure for a verification tool. Issue #1952,
// caught while running the 2026-05-17 end-to-end binary test.
func TestEvaluateShellCommand_RespectsEnforcementMode(t *testing.T) {
	home := withFakeHomeForCheck(t)

	// withFakeHomeForCheck defaults the CLI mode flag to "enforce" which
	// would win over policy.yaml's enforcement_mode (rung 1 > rung 3). For
	// this test we want to exercise the resolution falling through to
	// rung 3, so clear the CLI flag explicitly.
	mode = ""

	// Policy.yaml with enforcement_mode: audit-only + a BLOCK rule.
	// Mimics what aiagentlens emits via /api/policy/yaml when an org has
	// the Settings toggle flipped to audit-only.
	writePolicyFile(t, home, ".agentshield/policy.yaml", `version: "0.1"
enforcement_mode: "audit-only"

rules:
  - id: e2e-check-block-telnet
    match:
      command_prefix:
        - "telnet "
    decision: "BLOCK"
    reason: "Plaintext telnet detected."
`)

	result, err := evaluateShellCommand("telnet legacy-router 23", "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision != policy.DecisionAudit {
		t.Errorf("decision = %s, want AUDIT (the BLOCK rule should have been "+
			"downgraded by audit-only mode — if BLOCK, `check` is still ignoring "+
			"the policy.yaml enforcement_mode field and lying about what the "+
			"production hook would do)", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("original_decision = %q, want BLOCK (would-have-blocked signal "+
			"is the value the SaaS dashboard renders as the audit-only badge)",
			result.OriginalDecision)
	}
}

// TestEvaluateShellCommand_CLIModeOverridesPolicyYaml — the CLI flag wins.
// An operator using `agentshield check --mode=enforce` to break-glass-verify
// a rule must see the BLOCK result even when the local policy.yaml carries
// enforcement_mode: audit-only. Without this, the dev-loop can't be used to
// confirm an enforce-mode block before flipping the SaaS toggle.
func TestEvaluateShellCommand_CLIModeOverridesPolicyYaml(t *testing.T) {
	home := withFakeHomeForCheck(t)
	writePolicyFile(t, home, ".agentshield/policy.yaml", `version: "0.1"
enforcement_mode: "audit-only"

rules:
  - id: e2e-check-block-telnet
    match:
      command_prefix:
        - "telnet "
    decision: "BLOCK"
    reason: "Plaintext telnet detected."
`)

	// Simulate the CLI's --mode=enforce flag by setting the package-level
	// `mode` global that withFakeHomeForCheck saved + restores.
	mode = "enforce"

	result, err := evaluateShellCommand("telnet legacy-router 23", "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision != policy.DecisionBlock {
		t.Errorf("decision = %s, want BLOCK — the --mode=enforce CLI flag MUST "+
			"override the SaaS-pushed policy.yaml enforcement_mode (precedence "+
			"rung 1 > rung 3). Without this guarantee, operator break-glass is "+
			"broken.", result.Decision)
	}
	if result.OriginalDecision != "" {
		t.Errorf("enforce mode must NOT carry OriginalDecision; got %q",
			result.OriginalDecision)
	}
}

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

// TestEvaluateShellCommand_ProtectedPathFiresViaCheck — regression test for the
// pre-#1700 bug where `agentshield check` returned ALLOW for a command that
// the IDE hook correctly BLOCKED. Root cause: `check` wrapped the entire
// command string into a single `args[]` element before calling the normalizer,
// so the path-extraction state machine never saw the path as a separate token.
// Result: `paths=[]` flowed into the engine, `checkProtectedPaths` had nothing
// to match against, the protected-paths defaults were silently bypassed, and
// `ts-allow-readonly` fell through to ALLOW.
//
// The cases below all reference `protected_paths` entries that are NOT covered
// by any explicit `command_regex` rule in the community packs. If the path
// extraction breaks again, these flip from BLOCK back to ALLOW and this test
// catches it.
func TestEvaluateShellCommand_ProtectedPathFiresViaCheck(t *testing.T) {
	withFakeHomeForCheck(t)

	cases := []struct {
		name    string
		command string
	}{
		{"1password-config", "cat ~/.config/op/config"},
		{"age-key", "cat ~/.age/key.txt"},
		{"linux-keyring", "cat ~/.local/share/keyrings/login.keyring"},
		{"copilot-config", "cat ~/.config/github-copilot/hosts.json"},
		// issue #2813: inline quote-splice must still resolve through the
		// protected-path check. The shell removes the empty-quote pairs, so
		// ~/.a'g'e/ke'y'.txt opens ~/.age/key.txt; pathnorm.StripShellQuotes in
		// normalize.expandPath collapses it before checkProtectedPaths. If the
		// quote stripping regresses, these flip to ALLOW like the pre-fix bypass.
		// The SSH case is the headline exploit: the quoted spelling also dodges
		// the sec-block-ssh-private regex, so protected-path is the only catcher.
		{"age-key-quote-splice", `cat ~/.a'g'e/ke'y'.txt`},
		{"ssh-key-quote-splice", `cat ~/.ss'h'/id_r'sa'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := evaluateShellCommand(tc.command, "")
			if err != nil {
				t.Fatalf("evaluateShellCommand: %v", err)
			}
			if result.Decision != policy.DecisionBlock {
				t.Errorf("decision = %s, want BLOCK (protected-path should fire); rules=%v",
					result.Decision, result.TriggeredRules)
			}
			if !slices.Contains(result.TriggeredRules, "protected-path") {
				t.Errorf("TriggeredRules = %v, expected to include 'protected-path' "+
					"(if a different rule is firing the verdict happens to match but the "+
					"check/hook parity is still broken — see issue #1700)",
					result.TriggeredRules)
			}
		})
	}
}

// TestEvaluateShellCommand_FPRegression_MultilineQuoteMisattribution — issue
// #2831. A legitimate `rm -rf "$(cmd)"` temp-cleanup line, followed later in
// the same multi-line script by an unrelated `for...done` loop containing a
// nested `python3 -c "..."` block, was falsely BLOCKed.
//
// Root cause: both check.go and hook.go used to tokenize the raw command with
// strings.Fields (quote-blind) and rejoin with single spaces before handing
// it to the AST parser. That round-trip collapses embedded newlines inside a
// multi-line quoted argument into spaces, which can delete a statement
// separator the shell depends on (here, the newline before `done`). The
// mangled one-liner then fails to parse as valid shell, mvdan.cc/sh falls
// back to a naive single-segment tokenizer, and a stray quote character from
// deep in the script gets misattributed to `rm`'s argument list — which
// normalizes to "" and trips the root-target check. Fixed by parsing the AST
// from the original, unmodified command string (normalize.NormalizeCommand)
// instead of a whitespace-collapsed reconstruction.
func TestEvaluateShellCommand_FPRegression_MultilineQuoteMisattribution(t *testing.T) {
	withFakeHomeForCheck(t)

	// The nested `'"'"'` sequences are bash's escaped-single-quote idiom for
	// embedding a literal `'` in an argument — realistic for scripts that pass
	// single-quoted Python string literals through a python3 -c "..." body.
	command := "rm -rf \"$(cat /tmp/foo.txt)\"\n" +
		"for f in a.yaml b.yaml; do\n" +
		"  python3 -c \"\n" +
		"print('" + `"'"'` + "x" + `'"'"'` + ")\n" +
		"\"\n" +
		"done"

	result, err := evaluateShellCommand(command, "")
	if err != nil {
		t.Fatalf("evaluateShellCommand: %v", err)
	}
	if result.Decision == policy.DecisionBlock {
		t.Errorf("FP: multi-line temp-cleanup + embedded python3 -c script falsely BLOCKed; rules=%v reasons=%v",
			result.TriggeredRules, result.Reasons)
	}
	for _, rule := range result.TriggeredRules {
		if rule == "st-block-rm-recursive-root" {
			t.Errorf("st-block-rm-recursive-root fired on a temp-dir rm -rf, not root: reasons=%v", result.Reasons)
		}
	}
}

// TestEvaluateShellCommand_HookParityFitnessFunction — the engine call from
// `evaluateShellCommand` (used by `check --shell` and `check --fixture`) must
// stay shape-equivalent to the one in cli/hook.go so the dev tool faithfully
// predicts production behavior. This is the fitness function for issue #1700:
// it doesn't enumerate specific verdicts, it asserts the invariant that both
// call sites compute Decision the same way for the same input.
//
// If anyone ever changes one site without the other (e.g., reverts to passing
// the un-tokenized command, or drops the parsed AST), this test fails with a
// clear pointer to where they diverged.
func TestEvaluateShellCommand_HookParityFitnessFunction(t *testing.T) {
	withFakeHomeForCheck(t)

	// Representative panel — at least one case for each behavior the hook
	// path exercises that the pre-fix check path silently bypassed:
	//   - protected_paths defaults (path tokenization required)
	//   - structural rules (parsed AST required)
	//   - regex rules (raw-string match — should work even on broken path)
	//   - benign command (must still ALLOW)
	commands := []string{
		"cat ~/.config/op/config",          // protected-path: tokenization-sensitive
		"cat ~/.age/key.txt",               // protected-path
		"rm -rf /",                         // regex/structural
		"sudo dd if=/dev/zero of=/dev/sda", // structural
		"ls -la",                           // benign baseline
		"echo hello world",                 // benign baseline
		"git status",                       // benign baseline
	}

	for _, cmd := range commands {
		t.Run(cmd, func(t *testing.T) {
			checkResult, err := evaluateShellCommand(cmd, "")
			if err != nil {
				t.Fatalf("evaluateShellCommand: %v", err)
			}
			hookDecision := evaluateViaHookEnginePath(t, cmd)
			if checkResult.Decision != hookDecision {
				t.Errorf("parity violation for %q: check=%s, hook=%s\n"+
					"check is supposed to be a faithful predictor of hook behavior. "+
					"See cli/check.go:evaluateShellCommand and cli/hook.go around the "+
					"engine.EvaluateWithParsed call site — both must tokenize args via "+
					"strings.Fields and pass the parsed AST.",
					cmd, checkResult.Decision, hookDecision)
			}
		})
	}
}

// evaluateViaHookEnginePath replicates exactly what cli/hook.go does at the
// engine evaluation layer (skipping enterprise pre-eval middleware, which is
// hook-only by design). Kept verbose and inline so a future change to the hook
// path requires the author to mirror it here, surfacing the divergence.
func evaluateViaHookEnginePath(t *testing.T, command string) policy.Decision {
	t.Helper()
	pol, _, err := loadCheckPolicy("")
	if err != nil {
		t.Fatalf("loadCheckPolicy: %v", err)
	}
	engine, err := policy.NewEngineWithAnalyzers(pol, defaultMaxParseDepth())
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}
	cmdArgs := strings.Fields(command)
	normalized := normalize.Normalize(cmdArgs, "")
	return engine.EvaluateWithParsed(command, normalized.Paths, normalized.Parsed).Decision
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

// TestPrintShellResultJSON_RoundTrip — `--format=json` is the contract the
// SaaS playground depends on. Output must be valid JSON that round-trips
// back into EvalResult. Lock in the field names (decision/rules/reasons)
// so a future struct rename can't silently break the playground API.
func TestPrintShellResultJSON_RoundTrip(t *testing.T) {
	in := policy.EvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"block-rm-root"},
		Reasons:        []string{"Destructive remove at filesystem root."},
	}
	var buf bytes.Buffer
	if err := printShellResultJSON(&buf, in); err != nil {
		t.Fatalf("printShellResultJSON: %v", err)
	}

	var out policy.EvalResult
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if out.Decision != in.Decision {
		t.Errorf("decision = %s, want %s", out.Decision, in.Decision)
	}
	if !slices.Equal(out.TriggeredRules, in.TriggeredRules) {
		t.Errorf("rules = %v, want %v", out.TriggeredRules, in.TriggeredRules)
	}
	if !slices.Equal(out.Reasons, in.Reasons) {
		t.Errorf("reasons = %v, want %v", out.Reasons, in.Reasons)
	}

	// Field-name pin: the playground frontend reads these exact keys.
	for _, key := range []string{`"decision"`, `"rules"`, `"reasons"`} {
		if !strings.Contains(buf.String(), key) {
			t.Errorf("output missing JSON field %s\n%s", key, buf.String())
		}
	}
}

// --- #3302: --shell-file, the diagnosis path the hook cannot block ---

// resetCheckFlags clears the check command's flag globals. They are package
// vars bound by cobra, so a test that sets one leaks into every later test in
// this package unless it is put back.
func resetCheckFlags(t *testing.T) {
	t.Helper()
	prevShell, prevFile, prevFixture := checkShell, checkShellFile, checkFixture
	checkShell, checkShellFile, checkFixture = "", "", ""
	t.Cleanup(func() { checkShell, checkShellFile, checkFixture = prevShell, prevFile, prevFixture })
}

func TestResolveShellFile_ReadsCommandFromFile(t *testing.T) {
	resetCheckFlags(t)
	path := filepath.Join(t.TempDir(), "blocked.txt")
	if err := os.WriteFile(path, []byte("rm -rf /"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkShellFile = path
	if err := resolveShellFile(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if checkShell != "rm -rf /" {
		t.Errorf("expected checkShell to be filled from the file, got %q", checkShell)
	}
}

// A single trailing newline is what every editor adds; stripping it is the
// difference between "works" and "why does my file behave differently from
// --shell". Exactly one is stripped, and nothing else is touched.
func TestResolveShellFile_StripsOneTrailingNewlineOnly(t *testing.T) {
	for name, tc := range map[string]struct{ content, want string }{
		"lf":              {"rm -rf /\n", "rm -rf /"},
		"crlf":            {"rm -rf /\r\n", "rm -rf /"},
		"none":            {"rm -rf /", "rm -rf /"},
		"two lf":          {"rm -rf /\n\n", "rm -rf /\n"},
		"leading spaces":  {"   rm -rf /", "   rm -rf /"},
		"interior spaces": {"rm  -rf   /", "rm  -rf   /"},
		"multiline":       {"cd /tmp\nrm -rf /\n", "cd /tmp\nrm -rf /"},
	} {
		t.Run(name, func(t *testing.T) {
			resetCheckFlags(t)
			path := filepath.Join(t.TempDir(), "c.txt")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			checkShellFile = path
			if err := resolveShellFile(); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if checkShell != tc.want {
				t.Errorf("content %q -> got %q, want %q", tc.content, checkShell, tc.want)
			}
		})
	}
}

// Leading whitespace and interior spacing survive on purpose, and the case
// above pins it: command_position_exclude and the per-statement anchored-regex
// retry both key on where text sits in the command, so a --shell-file that
// quietly reformatted its input would be a less faithful predictor of the hook
// than --shell. That would defeat the reason this flag exists.
func TestResolveShellFile_MutualExclusion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.txt")
	if err := os.WriteFile(path, []byte("rm -rf /"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("with --shell", func(t *testing.T) {
		resetCheckFlags(t)
		checkShellFile, checkShell = path, "ls"
		err := resolveShellFile()
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("expected a mutual-exclusion error, got %v", err)
		}
	})
	t.Run("with --fixture", func(t *testing.T) {
		resetCheckFlags(t)
		checkShellFile, checkFixture = path, "f.yaml"
		err := resolveShellFile()
		if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("expected a mutual-exclusion error, got %v", err)
		}
	})
}

func TestResolveShellFile_ErrorCases(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		resetCheckFlags(t)
		checkShellFile = filepath.Join(t.TempDir(), "nope.txt")
		if err := resolveShellFile(); err == nil {
			t.Error("expected an error for a nonexistent file")
		}
	})
	// An empty or whitespace-only file must be an error, not an empty command.
	// Evaluating "" returns the default decision, which reads as "AgentShield
	// says this is fine" — a wrong answer delivered confidently.
	for name, content := range map[string]string{"empty": "", "whitespace": "  \n\t\n"} {
		t.Run(name, func(t *testing.T) {
			resetCheckFlags(t)
			path := filepath.Join(t.TempDir(), "c.txt")
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			checkShellFile = path
			err := resolveShellFile()
			if err == nil || !strings.Contains(err.Error(), "no command") {
				t.Errorf("expected a 'no command' error, got %v", err)
			}
		})
	}
	t.Run("unset is a no-op", func(t *testing.T) {
		resetCheckFlags(t)
		checkShell = "ls"
		if err := resolveShellFile(); err != nil {
			t.Errorf("unset --shell-file should do nothing, got %v", err)
		}
		if checkShell != "ls" {
			t.Errorf("--shell must survive untouched, got %q", checkShell)
		}
	})
}

// TestResolveShellFile_ParityWithShellFlag is the claim that matters: a command
// read from a file must evaluate identically to the same command passed inline.
// If the two paths ever diverge, --shell-file becomes a diagnostic that lies
// about the thing it was built to diagnose.
func TestResolveShellFile_ParityWithShellFlag(t *testing.T) {
	withFakeHomeForCheck(t)
	for _, cmdStr := range []string{
		"rm -rf /",
		"cd /tmp && rm -rf /",
		"  rm -rf /",
		"echo ok",
	} {
		t.Run(cmdStr, func(t *testing.T) {
			inline, err := evaluateShellCommand(cmdStr, "")
			if err != nil {
				t.Fatalf("inline: %v", err)
			}
			resetCheckFlags(t)
			path := filepath.Join(t.TempDir(), "c.txt")
			if err := os.WriteFile(path, []byte(cmdStr+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			checkShellFile = path
			if err := resolveShellFile(); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			fromFile, err := evaluateShellCommand(checkShell, "")
			if err != nil {
				t.Fatalf("from file: %v", err)
			}
			if inline.Decision != fromFile.Decision {
				t.Errorf("decision diverged: inline=%s file=%s", inline.Decision, fromFile.Decision)
			}
			if !slices.Equal(inline.TriggeredRules, fromFile.TriggeredRules) {
				t.Errorf("rules diverged:\n  inline=%v\n  file  =%v", inline.TriggeredRules, fromFile.TriggeredRules)
			}
		})
	}
}
