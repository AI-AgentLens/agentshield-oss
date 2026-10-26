package assembly

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// clearCIEnv blanks every variable execenv.Detect reads, so a test starts
// outside CI even when the suite itself runs in GitHub Actions.
func clearCIEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "BUILDKITE", "JENKINS_URL", "TF_BUILD", "CI"} {
		t.Setenv(v, "")
	}
}

func shellPolicy() *policy.Policy {
	ci := true
	return &policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionAllow},
		Rules: []policy.Rule{
			{ID: "t-block", Match: policy.Match{CommandRegex: `^zzassembly-block\b`}, Decision: policy.DecisionBlock, Reason: "test"},
			{ID: "t-ci-only", Match: policy.Match{CommandRegex: `^zzassembly-ci\b`, Context: &policy.ContextMatch{CI: &ci}}, Decision: policy.DecisionBlock, Reason: "test"},
		},
	}
}

// TestShellEngine_AppliesMode: the mode reaches the engine, so audit-only
// downgrades a BLOCK and records the original (#1952).
func TestShellEngine_AppliesMode(t *testing.T) {
	clearCIEnv(t)
	for _, c := range []struct {
		mode         string
		want, wantOr policy.Decision
	}{
		{"", policy.DecisionBlock, ""},
		{"enforce", policy.DecisionBlock, ""},
		{"audit-only", policy.DecisionAudit, policy.DecisionBlock},
	} {
		engine, err := ShellEngine(shellPolicy(), 0, c.mode)
		if err != nil {
			t.Fatal(err)
		}
		got := engine.Evaluate("zzassembly-block now", nil)
		if got.Decision != c.want || got.OriginalDecision != c.wantOr {
			t.Errorf("mode %q: decision %s (original %q), want %s (original %q)", c.mode, got.Decision, got.OriginalDecision, c.want, c.wantOr)
		}
	}
}

// TestShellEngine_DetectsCIContext: the execution context comes from this
// process's environment (#3291), so a ci-only rule fires in CI and not outside.
func TestShellEngine_DetectsCIContext(t *testing.T) {
	clearCIEnv(t)
	outside, err := ShellEngine(shellPolicy(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := outside.Evaluate("zzassembly-ci now", nil); got.Decision == policy.DecisionBlock {
		t.Errorf("outside CI: ci-only rule fired (%v)", got.TriggeredRules)
	}

	t.Setenv("CI", "true")
	inside, err := ShellEngine(shellPolicy(), 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := inside.Evaluate("zzassembly-ci now", nil); got.Decision != policy.DecisionBlock {
		t.Errorf("inside CI: decision %s, want BLOCK from the ci-only rule", got.Decision)
	}
}

// TestMCPEvaluator_AppliesMode: same contract for the MCP evaluator.
func TestMCPEvaluator_AppliesMode(t *testing.T) {
	pol := &mcp.MCPPolicy{
		Defaults:     mcp.MCPDefaults{Decision: policy.DecisionAllow},
		BlockedTools: []string{"zzassembly_tool"},
	}
	for _, c := range []struct {
		mode         string
		want, wantOr policy.Decision
	}{
		{"", policy.DecisionBlock, ""},
		{"audit-only", policy.DecisionAudit, policy.DecisionBlock},
	} {
		got := MCPEvaluator(pol, c.mode).EvaluateToolCall("zzassembly_tool", nil)
		if got.Decision != c.want || got.OriginalDecision != c.wantOr {
			t.Errorf("mode %q: decision %s (original %q), want %s (original %q)", c.mode, got.Decision, got.OriginalDecision, c.want, c.wantOr)
		}
	}
}

// selfProtectionShellPolicy has BLOCK rules that are self-protection rules by
// each of the shared definition's readings (mcp.ShellSelfProtectionRules: an
// id naming agentshield, the security-tool-tampering taxonomy, a match naming
// AgentShield's configuration directory), and rules that are not.
func selfProtectionShellPolicy() *policy.Policy {
	return &policy.Policy{
		Defaults: policy.Defaults{Decision: policy.DecisionAllow},
		Rules: []policy.Rule{
			{ID: "t-block-agentshield-by-id", Match: policy.Match{CommandRegex: `^zzsp-id\b`}, Decision: policy.DecisionBlock, Reason: "test"},
			{ID: "t-block-by-taxonomy", Taxonomy: "persistence-evasion/defense-evasion/security-tool-tampering", Match: policy.Match{CommandRegex: `^zzsp-tax\b`}, Decision: policy.DecisionBlock, Reason: "test"},
			{ID: "t-block-by-match", Match: policy.Match{CommandRegex: `^zzsp-match\s+\S*\.agentshield\b`}, Decision: policy.DecisionBlock, Reason: "test"},
			{ID: "t-block-plain", Match: policy.Match{CommandRegex: `^zzsp-plain\b`}, Decision: policy.DecisionBlock, Reason: "test"},
			{ID: "t-approve-agentshield", Match: policy.Match{CommandRegex: `^zzsp-approve\b`}, Decision: policy.DecisionRequireApproval, Reason: "test"},
		},
	}
}

// Audit-only mode keeps a BLOCK a self-protection rule decided, as the MCP
// proxies do (#4337 review B1), and downgrades every other BLOCK as before.
// On main the three self-protection rows were AUDIT with original_decision
// BLOCK; the controls decided the same there.
func TestShellEngine_AuditOnlyKeepsSelfProtectionBlock(t *testing.T) {
	clearCIEnv(t)
	cases := []struct {
		name, command string
		enforce       policy.Decision
		audit, auOrig policy.Decision
	}{
		{"self-protection rule by id", "zzsp-id now", policy.DecisionBlock, policy.DecisionBlock, ""},
		{"self-protection rule by taxonomy", "zzsp-tax now", policy.DecisionBlock, policy.DecisionBlock, ""},
		{"self-protection rule by match", "zzsp-match ~/.agentshield/x", policy.DecisionBlock, policy.DecisionBlock, ""},
		// Controls.
		{"control: other BLOCK still downgrades", "zzsp-plain now", policy.DecisionBlock, policy.DecisionAudit, policy.DecisionBlock},
		{"control: REQUIRE_APPROVAL is never kept", "zzsp-approve now", policy.DecisionRequireApproval, policy.DecisionAudit, policy.DecisionRequireApproval},
		{"no-op control: nothing fires", "ls -la", policy.DecisionAllow, policy.DecisionAllow, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enf, err := ShellEngine(selfProtectionShellPolicy(), 0, "enforce")
			if err != nil {
				t.Fatal(err)
			}
			aud, err := ShellEngine(selfProtectionShellPolicy(), 0, "audit-only")
			if err != nil {
				t.Fatal(err)
			}
			e := enf.Evaluate(c.command, nil)
			if e.Decision != c.enforce || e.OriginalDecision != "" {
				t.Fatalf("enforce: %s (original %q, rules %v), want %s", e.Decision, e.OriginalDecision, e.TriggeredRules, c.enforce)
			}
			a := aud.Evaluate(c.command, nil)
			if a.Decision != c.audit || a.OriginalDecision != c.auOrig {
				t.Errorf("audit-only: %s (original %q, rules %v), want %s (original %q)", a.Decision, a.OriginalDecision, a.TriggeredRules, c.audit, c.auOrig)
			}
			if strings.Join(a.TriggeredRules, ",") != strings.Join(e.TriggeredRules, ",") {
				t.Errorf("audit-only rules %v, want enforce mode's %v", a.TriggeredRules, e.TriggeredRules)
			}
		})
	}
}

// Bound 4 on the shell engine (#4395 pass 2, mutant M7): the keep applies to
// a BLOCK only. Under the shipped template policy (configs/default_policy.yaml)
// the default decision is REQUIRE_APPROVAL, and touching an agent's MCP config
// file decides it while the keep's change-to-a-target reading accepts the
// command. Audit-only must still record it as AUDIT with original_decision
// REQUIRE_APPROVAL. The "REQUIRE_APPROVAL is never kept" row above could not
// see a keep that admits REQUIRE_APPROVAL, because nothing there makes the
// keep's predicate true.
func TestShellEngine_AuditOnlyNeverKeepsRequireApproval_TemplatePolicy(t *testing.T) {
	clearCIEnv(t)
	t.Setenv("HOME", t.TempDir())
	command := "touch " + "~/.cursor/" + "mcp.json"
	load := func() *policy.Policy {
		p, err := policy.Load(filepath.Join("..", "..", "configs", "default_policy.yaml"))
		if err != nil {
			t.Fatalf("load template policy: %v", err)
		}
		return p
	}
	if !mcp.ShellSelfProtectionKeep(load())(command, nil, nil) {
		t.Fatal("setup: the keep's predicate must accept the command, or this row cannot see a keep that admits REQUIRE_APPROVAL")
	}
	enf, err := ShellEngine(load(), 0, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	if e := enf.Evaluate(command, nil); e.Decision != policy.DecisionRequireApproval || e.OriginalDecision != "" {
		t.Fatalf("enforce: %s (original %q, rules %v), want REQUIRE_APPROVAL", e.Decision, e.OriginalDecision, e.TriggeredRules)
	}
	aud, err := ShellEngine(load(), 0, "audit-only")
	if err != nil {
		t.Fatal(err)
	}
	if a := aud.Evaluate(command, nil); a.Decision != policy.DecisionAudit || a.OriginalDecision != policy.DecisionRequireApproval {
		t.Errorf("audit-only: %s (original %q, rules %v), want AUDIT (original REQUIRE_APPROVAL)", a.Decision, a.OriginalDecision, a.TriggeredRules)
	}
}
