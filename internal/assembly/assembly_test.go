package assembly

import (
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
