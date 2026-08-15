package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Audit-only mode tests for the MCP-side PolicyEvaluator (issue #1952).
// Mirrors internal/policy/engine_test.go's TestMode_* suite so that the
// "uniform behavior across IDE hook and MCP proxy" promise from the
// assumptions doc (Q5) is verified, not just claimed.

func modeTestPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"execute_command"},
		BlockedResources: []string{
			"file:///etc/shadow",
		},
		Rules: []MCPRule{
			{
				ID:       "block-file-write-etc",
				Match:    MCPMatch{ToolName: "write_file", ArgumentPatterns: map[string]string{"path": "/etc/**"}},
				Decision: policy.DecisionBlock,
				Reason:   "File write to /etc/ is blocked.",
			},
			{
				ID:       "approval-sudo",
				Match:    MCPMatch{ToolName: "run_sudo"},
				Decision: policy.DecisionRequireApproval,
				Reason:   "sudo requires approval.",
			},
			{
				ID:       "audit-database",
				Match:    MCPMatch{ToolName: "query_db"},
				Decision: policy.DecisionAudit,
				Reason:   "DB queries are audited.",
			},
			{
				ID:       "allow-weather",
				Match:    MCPMatch{ToolName: "get_weather"},
				Decision: policy.DecisionAllow,
				Reason:   "Weather lookups are safe.",
			},
		},
	}
}

func TestMCPMode_DefaultEnforce_BehaviorUnchanged(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	// SetMode never called → default enforce; existing behavior must hold.

	result := e.EvaluateToolCall("execute_command", nil)
	if result.Decision != policy.DecisionBlock {
		t.Errorf("default mode: expected BLOCK, got %v", result.Decision)
	}
	if result.OriginalDecision != "" {
		t.Errorf("default mode: expected empty OriginalDecision, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_DowngradeBlockedTool(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateToolCall("execute_command", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: expected AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only: expected OriginalDecision=BLOCK, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_DowngradeRuleBlock(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateToolCall("write_file", map[string]interface{}{"path": "/etc/passwd"})
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: expected AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only: expected OriginalDecision=BLOCK, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_DowngradeRequireApproval(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateToolCall("run_sudo", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: expected AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionRequireApproval {
		t.Errorf("audit-only: expected OriginalDecision=REQUIRE_APPROVAL, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_AllowUnchanged(t *testing.T) {
	// The MCP evaluator picks the most restrictive of matching rules and the
	// policy default is AUDIT, so an ALLOW outcome never flows from a normal
	// EvaluateToolCall against modeTestPolicy. Test the downgrade helper
	// directly to prove ALLOW is untouched.
	in := MCPEvalResult{Decision: policy.DecisionAllow}
	out := applyMCPModeDowngrade(in, "audit-only")
	if out.Decision != policy.DecisionAllow {
		t.Errorf("audit-only: ALLOW must stay ALLOW, got %v", out.Decision)
	}
	if out.OriginalDecision != "" {
		t.Errorf("audit-only: ALLOW must not carry OriginalDecision, got %q", out.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_AuditUnchanged(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateToolCall("query_db", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: AUDIT must stay AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != "" {
		t.Errorf("audit-only: AUDIT must not carry OriginalDecision (downstream readers rely on non-empty meaning real downgrade), got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_DowngradeResourceRead(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateResourceRead("file:///etc/shadow")
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: expected resource read AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only: expected resource OriginalDecision=BLOCK, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_AuditOnly_DowngradeRootsList_CredDir(t *testing.T) {
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("audit-only")

	result := e.EvaluateRootsList([]RootInfo{{URI: "file:///home/alice/.ssh"}})
	if result.Decision != policy.DecisionAudit {
		t.Errorf("audit-only: expected roots/list AUDIT, got %v", result.Decision)
	}
	if result.OriginalDecision != policy.DecisionBlock {
		t.Errorf("audit-only: expected roots OriginalDecision=BLOCK, got %q", result.OriginalDecision)
	}
}

func TestMCPMode_SetMode_InvalidValueIsEnforce(t *testing.T) {
	// Per the doc on PolicyEvaluator.mode: unknown values are treated as
	// "enforce" so misconfiguration fails safe (continues to block).
	e := NewPolicyEvaluator(modeTestPolicy())
	e.SetMode("loose") // not a recognized mode

	result := e.EvaluateToolCall("execute_command", nil)
	if result.Decision != policy.DecisionBlock {
		t.Errorf("invalid mode must fail safe to enforce → BLOCK, got %v", result.Decision)
	}
	if result.OriginalDecision != "" {
		t.Errorf("invalid mode must not record downgrade, got OriginalDecision=%q", result.OriginalDecision)
	}
}

func TestMCPMode_SetModeOnNilEvaluator_DoesNotPanic(t *testing.T) {
	// SetMode has an explicit nil-guard; verify it.
	var e *PolicyEvaluator
	e.SetMode("audit-only") // must not panic
}
