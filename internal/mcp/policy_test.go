package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func testPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{
			"execute_command",
			"run_shell",
		},
		Rules: []MCPRule{
			{
				ID: "block-file-write-etc",
				Match: MCPMatch{
					ToolName:         "write_file",
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "File write to /etc/ is blocked.",
			},
			{
				ID: "block-ssh-read",
				Match: MCPMatch{
					ToolNameAny:      []string{"read_file", "cat_file"},
					ArgumentPatterns: map[string]string{"path": "/home/*/.ssh/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Access to SSH keys is blocked.",
			},
			{
				ID: "audit-database",
				Match: MCPMatch{
					ToolNameRegex: ".*sql.*|.*query.*|.*database.*",
				},
				Decision: policy.DecisionAudit,
				Reason:   "Database access flagged for review.",
			},
			{
				ID: "allow-get-weather",
				Match: MCPMatch{
					ToolName: "get_weather",
				},
				Decision: policy.DecisionAllow,
				Reason:   "Weather lookups are safe.",
			},
		},
	}
}

func TestEvaluateToolCall_BlockedTool(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("execute_command", map[string]interface{}{"command": "ls"})
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
	if len(result.TriggeredRules) == 0 {
		t.Error("expected triggered rules")
	}
}

func TestEvaluateToolCall_BlockedToolRunShell(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("run_shell", nil)
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
}

func TestEvaluateToolCall_BlockedByRule_FileWriteEtc(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("write_file", map[string]interface{}{
		"path":    "/etc/passwd",
		"content": "root:x:0:0:root:/root:/bin/bash",
	})
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
	if len(result.TriggeredRules) == 0 || result.TriggeredRules[0] != "block-file-write-etc" {
		t.Errorf("expected rule block-file-write-etc, got %v", result.TriggeredRules)
	}
}

func TestEvaluateToolCall_BlockedByRule_SSHRead(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("read_file", map[string]interface{}{
		"path": "/home/user/.ssh/id_rsa",
	})
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
	if len(result.TriggeredRules) == 0 || result.TriggeredRules[0] != "block-ssh-read" {
		t.Errorf("expected rule block-ssh-read, got %v", result.TriggeredRules)
	}
}

func TestEvaluateToolCall_SSHRead_AlternativeTool(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("cat_file", map[string]interface{}{
		"path": "/home/user/.ssh/authorized_keys",
	})
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
}

func TestEvaluateToolCall_AuditByRegex(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("run_sql_query", map[string]interface{}{
		"query": "SELECT * FROM users",
	})
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT, got %v", result.Decision)
	}
	if len(result.TriggeredRules) == 0 || result.TriggeredRules[0] != "audit-database" {
		t.Errorf("expected rule audit-database, got %v", result.TriggeredRules)
	}
}

func TestEvaluateToolCall_AllowExplicit(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("get_weather", map[string]interface{}{
		"location": "NYC",
	})
	// Default is AUDIT, but explicit ALLOW rule matches — since AUDIT > ALLOW in severity,
	// the default wins unless the rule upgrades severity. Here the tool matches an ALLOW rule
	// but the default is AUDIT, so result should be AUDIT (default).
	// Actually: the rule matches and the decision is ALLOW which is lower severity than default AUDIT.
	// Our logic picks highest severity, so AUDIT (default) should remain.
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (default wins over ALLOW rule), got %v", result.Decision)
	}
}

func TestEvaluateToolCall_DefaultDecision(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("some_unknown_tool", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (default), got %v", result.Decision)
	}
	if len(result.TriggeredRules) != 0 {
		t.Errorf("expected no triggered rules, got %v", result.TriggeredRules)
	}
}

func TestEvaluateToolCall_WriteFileSafePath(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	result := e.EvaluateToolCall("write_file", map[string]interface{}{
		"path":    "/home/user/project/README.md",
		"content": "# Hello",
	})
	// write_file to a safe path: no rule matches, default AUDIT
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (default), got %v", result.Decision)
	}
}

func TestEvaluateToolCall_NilPolicy(t *testing.T) {
	e := NewPolicyEvaluator(nil)

	result := e.EvaluateToolCall("anything", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (nil policy default), got %v", result.Decision)
	}
}

func TestEvaluateToolCall_EmptyPolicy(t *testing.T) {
	e := NewPolicyEvaluator(&MCPPolicy{})

	result := e.EvaluateToolCall("anything", nil)
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (empty policy default), got %v", result.Decision)
	}
}

func TestEvaluateToolCall_ArgumentPatternNoMatch(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	// write_file to /etc/** rule requires path arg; if path doesn't match, rule shouldn't fire
	result := e.EvaluateToolCall("write_file", map[string]interface{}{
		"path": "/tmp/safe.txt",
	})
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (default), got %v", result.Decision)
	}
}

func TestEvaluateToolCall_ArgumentPatternMissingArg(t *testing.T) {
	e := NewPolicyEvaluator(testPolicy())

	// write_file rule checks "path" arg; if argument is missing, rule shouldn't fire
	result := e.EvaluateToolCall("write_file", map[string]interface{}{
		"content": "data",
	})
	if result.Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT (arg missing, rule skipped), got %v", result.Decision)
	}
}

func TestMatchToolName_Exact(t *testing.T) {
	if !matchToolName("execute_command", "execute_command") {
		t.Error("expected exact match")
	}
	if matchToolName("execute_command", "other_tool") {
		t.Error("expected no match")
	}
}

func TestMatchToolName_Glob(t *testing.T) {
	if !matchToolName("execute_command", "execute_*") {
		t.Error("expected glob match")
	}
	if matchToolName("read_file", "execute_*") {
		t.Error("expected no glob match")
	}
}

func TestMatchGlob_DoubleStarPath(t *testing.T) {
	if !matchGlob("/etc/passwd", "/etc/**") {
		t.Error("expected /etc/passwd to match /etc/**")
	}
	if !matchGlob("/etc/ssh/sshd_config", "/etc/**") {
		t.Error("expected /etc/ssh/sshd_config to match /etc/**")
	}
	if matchGlob("/tmp/file", "/etc/**") {
		t.Error("expected /tmp/file to NOT match /etc/**")
	}
}

func TestMatchGlob_SingleStar(t *testing.T) {
	if !matchGlob("foo.txt", "*.txt") {
		t.Error("expected foo.txt to match *.txt")
	}
	if matchGlob("foo.go", "*.txt") {
		t.Error("expected foo.go to NOT match *.txt")
	}
}

func TestArgumentPatternsAny(t *testing.T) {
	rule := MCPRule{
		ID: "test-patterns-any",
		Match: MCPMatch{
			ToolNameAny: []string{"read_file", "write_file"},
			ArgumentPatternsAny: map[string][]string{
				"path": {
					"/home/*/.config/gcloud/**",
					"/root/.config/gcloud/**",
					"/var/root/.config/gcloud/**",
					"/Users/*/.config/gcloud/**",
				},
			},
		},
		Decision: policy.DecisionBlock,
		Reason:   "test rule",
	}

	eval := &PolicyEvaluator{}

	tests := []struct {
		name    string
		tool    string
		args    map[string]interface{}
		matched bool
	}{
		// TP: home directory paths must match
		{"linux user home", "read_file", map[string]interface{}{"path": "/home/alice/.config/gcloud/credentials.json"}, true},
		{"linux root", "read_file", map[string]interface{}{"path": "/root/.config/gcloud/credentials.json"}, true},
		{"macos root", "read_file", map[string]interface{}{"path": "/var/root/.config/gcloud/credentials.json"}, true},
		{"macos user", "read_file", map[string]interface{}{"path": "/Users/alice/.config/gcloud/credentials.json"}, true},
		// TP: path traversal is cleaned by filepath.Clean in glob engine
		{"path traversal cleaned", "read_file", map[string]interface{}{"path": "/workspace/../../../../home/alice/.config/gcloud/creds.json"}, true},
		// TN: non-home directory paths must NOT match
		{"non-home var/data", "read_file", map[string]interface{}{"path": "/var/data/.config/gcloud/credentials.json"}, false},
		{"non-home opt/app", "read_file", map[string]interface{}{"path": "/opt/app/.config/gcloud/credentials.json"}, false},
		{"workspace config", "read_file", map[string]interface{}{"path": "/workspace/.config/gcloud/credentials.json"}, false},
		// TN: completely unrelated path
		{"benign workspace file", "read_file", map[string]interface{}{"path": "/workspace/src/gcloud_handler.py"}, false},
		// TN: wrong tool
		{"wrong tool", "list_files", map[string]interface{}{"path": "/home/alice/.config/gcloud/credentials.json"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := eval.matchRule(tc.tool, tc.args, rule)
			if got != tc.matched {
				t.Errorf("matchRule(%q, %v) = %v, want %v", tc.tool, tc.args, got, tc.matched)
			}
		})
	}
}

// TestEvaluateToolCall_DedupesIdenticalRuleAndReason — issue #1628 regression.
// When the same pack is loaded from two layers (e.g., embedded + legacy disk),
// a single tool call can fire two rules with identical (RuleID, Reason).
// The user-visible output must collapse these.
func TestEvaluateToolCall_DedupesIdenticalRuleAndReason(t *testing.T) {
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "dup-rule",
				Match:    MCPMatch{ToolName: "read_file"},
				Decision: policy.DecisionBlock,
				Reason:   "duplicated reason",
			},
			{
				ID:       "dup-rule",
				Match:    MCPMatch{ToolName: "read_file"},
				Decision: policy.DecisionBlock,
				Reason:   "duplicated reason",
			},
		},
	}
	result := NewPolicyEvaluator(p).EvaluateToolCall("read_file", nil)

	if result.Decision != policy.DecisionBlock {
		t.Fatalf("decision = %s, want BLOCK", result.Decision)
	}
	if len(result.TriggeredRules) != 1 {
		t.Errorf("TriggeredRules = %v, want 1 entry after dedupe", result.TriggeredRules)
	}
	if len(result.Reasons) != 1 {
		t.Errorf("Reasons = %v, want 1 entry after dedupe", result.Reasons)
	}
}

// TestEvaluateToolCall_KeepsDistinctRulesAndReasons — dedupe must NOT collapse
// genuinely different rules or different reason wording (e.g., embedded vs
// legacy disk pack with newer reason text). Both should still surface.
func TestEvaluateToolCall_KeepsDistinctRulesAndReasons(t *testing.T) {
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "rule-a",
				Match:    MCPMatch{ToolName: "read_file"},
				Decision: policy.DecisionBlock,
				Reason:   "reason A",
			},
			{
				ID:       "rule-b",
				Match:    MCPMatch{ToolName: "read_file"},
				Decision: policy.DecisionBlock,
				Reason:   "reason B",
			},
			// Same ID, different reason — keep both (different pack version).
			{
				ID:       "rule-a",
				Match:    MCPMatch{ToolName: "read_file"},
				Decision: policy.DecisionBlock,
				Reason:   "reason A — updated wording",
			},
		},
	}
	result := NewPolicyEvaluator(p).EvaluateToolCall("read_file", nil)

	if len(result.Reasons) != 3 {
		t.Errorf("Reasons = %v, want 3 distinct entries", result.Reasons)
	}
	if len(result.TriggeredRules) != 3 {
		t.Errorf("TriggeredRules = %v, want 3 entries", result.TriggeredRules)
	}
}

func TestPolicyWithAllowDefault(t *testing.T) {
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID:       "block-dangerous",
				Match:    MCPMatch{ToolName: "dangerous_tool"},
				Decision: policy.DecisionBlock,
				Reason:   "Dangerous tool blocked.",
			},
		},
	}
	e := NewPolicyEvaluator(p)

	// Unknown tool with ALLOW default
	result := e.EvaluateToolCall("safe_tool", nil)
	if result.Decision != policy.DecisionAllow {
		t.Errorf("expected ALLOW, got %v", result.Decision)
	}

	// Blocked tool
	result = e.EvaluateToolCall("dangerous_tool", nil)
	if result.Decision != policy.DecisionBlock {
		t.Errorf("expected BLOCK, got %v", result.Decision)
	}
}
