package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Representative calls for the two capability classes, mirroring the
// lethal-trifecta test fixtures.
var (
	lateralIngestFirewallEvents = call{"get_firewall_events", map[string]interface{}{"zone": "example.com"}}
	lateralIngestIssueRead      = call{"get_issue", map[string]interface{}{"id": "42"}}
	lateralWriteDNSRecord       = call{"update_dns_record", map[string]interface{}{"name": "app.example.com", "content": "203.0.113.5"}}
	lateralBenignRead           = call{"read_file", map[string]interface{}{"path": "/workspace/README.md"}}
)

// TestLateralWriteTracker_FiresWhenWriteFollowsIngest verifies the tracker
// fires exactly once when an infra-mutation write is invoked after an
// untrusted-content-ingest read has been seen in the session.
func TestLateralWriteTracker_FiresWhenWriteFollowsIngest(t *testing.T) {
	tr := NewLateralWriteTracker()

	if sig := tr.Scan(lateralIngestFirewallEvents.tool, lateralIngestFirewallEvents.args); sig != "" {
		t.Fatalf("ingest-only call must not fire, got %q", sig)
	}
	sig := tr.Scan(lateralWriteDNSRecord.tool, lateralWriteDNSRecord.args)
	if sig != SignalLateralWriteAfterIngest {
		t.Fatalf("expected fire on write-after-ingest, got %q", sig)
	}

	// Must not re-fire on a subsequent qualifying write.
	if again := tr.Scan(lateralWriteDNSRecord.tool, lateralWriteDNSRecord.args); again != "" {
		t.Errorf("tracker re-fired after completion: %q", again)
	}
}

// TestLateralWriteTracker_WriteBeforeIngestDoesNotFire ensures ordering is
// enforced: a write that happens before any ingest read carries no plausible
// taint story and must not fire, even if an ingest read follows later.
func TestLateralWriteTracker_WriteBeforeIngestDoesNotFire(t *testing.T) {
	tr := NewLateralWriteTracker()

	if sig := tr.Scan(lateralWriteDNSRecord.tool, lateralWriteDNSRecord.args); sig != "" {
		t.Fatalf("write-before-ingest must not fire, got %q", sig)
	}
	if sig := tr.Scan(lateralIngestFirewallEvents.tool, lateralIngestFirewallEvents.args); sig != "" {
		t.Fatalf("ingest read after an already-seen write must not retroactively fire, got %q", sig)
	}
	// A second write after the (now-seen) ingest read DOES complete the
	// composition — the ordering requirement is about the specific write call
	// that triggers the signal, not about a one-time session verdict.
	if sig := tr.Scan(lateralWriteDNSRecord.tool, lateralWriteDNSRecord.args); sig != SignalLateralWriteAfterIngest {
		t.Fatalf("expected fire on second write (now ordered after ingest), got %q", sig)
	}
}

// TestLateralWriteTracker_IngestOnlyNoFire ensures a session that only reads
// low-trust content, without any infra-mutation write, never fires.
func TestLateralWriteTracker_IngestOnlyNoFire(t *testing.T) {
	tr := NewLateralWriteTracker()
	tr.Scan(lateralIngestFirewallEvents.tool, lateralIngestFirewallEvents.args)
	tr.Scan(lateralIngestIssueRead.tool, lateralIngestIssueRead.args)
	for i := 0; i < 5; i++ {
		if sig := tr.Scan(lateralBenignRead.tool, lateralBenignRead.args); sig != "" {
			t.Fatalf("ingest-only session must not fire (call %d), got %q", i, sig)
		}
	}
}

// TestLateralWriteTracker_WriteOnlyNoFire ensures a session that only writes,
// without any prior ingest read, never fires.
func TestLateralWriteTracker_WriteOnlyNoFire(t *testing.T) {
	tr := NewLateralWriteTracker()
	for i := 0; i < 3; i++ {
		if sig := tr.Scan(lateralWriteDNSRecord.tool, lateralWriteDNSRecord.args); sig != "" {
			t.Fatalf("write-only session must not fire (call %d), got %q", i, sig)
		}
	}
}

// TestIsUntrustedContentIngestTool spot-checks the ingest classifier.
func TestIsUntrustedContentIngestTool(t *testing.T) {
	tests := []struct {
		tool string
		want bool
	}{
		{"get_firewall_events", true},
		{"list_issues", true},
		{"search_tickets", true},
		{"get_analytics", true},
		{"list_alerts", true},
		{"get_logs", true},
		{"read_file", false},
		{"update_dns_record", false},
		{"list_directory", false},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			if got := isUntrustedContentIngestTool(tt.tool); got != tt.want {
				t.Errorf("isUntrustedContentIngestTool(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}

// TestIsInfraMutationTool spot-checks the infra-mutation classifier.
func TestIsInfraMutationTool(t *testing.T) {
	tests := []struct {
		tool string
		want bool
	}{
		{"update_dns_record", true},
		{"deploy_worker", true},
		{"create_firewall_rule", true},
		{"grant_permission", true},
		{"execute_command", true},
		{"apply_config", true},
		{"get_firewall_events", false},
		{"read_file", false},
		{"list_issues", false},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			if got := isInfraMutationTool(tt.tool); got != tt.want {
				t.Errorf("isInfraMutationTool(%q) = %v, want %v", tt.tool, got, tt.want)
			}
		})
	}
}

// TestLateralWriteRule_EvaluatesAudit validates the authored synthetic-tool
// rule (mcp-agentic-audit-lateral-write-after-untrusted-ingest) resolves to
// AUDIT when the tracker injects the synthetic tool name.
func TestLateralWriteRule_EvaluatesAudit(t *testing.T) {
	const ruleID = "mcp-agentic-audit-lateral-write-after-untrusted-ingest"
	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	var rule *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*rule},
	})
	res := e.EvaluateToolCall(syntheticLateralWriteAfterIngest, map[string]interface{}{"context": "composition complete"})
	if res.Decision != policy.DecisionAudit {
		t.Errorf("synthetic lateral-write tool should evaluate AUDIT; got %v", res.Decision)
	}
	// A benign real tool must not match the synthetic-tool rule.
	benign := e.EvaluateToolCall("get_firewall_events", map[string]interface{}{"zone": "example.com"})
	if benign.Decision == policy.DecisionAudit {
		for _, id := range benign.TriggeredRules {
			if id == ruleID {
				t.Error("lateral-write rule must only match the synthetic tool name")
			}
		}
	}
}
