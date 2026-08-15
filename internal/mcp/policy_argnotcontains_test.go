package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// argNotContainsRule is a minimal rule exercising the argument_not_contains
// negative/absence predicate in isolation: fire on a `send_*` tool only when
// `body` contains NONE of the listed (case-insensitive) disclosure markers.
func argNotContainsRule() MCPRule {
	return MCPRule{
		ID: "test-arg-not-contains",
		Match: MCPMatch{
			ToolNameRegex: "(?i)^send_",
			ArgumentNotContains: map[string][]string{
				"body": {"[AI-generated]", "[AI-drafted]", "drafted with AI assistance"},
			},
		},
		Decision: policy.DecisionAudit,
		Reason:   "test",
	}
}

func TestArgumentNotContains_Predicate(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := argNotContainsRule()

	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		fire bool
	}{
		{"no marker fires", "send_email",
			map[string]interface{}{"body": "Dear colleague, please review."}, true},
		{"exact marker suppresses", "send_email",
			map[string]interface{}{"body": "[AI-generated] Monthly update."}, false},
		{"case-insensitive marker suppresses", "send_email",
			map[string]interface{}{"body": "[ai-DRAFTED] hello"}, false},
		{"marker mid-string suppresses", "send_email",
			map[string]interface{}{"body": "Hello team. This was drafted with AI assistance."}, false},
		{"different marker still fires", "send_email",
			map[string]interface{}{"body": "[human-written] note"}, true},
		{"absent body fires (contains nothing)", "send_email",
			map[string]interface{}{"subject": "no body here"}, true},
		{"tool-name gate still applies", "read_email",
			map[string]interface{}{"body": "no marker"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.matchRule(tc.tool, tc.args, rule)
			if got != tc.fire {
				t.Errorf("matchRule(%q, %v) = %v, want %v", tc.tool, tc.args, got, tc.fire)
			}
		})
	}
}

// TestArgumentNotContains_ArraySerialization confirms the predicate operates on
// the fmt.Sprintf("%v") serialization, so a []string body is matched as "[a b]".
func TestArgumentNotContains_ArraySerialization(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID:       "test-arr",
		Match:    MCPMatch{ArgumentNotContains: map[string][]string{"tags": {"ai-generated"}}},
		Decision: policy.DecisionAudit,
	}
	// []string serializes to "[human ai-generated]" → contains marker → suppressed.
	if e.matchRule("x", map[string]interface{}{"tags": []string{"human", "ai-generated"}}, rule) {
		t.Errorf("expected suppression when serialized array contains marker")
	}
	if !e.matchRule("x", map[string]interface{}{"tags": []string{"human", "manual"}}, rule) {
		t.Errorf("expected fire when serialized array lacks marker")
	}
}

// TestBulkEmailUndisclosed_InSitu verifies the real premium pack rule
// mcp-excessive-agency-bulk-email-send-audit fires on an UNDISCLOSED bulk send
// and is suppressed on a DISCLOSED bulk send. This is the #2492 fitness check —
// it fails if argument_not_contains is removed/broken, which the decision-level
// scenario harness (AUDIT either way, dominated by the all-sends rule) cannot catch.
func TestBulkEmailUndisclosed_InSitu(t *testing.T) {
	handler := newTestMCPHandler(t)
	evaluator := handler.Evaluator
	if evaluator == nil {
		t.Skip("no policy evaluator on test handler")
	}

	const ruleID = "mcp-excessive-agency-bulk-email-send-audit"

	undisclosed := evaluator.EvaluateToolCall("send_email", map[string]interface{}{
		"to": []string{"alice@corp.com", "bob@corp.com"}, "body": "Dear colleague, urgent action required.",
	})
	if !containsRule(undisclosed.TriggeredRules, ruleID) {
		t.Errorf("undisclosed bulk send should trigger %s; got rules=%v", ruleID, undisclosed.TriggeredRules)
	}

	disclosed := evaluator.EvaluateToolCall("send_email", map[string]interface{}{
		"to": []string{"alice@corp.com", "bob@corp.com"}, "body": "[AI-generated] Monthly newsletter.",
	})
	if containsRule(disclosed.TriggeredRules, ruleID) {
		t.Errorf("disclosed bulk send must NOT trigger %s; got rules=%v", ruleID, disclosed.TriggeredRules)
	}
	// Disclosed bulk send is still AUDITed by the generic all-sends rule (defense in depth).
	if disclosed.Decision != policy.DecisionAudit {
		t.Errorf("disclosed bulk send should still AUDIT via all-sends rule; got %s", disclosed.Decision)
	}
}

func containsRule(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}
