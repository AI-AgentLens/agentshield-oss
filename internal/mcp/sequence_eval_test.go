package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// sequencePolicy is a policy whose only rule is a cross-call chain
// (OSINT → generation → bulk send). Default ALLOW so a non-firing sequence
// rule is distinguishable from a firing one (AUDIT).
func sequencePolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID: "mcp-osint-bulk-send-chain",
				Match: MCPMatch{
					Sequence: &MCPSequenceMatch{
						WithinCalls: 20,
						Steps: []MCPSequenceStep{
							{ToolNameRegex: "^(web_search|fetch)", MinCount: 3},
							{ToolNameRegex: "(generate|complete|chat)"},
							{
								ToolNameRegex:         "send_email",
								ArgumentRegexPatterns: map[string]string{"to": `^\[`},
								ArgumentNotContains:   map[string][]string{"body": {"ai-generated"}},
							},
						},
					},
				},
				Decision: policy.DecisionAudit,
				Reason:   "OSINT → generation → bulk send chain without disclosure.",
			},
		},
	}
}

func TestEvaluateWithHistory_SequenceFires(t *testing.T) {
	e := NewPolicyEvaluator(sequencePolicy())
	history := []RecordedCall{
		{ToolName: "web_search"}, {ToolName: "web_search"}, {ToolName: "fetch_url"},
		{ToolName: "generate_text"},
		{ToolName: "send_email", Args: map[string]interface{}{"to": "[a@x.com, b@y.com]", "body": "hi"}},
	}

	res := e.EvaluateToolCallWithHistory("send_email", history[len(history)-1].Args, "", history)
	if res.Decision != policy.DecisionAudit {
		t.Fatalf("expected AUDIT (chain fires), got %v", res.Decision)
	}
	found := false
	for _, id := range res.TriggeredRules {
		if id == "mcp-osint-bulk-send-chain" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the sequence rule to be triggered, got %v", res.TriggeredRules)
	}
}

func TestEvaluateWithHistory_IncompleteChainDoesNotFire(t *testing.T) {
	e := NewPolicyEvaluator(sequencePolicy())
	// Only two OSINT reads (min_count is 3) → chain must not fire.
	history := []RecordedCall{
		{ToolName: "web_search"}, {ToolName: "fetch_url"},
		{ToolName: "generate_text"},
		{ToolName: "send_email", Args: map[string]interface{}{"to": "[a@x.com]", "body": "hi"}},
	}
	res := e.EvaluateToolCallWithHistory("send_email", history[len(history)-1].Args, "", history)
	if res.Decision != policy.DecisionAllow {
		t.Errorf("expected ALLOW (chain incomplete), got %v", res.Decision)
	}
}

func TestEvaluateStateless_IgnoresSequenceRules(t *testing.T) {
	e := NewPolicyEvaluator(sequencePolicy())
	// The stateless entry point has no history, so a sequence rule must never
	// fire — even for a send_email that would be the chain's final step.
	res := e.EvaluateToolCall("send_email", map[string]interface{}{"to": "[a@x.com]", "body": "hi"})
	if res.Decision != policy.DecisionAllow {
		t.Errorf("stateless EvaluateToolCall must not fire sequence rules; got %v", res.Decision)
	}
}
