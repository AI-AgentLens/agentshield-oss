package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func floatPtr(f float64) *float64 { return &f }

func testValueLimitPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ValueLimits: []ValueLimitRule{
			{
				ID:          "block-large-transfer",
				ToolPattern: "send_*",
				Argument:    "amount",
				Max:         floatPtr(100),
				Decision:    policy.DecisionBlock,
				Reason:      "Transfer amount exceeds maximum allowed (100).",
			},
			{
				ID:            "audit-medium-payment",
				ToolNameRegex: "pay.*|transfer.*",
				Argument:      "amount",
				Max:           floatPtr(10),
				Decision:      policy.DecisionAudit,
				Reason:        "Payment above 10 flagged for review.",
			},
			{
				ID:          "block-negative-withdraw",
				ToolPattern: "withdraw",
				Argument:    "amount",
				Min:         floatPtr(0),
				Decision:    policy.DecisionBlock,
				Reason:      "Withdrawal amount must not be negative.",
			},
			{
				ID:       "global-quantity-cap",
				Argument: "quantity",
				Max:      floatPtr(1000),
				Decision: policy.DecisionBlock,
				Reason:   "Quantity exceeds global cap of 1000.",
			},
		},
	}
}

func TestValueLimit_BlockLargeTransfer(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"to":     "0xabc123",
		"amount": float64(52000000),
	})
	if !result.Blocked {
		t.Fatal("expected blocked — transfer of 52M exceeds max 100")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].RuleID != "block-large-transfer" {
		t.Errorf("expected rule block-large-transfer, got %s", result.Findings[0].RuleID)
	}
}

func TestValueLimit_AllowSmallTransfer(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"to":     "0xabc123",
		"amount": float64(50),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — transfer of 50 is within max 100")
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestValueLimit_ExactlyAtMax(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"amount": float64(100),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — amount exactly at max (100) should pass")
	}
}

func TestValueLimit_AuditMediumPayment(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("payment_process", map[string]interface{}{
		"amount": float64(50),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — AUDIT rule should not block")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (audit), got %d", len(result.Findings))
	}
	if result.Findings[0].Decision != policy.DecisionAudit {
		t.Errorf("expected AUDIT decision, got %v", result.Findings[0].Decision)
	}
}

func TestValueLimit_BlockNegativeWithdrawal(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("withdraw", map[string]interface{}{
		"amount": float64(-100),
	})
	if !result.Blocked {
		t.Fatal("expected blocked — negative withdrawal")
	}
	if result.Findings[0].RuleID != "block-negative-withdraw" {
		t.Errorf("expected rule block-negative-withdraw, got %s", result.Findings[0].RuleID)
	}
}

func TestValueLimit_AllowPositiveWithdrawal(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	result := e.CheckValueLimits("withdraw", map[string]interface{}{
		"amount": float64(25),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — positive withdrawal is fine")
	}
}

func TestValueLimit_GlobalQuantityCap(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	// Global rule (no tool filter) applies to any tool with "quantity" arg
	result := e.CheckValueLimits("order_items", map[string]interface{}{
		"item":     "widgets",
		"quantity": float64(5000),
	})
	if !result.Blocked {
		t.Fatal("expected blocked — quantity 5000 exceeds global cap of 1000")
	}
	if result.Findings[0].RuleID != "global-quantity-cap" {
		t.Errorf("expected rule global-quantity-cap, got %s", result.Findings[0].RuleID)
	}
}

func TestValueLimit_ToolPatternNoMatch(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	// "read_file" doesn't match "send_*" pattern
	result := e.CheckValueLimits("read_file", map[string]interface{}{
		"amount": float64(999999),
	})
	// Only the global quantity cap could match, but arg is "amount" not "quantity"
	if result.Blocked {
		t.Fatal("expected NOT blocked — tool doesn't match any value limit rule for 'amount'")
	}
}

func TestValueLimit_MissingArgument(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	// send_tokens without "amount" arg — rule skipped
	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"to": "0xabc123",
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — argument 'amount' not present")
	}
}

func TestValueLimit_NonNumericArgument(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	// "amount" is a string, not numeric — rule skipped
	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"amount": "fifty",
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — non-numeric argument skipped")
	}
}

func TestValueLimit_IntegerArgument(t *testing.T) {
	e := NewPolicyEvaluator(testValueLimitPolicy())

	// integer value should also be checked
	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"amount": 500,
	})
	if !result.Blocked {
		t.Fatal("expected blocked — int 500 exceeds max 100")
	}
}

func TestValueLimit_NoRulesConfigured(t *testing.T) {
	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	})

	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"amount": float64(999999),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — no value limit rules configured")
	}
}

func TestValueLimit_MultipleViolations(t *testing.T) {
	// A tool call that violates multiple rules
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ValueLimits: []ValueLimitRule{
			{
				ID:       "cap-amount",
				Argument: "amount",
				Max:      floatPtr(100),
				Decision: policy.DecisionBlock,
			},
			{
				ID:       "cap-count",
				Argument: "count",
				Max:      floatPtr(10),
				Decision: policy.DecisionBlock,
			},
		},
	}
	e := NewPolicyEvaluator(p)

	result := e.CheckValueLimits("bulk_transfer", map[string]interface{}{
		"amount": float64(500),
		"count":  float64(50),
	})
	if !result.Blocked {
		t.Fatal("expected blocked — both limits violated")
	}
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result.Findings))
	}
}

// TestValueLimit_LobstarWildeScenario reproduces the Lobstar Wilde incident:
// an agent tries to send 52,439,000 tokens instead of a small amount.
func TestValueLimit_LobstarWildeScenario(t *testing.T) {
	p := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ValueLimits: []ValueLimitRule{
			{
				ID:            "block-large-crypto-transfer",
				ToolNameRegex: "send_.*|transfer_.*",
				Argument:      "amount",
				Max:           floatPtr(1000),
				Decision:      policy.DecisionBlock,
				Reason:        "Crypto transfer exceeds safety limit of 1000 tokens.",
			},
		},
	}
	e := NewPolicyEvaluator(p)

	// The accidental mega-transfer
	result := e.CheckValueLimits("send_tokens", map[string]interface{}{
		"to":     "TreasureDavid_wallet",
		"amount": float64(52439000),
	})
	if !result.Blocked {
		t.Fatal("expected blocked — Lobstar Wilde scenario: 52M tokens exceeds 1000 limit")
	}
	if result.Findings[0].Value != 52439000 {
		t.Errorf("expected value 52439000, got %.0f", result.Findings[0].Value)
	}

	// The intended small transfer should pass
	result = e.CheckValueLimits("send_tokens", map[string]interface{}{
		"to":     "TreasureDavid_wallet",
		"amount": float64(4),
	})
	if result.Blocked {
		t.Fatal("expected NOT blocked — small 4-token transfer within limit")
	}
}
