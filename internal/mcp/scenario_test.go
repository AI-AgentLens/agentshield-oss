package mcp

import (
	"io"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
)

// newTestMCPHandler creates a MessageHandler with all MCP packs loaded,
// matching how the real proxy evaluates tool calls.
func newTestMCPHandler(t *testing.T) *MessageHandler {
	t.Helper()

	// Start with default policy (includes blocked tools)
	mcpPolicy := DefaultMCPPolicy()

	// Load MCP packs from the project root
	packsDir := "../../packs/mcp"
	merged, _, err := LoadMCPPacks(packsDir, mcpPolicy)
	if err != nil {
		t.Logf("warning: could not load MCP packs from %s: %v", packsDir, err)
		merged = mcpPolicy
	}

	evaluator := NewPolicyEvaluator(merged)

	return &MessageHandler{
		Evaluator: evaluator,
		Stderr:    io.Discard,
	}
}

// TestMCPScenarios runs all labeled MCP test scenarios through the policy
// engine and reports accuracy metrics (TP, TN, FP, FN, precision, recall).
func TestMCPScenarios(t *testing.T) {
	handler := newTestMCPHandler(t)
	allScenarios := scenarios.AllScenarios()

	tp, tn, fp, fn := 0, 0, 0, 0

	for _, sc := range allScenarios {
		t.Run(sc.ID, func(t *testing.T) {
			actual := evaluateScenarioFromDef(handler, sc)

			if actual != sc.ExpectedDecision {
				if sc.Classification == "TP" {
					t.Errorf("[FALSE NEGATIVE] %s\n"+
						"  Tool:       %s\n"+
						"  Expected:   %s\n"+
						"  Got:        %s\n"+
						"  Category:   %s\n"+
						"  Reason:     %s",
						sc.ID, sc.ToolName, sc.ExpectedDecision, actual, sc.Category, sc.Description)
				} else {
					t.Errorf("[FALSE POSITIVE] %s\n"+
						"  Tool:       %s\n"+
						"  Expected:   %s\n"+
						"  Got:        %s\n"+
						"  Category:   %s\n"+
						"  Reason:     %s",
						sc.ID, sc.ToolName, sc.ExpectedDecision, actual, sc.Category, sc.Description)
				}
			}
		})

		// Compute confusion matrix (outside subtest for aggregate stats)
		actual := evaluateScenarioFromDef(handler, sc)
		match := actual == sc.ExpectedDecision

		switch {
		case sc.Classification == "TP" && match:
			tp++
		case sc.Classification == "TP" && !match:
			fn++
		case sc.Classification == "TN" && match:
			tn++
		case sc.Classification == "TN" && !match:
			fp++
		}
	}

	// Report accuracy metrics
	total := len(allScenarios)
	precision := float64(0)
	recall := float64(0)
	if tp+fp > 0 {
		precision = 100 * float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = 100 * float64(tp) / float64(tp+fn)
	}

	t.Logf("")
	t.Logf("=== MCP Proxy Self-Test Results ===")
	t.Logf("Total scenarios: %d", total)
	t.Logf("  TP (True Positives):  %d", tp)
	t.Logf("  TN (True Negatives):  %d", tn)
	t.Logf("  FP (False Positives): %d", fp)
	t.Logf("  FN (False Negatives): %d", fn)
	t.Logf("")
	t.Logf("  Precision: %.1f%%", precision)
	t.Logf("  Recall:    %.1f%%", recall)
}

// TestMCPScenarioIDsAreUnique validates that no two scenarios share the same ID.
func TestMCPScenarioIDsAreUnique(t *testing.T) {
	allScenarios := scenarios.AllScenarios()
	seen := map[string]bool{}
	for _, sc := range allScenarios {
		if seen[sc.ID] {
			t.Errorf("duplicate scenario ID: %s", sc.ID)
		}
		seen[sc.ID] = true
	}
	t.Logf("Verified %d scenario IDs are unique", len(allScenarios))
}

// TestMCPScenarioClassificationsAreValid validates all classifications are TP or TN.
func TestMCPScenarioClassificationsAreValid(t *testing.T) {
	for _, sc := range scenarios.AllScenarios() {
		if sc.Classification != "TP" && sc.Classification != "TN" {
			t.Errorf("[%s] invalid classification: %q (must be TP or TN)", sc.ID, sc.Classification)
		}
	}
}
