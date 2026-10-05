package mcp

import (
	"io"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// newTestMCPEvaluator builds a PolicyEvaluator with all MCP packs loaded,
// matching how the real proxy evaluates tool calls.
//
// It loads packs/community/mcp/ first, then layers packs/premium/mcp/ on top
// when present. This mirrors `make deploy`, which copies both into
// ~/.agentshield/packs/mcp/. When premium/ is missing (OSS-only checkout) the
// loader simply returns the community-only policy and tests for premium-only
// rules will surface as failures — by design, so that scenario expectations
// are kept honest about the deployed rule set.
//
// Pack loading costs ~110ms, which is why the scenario harness shares one
// instance across the corpus rather than rebuilding per scenario. That sharing
// is only safe because a PolicyEvaluator holds no per-session state; see
// evaluateScenarioFromDef's comment and
// TestMCPScenarioVerdictsAreOrderIndependent (#3392).
func newTestMCPEvaluator(t *testing.T) *PolicyEvaluator {
	t.Helper()

	// Start with default policy (includes blocked tools)
	mcpPolicy := DefaultMCPPolicy()

	// Load community MCP packs from the project root
	communityDir := "../../packs/community/mcp"
	merged, _, err := LoadMCPPacks(communityDir, mcpPolicy)
	if err != nil {
		t.Logf("warning: could not load community MCP packs from %s: %v", communityDir, err)
		merged = mcpPolicy
	}

	// Layer premium MCP packs on top when present (skipped in OSS-only checkouts).
	premiumDir := "../../packs/premium/mcp"
	premiumMerged, _, perr := LoadMCPPacks(premiumDir, merged)
	if perr != nil {
		t.Logf("warning: could not load premium MCP packs from %s: %v", premiumDir, perr)
	} else {
		merged = premiumMerged
	}

	return NewPolicyEvaluator(merged)
}

// newTestMCPHandler wraps newTestMCPEvaluator in a MessageHandler for the tests
// that genuinely exercise handler-level behaviour (batching, long-context
// accumulation, session history). The scenario corpus does NOT use this — it
// evaluates against the evaluator directly so that no session state can reach a
// verdict.
func newTestMCPHandler(t *testing.T) *MessageHandler {
	t.Helper()

	return &MessageHandler{
		Evaluator: newTestMCPEvaluator(t),
		Stderr:    io.Discard,
	}
}

// TestMCPScenarios runs all labeled MCP test scenarios through the policy
// engine and reports accuracy metrics (TP, TN, FP, FN, precision, recall).
func TestMCPScenarios(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	evaluator := newTestMCPEvaluator(t)
	allScenarios := scenarios.AllScenarios()

	tp, tn, fp, fn := 0, 0, 0, 0

	for _, sc := range allScenarios {
		// Evaluated ONCE per scenario. Until #3392 this ran the whole corpus
		// twice — once inside the subtest, once again outside it for the
		// confusion matrix — which doubled the runtime and, more to the point,
		// meant the aggregate numbers came from a different pass than the
		// per-scenario failures reported above them. Nothing guaranteed the two
		// passes agreed.
		actual := evaluateScenarioFromDef(evaluator, sc)

		t.Run(sc.ID, func(t *testing.T) {
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

		// Confusion matrix, from the same evaluation the subtest graded.
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
