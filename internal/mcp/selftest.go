package mcp

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/security-researcher-ca/agentshield/internal/mcp/scenarios"
	"github.com/security-researcher-ca/agentshield/internal/policy"
)

// MCPSelfTestResults holds the aggregate outcome of an MCP self-test run.
type MCPSelfTestResults struct {
	Total     int
	TP        int
	TN        int
	FP        int
	FN        int
	Precision float64
	Recall    float64
	Scenarios []ScenarioResult
}

// ScenarioResult holds the outcome of a single scenario evaluation.
type ScenarioResult struct {
	ID               string
	ToolName         string
	Category         string
	Classification   string
	ExpectedDecision string
	ActualDecision   string
	Pass             bool
	Description      string
}

// FormatMarkdown returns a Markdown-formatted report of the self-test results.
func (r MCPSelfTestResults) FormatMarkdown() string {
	var s string

	s += "## MCP Proxy Self-Test Results\n\n"
	s += fmt.Sprintf("TP: %d | TN: %d | FP: %d | FN: %d\n", r.TP, r.TN, r.FP, r.FN)
	s += fmt.Sprintf("Precision: %.0f%% | Recall: %.0f%%\n\n", r.Precision, r.Recall)

	// Count failures
	var failures []ScenarioResult
	for _, sr := range r.Scenarios {
		if !sr.Pass {
			failures = append(failures, sr)
		}
	}

	if len(failures) == 0 {
		s += "### All scenarios passed\n"
	} else {
		s += fmt.Sprintf("### %d scenario(s) failed\n\n", len(failures))
		s += "| ID | Tool | Category | Expected | Got | Description |\n"
		s += "|----|------|----------|----------|-----|-------------|\n"
		for _, f := range failures {
			desc := f.Description
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}
			s += fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
				f.ID, f.ToolName, f.Category, f.ExpectedDecision, f.ActualDecision, desc)
		}
	}

	return s
}

// RunMCPSelfTest runs all scenarios and returns structured results.
// packsDir should point to the packs/mcp/ directory containing YAML packs.
func RunMCPSelfTest(packsDir string) MCPSelfTestResults {
	// Load policy
	mcpPolicy := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks(packsDir, mcpPolicy)
	if err != nil {
		merged = mcpPolicy
	}

	evaluator := NewPolicyEvaluator(merged)
	handler := &MessageHandler{
		Evaluator: evaluator,
		Stderr:    io.Discard,
	}

	allScenarios := scenarios.AllScenarios()
	var results MCPSelfTestResults
	results.Total = len(allScenarios)

	for _, sc := range allScenarios {
		actual := evaluateScenarioFromDef(handler, sc)
		match := actual == sc.ExpectedDecision

		sr := ScenarioResult{
			ID:               sc.ID,
			ToolName:         sc.ToolName,
			Category:         sc.Category,
			Classification:   sc.Classification,
			ExpectedDecision: sc.ExpectedDecision,
			ActualDecision:   actual,
			Pass:             match,
			Description:      sc.Description,
		}
		results.Scenarios = append(results.Scenarios, sr)

		switch {
		case sc.Classification == "TP" && match:
			results.TP++
		case sc.Classification == "TP" && !match:
			results.FN++
		case sc.Classification == "TN" && match:
			results.TN++
		case sc.Classification == "TN" && !match:
			results.FP++
		}
	}

	if results.TP+results.FP > 0 {
		results.Precision = 100 * float64(results.TP) / float64(results.TP+results.FP)
	}
	if results.TP+results.FN > 0 {
		results.Recall = 100 * float64(results.TP) / float64(results.TP+results.FN)
	}

	return results
}

// evaluateScenarioFromDef runs a single scenario through the full MCP evaluation
// pipeline. This is the non-test version used by RunMCPSelfTest.
func evaluateScenarioFromDef(handler *MessageHandler, sc scenarios.Scenario) string {
	// Step 1: Policy evaluation
	result := handler.Evaluator.EvaluateToolCall(sc.ToolName, sc.Arguments)

	// Step 2: Content scanning
	if result.Decision != policy.DecisionBlock {
		contentResult := ScanToolCallContent(sc.ToolName, sc.Arguments)
		if contentResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 3: Value limits
	if result.Decision != policy.DecisionBlock {
		vlResult := handler.Evaluator.CheckValueLimits(sc.ToolName, sc.Arguments)
		if vlResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 4: Config guard
	if result.Decision != policy.DecisionBlock {
		guardResult := CheckConfigGuard(sc.ToolName, sc.Arguments)
		if guardResult.Blocked {
			result.Decision = policy.DecisionBlock
		}
	}

	// Step 5: Description poisoning scan
	if result.Decision != policy.DecisionBlock && (sc.ToolDescription != "" || sc.InputSchema != "") {
		tool := ToolDefinition{
			Name:        sc.ToolName,
			Description: sc.ToolDescription,
		}
		if sc.InputSchema != "" {
			tool.InputSchema = json.RawMessage(sc.InputSchema)
		}
		descResult := ScanToolDescription(tool)
		if descResult.Poisoned {
			result.Decision = policy.DecisionBlock
		}
	}

	return string(result.Decision)
}
