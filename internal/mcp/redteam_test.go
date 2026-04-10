package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// RedTeamMCPCase is a single MCP red-team regression test case.
type RedTeamMCPCase struct {
	ID               string                 `yaml:"id"`
	Description      string                 `yaml:"description"`
	ToolName         string                 `yaml:"tool_name"`
	Arguments        map[string]interface{} `yaml:"arguments"`
	ExpectedDecision string                 `yaml:"expected_decision"`
	ExpectedReasons  []string               `yaml:"expected_reasons"`
}

// RedTeamMCPSuite is the top-level YAML structure.
type RedTeamMCPSuite struct {
	Cases []RedTeamMCPCase `yaml:"cases"`
}

func loadMCPRedTeamCases(t *testing.T) []RedTeamMCPCase {
	t.Helper()

	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	path := filepath.Join(dir, "testdata", "redteam_mcp_cases.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read MCP red-team cases: %v", err)
	}

	var suite RedTeamMCPSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("failed to parse MCP red-team YAML: %v", err)
	}

	if len(suite.Cases) == 0 {
		t.Fatal("no MCP red-team cases loaded")
	}

	return suite.Cases
}

// redTeamPolicy returns the MCP policy used for red-team tests.
// It mirrors the real proxy startup: DefaultMCPPolicy() as the base,
// merged with the built-in packs from packs/community/mcp/ in the repo root.
// This ensures red-team tests validate the full deployed policy, not
// just the minimal defaults.
func redTeamPolicy() *MCPPolicy {
	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	packsDir := filepath.Join(dir, "..", "..", "packs", "community", "mcp")

	base := DefaultMCPPolicy()
	merged, _, err := LoadMCPPacks(packsDir, base)
	if err != nil {
		// Fall back to base if packs directory is unavailable.
		return base
	}
	return merged
}

func TestRedTeamMCP(t *testing.T) {
	cases := loadMCPRedTeamCases(t)
	evaluator := NewPolicyEvaluator(redTeamPolicy())

	var passed, failed int
	var failures []string

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			result := evaluator.EvaluateToolCall(tc.ToolName, tc.Arguments)

			// Check decision
			if string(result.Decision) != tc.ExpectedDecision {
				msg := fmt.Sprintf("%s: expected %s, got %s (tool=%s)",
					tc.ID, tc.ExpectedDecision, result.Decision, tc.ToolName)
				t.Error(msg)
				failures = append(failures, msg)
				failed++
				return
			}

			// Check expected reasons (substring match)
			for _, expectedReason := range tc.ExpectedReasons {
				found := false
				allReasons := strings.Join(result.Reasons, " ")
				if strings.Contains(strings.ToLower(allReasons), strings.ToLower(expectedReason)) {
					found = true
				}
				if !found {
					msg := fmt.Sprintf("%s: expected reason containing %q, got reasons: %v",
						tc.ID, expectedReason, result.Reasons)
					t.Error(msg)
					failures = append(failures, msg)
					failed++
					return
				}
			}

			passed++
		})
	}

	t.Logf("\nMCP Red-Team Results: %d passed, %d failed, %d total",
		passed, failed, len(cases))

	if len(failures) > 0 {
		t.Log("\nFailures:")
		for _, f := range failures {
			t.Logf("  - %s", f)
		}
	}
}

// TestRedTeamMCPReport generates a markdown summary of all red-team results.
func TestRedTeamMCPReport(t *testing.T) {
	cases := loadMCPRedTeamCases(t)
	evaluator := NewPolicyEvaluator(redTeamPolicy())

	var sb strings.Builder
	sb.WriteString("# MCP Red-Team Report\n\n")
	sb.WriteString("| ID | Tool | Expected | Actual | Pass | Reasons |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")

	passed := 0
	total := len(cases)

	for _, tc := range cases {
		result := evaluator.EvaluateToolCall(tc.ToolName, tc.Arguments)
		pass := string(result.Decision) == tc.ExpectedDecision

		// Also check reason substrings
		if pass {
			for _, expectedReason := range tc.ExpectedReasons {
				allReasons := strings.ToLower(strings.Join(result.Reasons, " "))
				if !strings.Contains(allReasons, strings.ToLower(expectedReason)) {
					pass = false
					break
				}
			}
		}

		icon := "❌"
		if pass {
			icon = "✅"
			passed++
		}

		reasons := strings.Join(result.Reasons, "; ")
		if len(reasons) > 60 {
			reasons = reasons[:57] + "..."
		}

		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s |\n",
			tc.ID, tc.ToolName, tc.ExpectedDecision,
			result.Decision, icon, reasons)
	}

	fmt.Fprintf(&sb, "\n**Results: %d/%d passed (%.1f%%)**\n",
		passed, total, float64(passed)/float64(total)*100)
	t.Log(sb.String())

	// Write report file
	_, filename, _, _ := runtime.Caller(0)
	reportPath := filepath.Join(filepath.Dir(filename), "testdata", "MCP_REDTEAM_REPORT.md")
	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		t.Logf("warning: could not write report: %v", err)
	} else {
		t.Logf("Report written to: %s", reportPath)
	}
}

// TestRedTeamMCP_PolicyCoverage verifies that the default policy covers key
// categories of attacks.
func TestRedTeamMCP_PolicyCoverage(t *testing.T) {
	pol := redTeamPolicy()

	// Must have blocked tools
	if len(pol.BlockedTools) == 0 {
		t.Error("default policy has no blocked tools")
	}

	// Must have rules
	if len(pol.Rules) == 0 {
		t.Error("default policy has no rules")
	}

	// Verify blocked tools include common shell execution tools
	blockedSet := map[string]bool{}
	for _, bt := range pol.BlockedTools {
		blockedSet[bt] = true
	}

	shellTools := []string{"execute_command", "run_shell", "run_terminal_command", "shell_exec"}
	for _, st := range shellTools {
		if !blockedSet[st] {
			t.Errorf("expected %q in blocked tools list", st)
		}
	}

	// Verify default decision
	if pol.Defaults.Decision != policy.DecisionAudit {
		t.Errorf("expected default decision AUDIT, got %s", pol.Defaults.Decision)
	}
}
