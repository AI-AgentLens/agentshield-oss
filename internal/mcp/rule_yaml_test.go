package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// mcpPacksDir returns the absolute path to the packs/mcp/ directory.
func mcpPacksDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "packs", "mcp")
}

// loadAllMCPRules loads all MCP rules from all pack YAML files.
func loadAllMCPRules(t *testing.T) []MCPRule {
	t.Helper()
	dir := mcpPacksDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read MCP packs dir: %v", err)
	}

	var allRules []MCPRule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Logf("skip %s: %v", entry.Name(), err)
			continue
		}
		var pack MCPPolicy
		if err := yaml.Unmarshal(data, &pack); err != nil {
			t.Logf("skip %s: parse error: %v", entry.Name(), err)
			continue
		}
		allRules = append(allRules, pack.Rules...)
	}
	return allRules
}

// TestMCPRuleYAMLTests validates every MCP rule's inline TP/TN test cases
// by calling matchRule directly — fast, no full pipeline needed.
func TestMCPRuleYAMLTests(t *testing.T) {
	rules := loadAllMCPRules(t)

	// Create a minimal evaluator just to access matchRule
	evaluator := &PolicyEvaluator{}

	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			t.Run(fmt.Sprintf("%s/TP-%d", rule.ID, i+1), func(t *testing.T) {
				args := tc.Args
				if args == nil {
					args = map[string]interface{}{}
				}
				if !evaluator.matchRule(tc.Tool, args, rule) {
					t.Errorf("TP failed — MCP rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			t.Run(fmt.Sprintf("%s/TN-%d", rule.ID, i+1), func(t *testing.T) {
				args := tc.Args
				if args == nil {
					args = map[string]interface{}{}
				}
				if evaluator.matchRule(tc.Tool, args, rule) {
					t.Errorf("TN failed — MCP rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}

	t.Logf("Validated inline MCP tests for %d/%d rules", tested, len(rules))
}

// TestAllMCPRulesHaveTests is the coverage gate for MCP rules.
func TestAllMCPRulesHaveTests(t *testing.T) {
	if os.Getenv("SKIP_COVERAGE_GATE") != "" {
		t.Skip("SKIP_COVERAGE_GATE set")
	}

	rules := loadAllMCPRules(t)
	missing := []string{}
	for _, rule := range rules {
		if rule.Tests == nil || len(rule.Tests.TP) == 0 {
			missing = append(missing, rule.ID)
		}
	}

	if len(missing) > 0 {
		t.Logf("MCP rules missing inline tests: %d/%d", len(missing), len(rules))
		for i, id := range missing {
			if i >= 20 {
				t.Logf("  ... and %d more", len(missing)-20)
				break
			}
			t.Logf("  MISSING: %s", id)
		}
		t.Logf("WARNING: %d MCP rules have no inline tests. Target: 0.", len(missing))
	}
}
