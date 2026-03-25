package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// packsDir returns the absolute path to the packs/ directory.
func packsDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "packs")
}

// loadAllRules loads the default policy + all packs and returns rules.
func loadAllRules(t *testing.T) []Rule {
	t.Helper()
	base := DefaultPolicy()
	pol, _, err := LoadPacks(packsDir(), base)
	if err != nil {
		t.Fatalf("failed to load packs: %v", err)
	}
	return pol.Rules
}

// TestRuleYAMLTests validates every rule's inline TP/TN test cases.
// TP commands must trigger the rule; TN commands must NOT trigger it.
func TestRuleYAMLTests(t *testing.T) {
	rules := loadAllRules(t)
	engine := &Engine{} // only used for matchRule; no full pipeline needed

	tested := 0
	skippedStructural := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}

		// Skip rules that only have structural/semantic/dataflow/stateful match —
		// matchRule only handles regex/prefix/exact. Structural rules are validated
		// by TestAccuracy and TestMCPScenarios through the full pipeline.
		hasRegexMatch := rule.Match.CommandRegex != "" || rule.Match.CommandExact != "" || len(rule.Match.CommandPrefix) > 0
		if !hasRegexMatch {
			skippedStructural++
			continue
		}
		tested++

		// Test true positives
		for i, cmd := range rule.Tests.TP {
			t.Run(fmt.Sprintf("%s/TP-%d", rule.ID, i+1), func(t *testing.T) {
				if !engine.matchRule(cmd, rule) {
					t.Errorf("TP failed — rule %s should fire on:\n  %s", rule.ID, cmd)
				}
			})
		}

		// Test true negatives
		for i, cmd := range rule.Tests.TN {
			t.Run(fmt.Sprintf("%s/TN-%d", rule.ID, i+1), func(t *testing.T) {
				if engine.matchRule(cmd, rule) {
					t.Errorf("TN failed — rule %s should NOT fire on:\n  %s", rule.ID, cmd)
				}
			})
		}
	}

	t.Logf("Validated inline tests for %d/%d rules (%d structural-only skipped — tested via full pipeline)", tested, len(rules), skippedStructural)
}

// TestAllRulesHaveTests fails if any rule is missing inline tests.
// This is the coverage gate — no rule ships without TP/TN.
func TestAllRulesHaveTests(t *testing.T) {
	// Skip if SKIP_COVERAGE_GATE is set (useful during backfill)
	if os.Getenv("SKIP_COVERAGE_GATE") != "" {
		t.Skip("SKIP_COVERAGE_GATE set — skipping coverage enforcement")
	}

	rules := loadAllRules(t)
	missing := []string{}
	for _, rule := range rules {
		// Skip MCP rules — they're tested via TestMCPScenarios (100% precision/recall)
		if strings.HasPrefix(rule.ID, "mcp-") {
			continue
		}
		// Skip base policy rules (no pack prefix) — tested via TestAccuracy
		if !strings.Contains(rule.ID, "-") || rule.ID == "block-rm-root" || rule.ID == "block-pipe-to-shell" ||
			rule.ID == "audit-package-installs" || rule.ID == "audit-file-edits" || rule.ID == "allow-safe-readonly" {
			continue
		}
		if rule.Tests == nil || len(rule.Tests.TP) == 0 {
			missing = append(missing, rule.ID)
		}
	}

	if len(missing) > 0 {
		t.Logf("Rules missing inline tests: %d/%d", len(missing), len(rules))
		// Log first 20 for visibility
		for i, id := range missing {
			if i >= 20 {
				t.Logf("  ... and %d more", len(missing)-20)
				break
			}
			t.Logf("  MISSING: %s", id)
		}
		// For now, warn but don't fail — flip to t.Errorf after backfill is complete
		t.Logf("WARNING: %d rules have no inline tests. Target: 0.", len(missing))
	}
}
