package policy

import (
	"errors"
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
	pol, infos, err := LoadPacks(packsDir(), base)
	if err != nil {
		t.Fatalf("failed to load packs: %v", err)
	}
	if loadErr := firstPackLoadError(infos); loadErr != nil {
		t.Fatal(loadErr)
	}
	return pol.Rules
}

// firstPackLoadError returns an error naming the first pack whose LoadError
// is set, or nil if every pack loaded cleanly. Extracted from loadAllRules so
// the "does the gate refuse to swallow a bad pack" behavior is directly
// unit-testable — without needing t.Fatalf to actually fire inside a test
// (a subtest deliberately engineered to fail also marks its PARENT test, and
// therefore the whole package run, as permanently FAIL — the wrong shape for
// a gate that must itself stay green).
func firstPackLoadError(infos []PackInfo) error {
	for _, info := range infos {
		if info.LoadError != nil {
			return fmt.Errorf("pack %q failed to load: %w", info.Path, info.LoadError)
		}
	}
	return nil
}

// TestFirstPackLoadError proves the #3637 gate mechanism: loadAllRules must
// stop swallowing a pack whose LoadError is set (LoadPacks already recorded
// it per #2188/#3035, but TestRuleYAMLTests and TestAllRulesHaveTests loaded
// through the old loadAllRules with `_` discarding the infos slice, so both
// gates stayed green while silently missing an entire pack's rules).
func TestFirstPackLoadError(t *testing.T) {
	if err := firstPackLoadError(nil); err != nil {
		t.Errorf("no infos should report no error, got %v", err)
	}
	clean := []PackInfo{{Path: "good.yaml"}, {Path: "also-good.yaml"}}
	if err := firstPackLoadError(clean); err != nil {
		t.Errorf("infos with no LoadError should report no error, got %v", err)
	}
	withFailure := []PackInfo{
		{Path: "good.yaml"},
		{Path: "bad.yaml", LoadError: errors.New("yaml: line 8: mapping values are not allowed in this context")},
	}
	err := firstPackLoadError(withFailure)
	if err == nil {
		t.Fatal("expected an error when a pack has LoadError set — this is the #3637 gate")
	}
	if !strings.Contains(err.Error(), "bad.yaml") {
		t.Errorf("error should name the failed pack, got: %v", err)
	}
}

// TestRuleYAMLTests validates every rule's inline TP/TN test cases.
// TP commands must trigger the rule; TN commands must NOT trigger it.
func TestRuleYAMLTests(t *testing.T) {
	rules := loadAllRules(t)
	// Build a real engine with regex cache from loaded rules
	pol := &Policy{Rules: rules}
	engine, err := NewEngine(pol)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

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

		// Test attested cases: the rule fires (so a receipt names it) but a
		// command_intent_downgrade label moves the decision to AUDIT (#2843,
		// #2983). Both halves are asserted — a case that stops firing has
		// lost its attribution, and one that stays at BLOCK is the FP the
		// label exists to prevent. An `attested:` case on a rule with no
		// downgrade label is a rule-authoring error, not a passing test.
		for i, cmd := range rule.Tests.Attested {
			t.Run(fmt.Sprintf("%s/ATTESTED-%d", rule.ID, i+1), func(t *testing.T) {
				if len(rule.Match.CommandIntentDowngrade) == 0 {
					t.Errorf("ATTESTED case on rule %s, which has no command_intent_downgrade — use tp:/tn: instead:\n  %s", rule.ID, cmd)
					return
				}
				if !engine.matchRule(cmd, rule) {
					t.Errorf("ATTESTED failed — rule %s should FIRE (then downgrade) on:\n  %s", rule.ID, cmd)
					return
				}
				if eff := engine.effectiveDecision(cmd, rule); eff != DecisionAudit {
					t.Errorf("ATTESTED failed — rule %s fired at %s, want AUDIT (downgrade label did not apply) on:\n  %s", rule.ID, eff, cmd)
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
