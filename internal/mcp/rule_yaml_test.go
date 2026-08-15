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

// mcpPacksDir returns the absolute path to the authoritative MCP packs
// directory — the one embedded into the binary via packs/packs.go
// (//go:embed community/mcp/*.yaml). Reading the same source of truth
// that ships to customers ensures TP/TN tests validate what actually runs.
func mcpPacksDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "packs", "community", "mcp")
}

// premiumMCPPacksDir returns the absolute path to the premium MCP packs
// directory. Premium packs are not embedded (delivered via SaaS update),
// but this repo clone has them on disk, so their inline `tests:` blocks
// can be — and must be — validated the same way as community's.
func premiumMCPPacksDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "packs", "premium", "mcp")
}

// loadMCPRulesFromDir loads all MCP semantic rules from every pack YAML file
// in dir.
func loadMCPRulesFromDir(t *testing.T, dir string) []MCPRule {
	t.Helper()
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

// loadMCPStructuralRulesFromDir loads all MCP structural rules from every
// pack YAML file in dir (the `structural_rules:` section).
func loadMCPStructuralRulesFromDir(t *testing.T, dir string) []MCPStructuralRule {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read MCP packs dir: %v", err)
	}

	var allRules []MCPStructuralRule
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
		allRules = append(allRules, pack.StructuralRules...)
	}
	return allRules
}

// loadAllMCPRules loads all MCP rules from all community pack YAML files.
func loadAllMCPRules(t *testing.T) []MCPRule {
	t.Helper()
	return loadMCPRulesFromDir(t, mcpPacksDir())
}

// loadAllMCPStructuralRules loads all MCP structural rules from all
// community pack YAML files. Mirrors loadAllMCPRules but reads the
// `structural_rules:` section so the persistence pack (and any other pack
// that uses the structural matcher) gets its inline tests validated by
// TestMCPStructuralRuleYAMLTests.
func loadAllMCPStructuralRules(t *testing.T) []MCPStructuralRule {
	t.Helper()
	return loadMCPStructuralRulesFromDir(t, mcpPacksDir())
}

// loadAllPremiumMCPRules loads all MCP rules from all premium pack YAML
// files (packs/premium/mcp). Unlike community, premium packs are not
// embedded into the binary — but this repo clone has them on disk, and
// their inline `tests:` blocks are just as load-bearing for the attestation
// chain (a Shield block is only attestation-grade if we can prove the rule
// fires as claimed — see issue #2865).
func loadAllPremiumMCPRules(t *testing.T) []MCPRule {
	t.Helper()
	return loadMCPRulesFromDir(t, premiumMCPPacksDir())
}

// loadAllPremiumMCPStructuralRules loads all MCP structural rules from all
// premium pack YAML files.
func loadAllPremiumMCPStructuralRules(t *testing.T) []MCPStructuralRule {
	t.Helper()
	return loadMCPStructuralRulesFromDir(t, premiumMCPPacksDir())
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
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if !evaluator.matchRule(tc.Tool, args, rule) {
					t.Errorf("TP failed — MCP rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			t.Run(fmt.Sprintf("%s/TN-%d", rule.ID, i+1), func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if evaluator.matchRule(tc.Tool, args, rule) {
					t.Errorf("TN failed — MCP rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}

	t.Logf("Validated inline MCP tests for %d/%d rules", tested, len(rules))
}

// knownStructuralRuleTestGaps is a deny list of inline structural-rule tests
// that pre-date TestMCPStructuralRuleYAMLTests and currently fail. These are
// real-but-unrelated bugs in TP test data (not in any rule touched by issue
// #1155 / FN-MCP-011) — typically TPs that pass an HTTP method via tool name
// but the rule still requires an explicit `method` arg. They are surfaced as
// warnings here so the new test gate doesn't block on pre-existing debt while
// still validating every rule we DO care about. Each gap is keyed by the
// generated subtest name "<rule-id>/(TP|TN)-<n>".
//
// TODO: file follow-up issues to fix each gap and remove it from this list.
var knownStructuralRuleTestGaps = map[string]string{}

// TestMCPStructuralRuleYAMLTests validates every structural MCP rule's inline
// TP/TN test cases by calling matchStructuralRule directly. Without this test,
// `tests:` blocks under structural rules in (e.g.) mcp-persistence.yaml are
// silently ignored — which is exactly how FN-MCP-011 (issue #1155) shipped to
// production unnoticed.
func TestMCPStructuralRuleYAMLTests(t *testing.T) {
	rules := loadAllMCPStructuralRules(t)

	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if !matchStructuralRule(tc.Tool, args, rule) {
					if reason, known := knownStructuralRuleTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — MCP structural rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if matchStructuralRule(tc.Tool, args, rule) {
					if reason, known := knownStructuralRuleTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — MCP structural rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}

	t.Logf("Validated inline MCP structural tests for %d/%d rules (%d known gaps)", tested, len(rules), len(knownStructuralRuleTestGaps))
}

// knownPremiumMCPTestGaps is a deny list of premium MCP *semantic* rule
// inline test cases that fail today. Premium packs were never loaded by
// this harness before #2865 (only packs/community/mcp was), so these
// inline `tests:` blocks have never actually executed in CI — they "passed"
// by not running. Wiring premium in surfaced these as real gaps needing
// individual root-cause triage (some are narrow regex/domain coverage
// misses, some look like the known MCP-HTTP-method-filter class from
// RULE_REVIEW.md #1152). Do NOT bulk-fix by guessing — see tracking issue.
// Chip this down the same way cmd/check-rule-coverage/baseline.txt gets
// chipped down: fix a rule (or its test), remove the entry, keep it green.
//
// Tracking: https://github.com/AI-AgentLens/agentshield-oss/issues/2875
var knownPremiumMCPTestGaps = map[string]string{}

// knownPremiumMCPStructuralTestGaps mirrors knownPremiumMCPTestGaps for
// premium structural_rules:. Same tracking issue.
var knownPremiumMCPStructuralTestGaps = map[string]string{}

// TestPremiumMCPRuleYAMLTests validates every premium MCP semantic rule's
// inline TP/TN test cases by calling matchRule directly. Mirrors
// TestMCPRuleYAMLTests but for packs/premium/mcp. Engine-based sentinel
// rules (rule.Engine != "") are pattern-matched by dedicated Go signal
// functions, not matchRule, and already have direct Go test coverage
// (description_scanner_test.go et al.) — matchRule always returns false
// for them by design, so they're skipped here rather than counted as gaps.
func TestPremiumMCPRuleYAMLTests(t *testing.T) {
	rules := loadAllPremiumMCPRules(t)
	evaluator := &PolicyEvaluator{}

	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil || rule.Engine != "" {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if !evaluator.matchRule(tc.Tool, args, rule) {
					if reason, known := knownPremiumMCPTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — premium MCP rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if evaluator.matchRule(tc.Tool, args, rule) {
					if reason, known := knownPremiumMCPTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — premium MCP rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}

	t.Logf("Validated inline premium MCP tests for %d/%d rules (%d known gaps)", tested, len(rules), len(knownPremiumMCPTestGaps))
}

// TestPremiumMCPStructuralRuleYAMLTests mirrors TestMCPStructuralRuleYAMLTests
// but for packs/premium/mcp structural_rules:.
func TestPremiumMCPStructuralRuleYAMLTests(t *testing.T) {
	rules := loadAllPremiumMCPStructuralRules(t)

	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if !matchStructuralRule(tc.Tool, args, rule) {
					if reason, known := knownPremiumMCPStructuralTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — premium MCP structural rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args, err := tc.ResolvedArgs()
				if err != nil {
					t.Fatalf("rule %s: decode test args: %v", rule.ID, err)
				}
				if matchStructuralRule(tc.Tool, args, rule) {
					if reason, known := knownPremiumMCPStructuralTestGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — premium MCP structural rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}

	t.Logf("Validated inline premium MCP structural tests for %d/%d rules (%d known gaps)", tested, len(rules), len(knownPremiumMCPStructuralTestGaps))
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
