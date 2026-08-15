package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// loadMCPPolicyFromDir parses every pack YAML file in dir into an MCPPolicy
// and returns the parsed packs. Shared by the resource/value-limit/semantic
// inline-test loaders below so each one doesn't re-walk the directory.
func loadMCPPolicyFromDir(t *testing.T, dir string) []MCPPolicy {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("cannot read MCP packs dir: %v", err)
	}

	var packs []MCPPolicy
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
		packs = append(packs, pack)
	}
	return packs
}

func loadResourceRulesFromDir(t *testing.T, dir string) []ResourceRule {
	t.Helper()
	var all []ResourceRule
	for _, pack := range loadMCPPolicyFromDir(t, dir) {
		all = append(all, pack.ResourceRules...)
	}
	return all
}

func loadValueLimitsFromDir(t *testing.T, dir string) []ValueLimitRule {
	t.Helper()
	var all []ValueLimitRule
	for _, pack := range loadMCPPolicyFromDir(t, dir) {
		all = append(all, pack.ValueLimits...)
	}
	return all
}

func loadSemanticRulesFromDir(t *testing.T, dir string) []MCPSemanticRule {
	t.Helper()
	var all []MCPSemanticRule
	for _, pack := range loadMCPPolicyFromDir(t, dir) {
		all = append(all, pack.SemanticRules...)
	}
	return all
}

// knownResourceValueSemanticTestGaps is a deny list for pre-existing inline
// tests on resource_rules/value_limits/semantic_rules that predate this
// harness and currently fail — mirrors knownPremiumMCPTestGaps. These
// `tests:` blocks parsed successfully but were never executed by any test
// (issue #2869: no dedicated harness existed), so a rule/test bug here is
// pre-existing debt, not a regression from adding the harness. Chip this
// down by fixing the rule or test and removing the entry.
var knownResourceValueSemanticTestGaps = map[string]string{}

// resolveTestCaseArgs decodes a test case's args (or args_b64) the same way
// MCPTestCase.ResolvedArgs does for the tool-call rule harnesses.
func resolveTestCaseArgs(t *testing.T, ruleID string, tc MCPTestCase) map[string]interface{} {
	t.Helper()
	args, err := tc.ResolvedArgs()
	if err != nil {
		t.Fatalf("rule %s: decode test args: %v", ruleID, err)
	}
	return args
}

// TestMCPResourceRuleYAMLTests validates every resource_rules: inline TP/TN
// test case by calling matchResourceRule directly. Test cases carry the URI
// under args["uri"] (the same shape resources/read tool-call tests use — see
// mcp-agentic-attacks.yaml's mcp-agentic-audit-ui-scheme-resource).
func TestMCPResourceRuleYAMLTests(t *testing.T) {
	runResourceRuleYAMLTests(t, loadResourceRulesFromDir(t, mcpPacksDir()), nil)
}

// TestPremiumMCPResourceRuleYAMLTests mirrors TestMCPResourceRuleYAMLTests for
// packs/premium/mcp.
func TestPremiumMCPResourceRuleYAMLTests(t *testing.T) {
	runResourceRuleYAMLTests(t, loadResourceRulesFromDir(t, premiumMCPPacksDir()), knownResourceValueSemanticTestGaps)
}

func runResourceRuleYAMLTests(t *testing.T, rules []ResourceRule, knownGaps map[string]string) {
	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				uri, _ := args["uri"].(string)
				if !matchResourceRule(uri, rule) {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — resource rule %s should fire on uri=%q", rule.ID, uri)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				uri, _ := args["uri"].(string)
				if matchResourceRule(uri, rule) {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — resource rule %s should NOT fire on uri=%q", rule.ID, uri)
				}
			})
		}
	}
	t.Logf("Validated inline resource-rule tests for %d/%d rules", tested, len(rules))
}

// TestMCPValueLimitRuleYAMLTests validates every value_limits: inline TP/TN
// test case. Reuses CheckValueLimits (the real evaluation path) scoped to a
// single rule so the test exercises production logic rather than a
// reimplementation of the threshold check.
func TestMCPValueLimitRuleYAMLTests(t *testing.T) {
	runValueLimitRuleYAMLTests(t, loadValueLimitsFromDir(t, mcpPacksDir()), nil)
}

// TestPremiumMCPValueLimitRuleYAMLTests mirrors TestMCPValueLimitRuleYAMLTests
// for packs/premium/mcp.
func TestPremiumMCPValueLimitRuleYAMLTests(t *testing.T) {
	runValueLimitRuleYAMLTests(t, loadValueLimitsFromDir(t, premiumMCPPacksDir()), knownResourceValueSemanticTestGaps)
}

func runValueLimitRuleYAMLTests(t *testing.T, rules []ValueLimitRule, knownGaps map[string]string) {
	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++
		evaluator := &PolicyEvaluator{policy: &MCPPolicy{ValueLimits: []ValueLimitRule{rule}}}

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				result := evaluator.CheckValueLimits(tc.Tool, args)
				if len(result.Findings) == 0 {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — value limit rule %s should fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				result := evaluator.CheckValueLimits(tc.Tool, args)
				if len(result.Findings) != 0 {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — value limit rule %s should NOT fire on tool=%q args=%v", rule.ID, tc.Tool, args)
				}
			})
		}
	}
	t.Logf("Validated inline value-limit tests for %d/%d rules", tested, len(rules))
}

// TestMCPSemanticRuleYAMLTests validates every semantic_rules: inline TP/TN
// test case by classifying intent from (tool, args) — matching how the
// runtime path (evaluateSemanticRules) derives intents — then calling
// matchSemanticRule directly.
func TestMCPSemanticRuleYAMLTests(t *testing.T) {
	runSemanticRuleYAMLTests(t, loadSemanticRulesFromDir(t, mcpPacksDir()), nil)
}

// TestPremiumMCPSemanticRuleYAMLTests mirrors TestMCPSemanticRuleYAMLTests for
// packs/premium/mcp.
func TestPremiumMCPSemanticRuleYAMLTests(t *testing.T) {
	runSemanticRuleYAMLTests(t, loadSemanticRulesFromDir(t, premiumMCPPacksDir()), knownResourceValueSemanticTestGaps)
}

func runSemanticRuleYAMLTests(t *testing.T, rules []MCPSemanticRule, knownGaps map[string]string) {
	tested := 0
	for _, rule := range rules {
		if rule.Tests == nil {
			continue
		}
		tested++

		for i, tc := range rule.Tests.TP {
			caseName := fmt.Sprintf("%s/TP-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				result := ClassifyToolIntent(tc.Tool, args, "")
				if !matchSemanticRule(tc.Tool, result.Intents, rule) {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TP failed — semantic rule %s should fire on tool=%q args=%v (intents=%v)", rule.ID, tc.Tool, args, result.Intents)
				}
			})
		}

		for i, tc := range rule.Tests.TN {
			caseName := fmt.Sprintf("%s/TN-%d", rule.ID, i+1)
			t.Run(caseName, func(t *testing.T) {
				args := resolveTestCaseArgs(t, rule.ID, tc)
				result := ClassifyToolIntent(tc.Tool, args, "")
				if matchSemanticRule(tc.Tool, result.Intents, rule) {
					if reason, known := knownGaps[caseName]; known {
						t.Skipf("KNOWN GAP: %s", reason)
						return
					}
					t.Errorf("TN failed — semantic rule %s should NOT fire on tool=%q args=%v (intents=%v)", rule.ID, tc.Tool, args, result.Intents)
				}
			})
		}
	}
	t.Logf("Validated inline semantic-rule tests for %d/%d rules", tested, len(rules))
}
