package analyzer

import (
	"testing"
)

func TestCombiner_MostRestrictive_BlockWins(t *testing.T) {
	c := NewCombiner(StrategyMostRestrictive)
	findings := []Finding{
		{AnalyzerName: "regex", RuleID: "r1", Decision: "AUDIT", Confidence: 0.70, Reason: "audit reason"},
		{AnalyzerName: "structural", RuleID: "s1", Decision: "BLOCK", Confidence: 0.95, Reason: "block reason"},
	}
	result := c.Combine(findings, "AUDIT")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK, got %s", result.Decision)
	}
	if len(result.TriggeredRules) != 1 || result.TriggeredRules[0] != "s1" {
		t.Errorf("expected triggered rule s1, got %v", result.TriggeredRules)
	}
}

func TestCombiner_MostRestrictive_SameSeverityCollectsAll(t *testing.T) {
	c := NewCombiner(StrategyMostRestrictive)
	findings := []Finding{
		{AnalyzerName: "regex", RuleID: "r1", Decision: "BLOCK", Confidence: 0.70, Reason: "regex block"},
		{AnalyzerName: "structural", RuleID: "s1", Decision: "BLOCK", Confidence: 0.95, Reason: "structural block"},
	}
	result := c.Combine(findings, "AUDIT")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK, got %s", result.Decision)
	}
	if len(result.TriggeredRules) != 2 {
		t.Errorf("expected 2 triggered rules, got %d", len(result.TriggeredRules))
	}
}

func TestCombiner_MostRestrictive_NoFindings(t *testing.T) {
	c := NewCombiner(StrategyMostRestrictive)
	result := c.Combine(nil, "AUDIT")
	if result.Decision != "AUDIT" {
		t.Errorf("expected default AUDIT, got %s", result.Decision)
	}
}

func TestCombiner_StructuralAllowOverride(t *testing.T) {
	c := NewCombiner(StrategyMostRestrictive)
	findings := []Finding{
		{
			AnalyzerName: "regex",
			RuleID:       "regex-block-dd",
			Decision:     "BLOCK",
			Confidence:   0.70,
			Reason:       "regex blocks dd",
			TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
		},
		{
			AnalyzerName: "structural",
			RuleID:       "st-allow-dd-to-file",
			Decision:     "ALLOW",
			Confidence:   0.90,
			Reason:       "dd to regular file, not block device",
			TaxonomyRef:  "destructive-ops/disk-ops/disk-overwrite",
			Tags:         []string{"structural-override"},
		},
	}
	result := c.Combine(findings, "AUDIT")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW (structural override), got %s", result.Decision)
	}
}

func TestCombiner_WeightedVote_BlockBonus(t *testing.T) {
	c := NewCombiner(StrategyWeightedVote)
	findings := []Finding{
		{AnalyzerName: "regex", RuleID: "r1", Decision: "AUDIT", Confidence: 0.60, Reason: "audit"},
		{AnalyzerName: "structural", RuleID: "s1", Decision: "BLOCK", Confidence: 0.50, Reason: "block"},
	}
	result := c.Combine(findings, "AUDIT")
	// BLOCK gets 0.50 * 1.5 = 0.75, AUDIT gets 0.60. BLOCK wins.
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK (weighted), got %s", result.Decision)
	}
}
