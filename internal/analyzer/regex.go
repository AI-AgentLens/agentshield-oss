package analyzer

import (
	"regexp"
	"strings"
)

// RegexRule is a simplified rule representation for the regex analyzer.
// It mirrors the fields from policy.Rule that the regex analyzer needs,
// avoiding an import cycle with the policy package.
type RegexRule struct {
	ID            string
	Decision      string
	Confidence    float64
	Reason        string
	Taxonomy      string
	Exact         string
	Prefixes      []string
	Regex         string
	RegexExclude  string // if non-empty, suppress the match when this pattern matches
}

// RegexAnalyzer wraps the existing regex/prefix/exact rule matching logic
// as an Analyzer in the pipeline. This is Layer 0 — the fastest and most
// basic analysis layer.
type RegexAnalyzer struct {
	rules []RegexRule
}

// NewRegexAnalyzer creates a regex analyzer from RegexRule definitions.
func NewRegexAnalyzer(rules []RegexRule) *RegexAnalyzer {
	return &RegexAnalyzer{rules: rules}
}

func (a *RegexAnalyzer) Name() string { return "regex" }

// Analyze evaluates the raw command against all regex/prefix/exact rules.
// Returns one Finding per matching rule.
func (a *RegexAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	var findings []Finding
	for _, rule := range a.rules {
		if matchRegexRule(ctx.RawCommand, rule) {
			f := Finding{
				AnalyzerName: "regex",
				RuleID:       rule.ID,
				Decision:     rule.Decision,
				Confidence:   rule.Confidence,
				Reason:       rule.Reason,
				TaxonomyRef:  rule.Taxonomy,
			}
			if f.Confidence == 0 {
				f.Confidence = 0.70 // default regex confidence
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// matchRegexRule checks if a command matches a single rule (exact, prefix, or regex).
func matchRegexRule(command string, rule RegexRule) bool {
	if rule.Exact != "" {
		if command == rule.Exact {
			return true
		}
	}

	for _, prefix := range rule.Prefixes {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}

	if rule.Regex != "" {
		re, err := regexp.Compile(rule.Regex)
		if err == nil && re.MatchString(command) {
			// Check exclusion pattern: if it matches, suppress this finding.
			if rule.RegexExclude != "" {
				reExcl, err := regexp.Compile(rule.RegexExclude)
				if err == nil && reExcl.MatchString(command) {
					return false
				}
			}
			return true
		}
	}

	return false
}
