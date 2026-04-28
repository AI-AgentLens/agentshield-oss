package analyzer

// CombineStrategy determines how the combiner merges findings from all analyzers.
type CombineStrategy string

const (
	// StrategyMostRestrictive picks the highest-severity decision across all findings.
	// BLOCK > AUDIT > ALLOW. This is the safest default.
	StrategyMostRestrictive CombineStrategy = "most_restrictive"

	// StrategyWeightedVote weighs findings by confidence. Higher confidence
	// findings have more influence. Useful when analyzers disagree.
	StrategyWeightedVote CombineStrategy = "weighted_vote"
)

// CombinedResult is the output of the Combiner, kept free of policy imports
// to avoid import cycles. The engine converts this to policy.EvalResult.
type CombinedResult struct {
	Decision       string
	TriggeredRules []string
	Reasons        []string
	Findings       []Finding
}

// Combiner merges findings from all analyzers into a final CombinedResult.
//
// Strategies:
//   - most_restrictive: BLOCK wins over AUDIT wins over ALLOW
//   - weighted_vote: confidence-weighted voting (future)
//
// Corroboration: if 2+ analyzers flag the same intent, confidence is boosted.
// Contradiction: if structural says ALLOW but regex says BLOCK, the combiner
// uses confidence + severity to resolve.
type Combiner struct {
	Strategy CombineStrategy
}

// NewCombiner creates a Combiner with the given strategy.
func NewCombiner(strategy CombineStrategy) *Combiner {
	if strategy == "" {
		strategy = StrategyMostRestrictive
	}
	return &Combiner{Strategy: strategy}
}

// Combine merges all findings into a final CombinedResult.
// The defaultDecision is used when no findings are present.
func (c *Combiner) Combine(findings []Finding, defaultDecision string) CombinedResult {
	result := CombinedResult{
		Decision:       defaultDecision,
		TriggeredRules: []string{},
		Reasons:        []string{},
		Findings:       findings,
	}

	if len(findings) == 0 {
		return result
	}

	switch c.Strategy {
	case StrategyWeightedVote:
		return c.combineWeightedVote(findings, defaultDecision)
	default:
		return c.combineMostRestrictive(findings, defaultDecision)
	}
}

// combineMostRestrictive picks the highest-severity decision.
// Among findings with the same severity, all rule IDs and reasons are collected.
// Special case: if a structural ALLOW contradicts a regex BLOCK at lower confidence,
// the structural ALLOW wins (structural is more precise than regex).
func (c *Combiner) combineMostRestrictive(findings []Finding, defaultDecision string) CombinedResult {
	result := CombinedResult{
		Decision:       defaultDecision,
		TriggeredRules: []string{},
		Reasons:        []string{},
		Findings:       findings,
	}

	// Check for analyzer ALLOW overrides (FP fixes).
	// A structural or semantic ALLOW with high confidence can override a regex BLOCK
	// for the same taxonomy. The finding must be tagged with "structural-override"
	// or "semantic-override".
	structuralAllows := map[string]Finding{}
	for _, f := range findings {
		if (f.AnalyzerName == "structural" || f.AnalyzerName == "semantic") &&
			f.Decision == "ALLOW" && f.Confidence >= 0.80 {
			for _, tag := range f.Tags {
				if tag == "structural-override" || tag == "semantic-override" {
					structuralAllows[f.TaxonomyRef] = f
				}
			}
		}
	}

	var bestSeverity int
	matched := false

	for _, f := range findings {
		// If a structural/semantic ALLOW override exists for this taxonomy, skip
		// non-structural/semantic findings that would BLOCK/AUDIT on the same taxonomy.
		if _, overridden := structuralAllows[f.TaxonomyRef]; overridden &&
			f.AnalyzerName != "structural" && f.AnalyzerName != "semantic" &&
			f.Decision != "ALLOW" {
			continue
		}

		// Also suppress generic regex findings (no taxonomy) when any override exists.
		// Generic rules are imprecise; semantic/structural overrides are authoritative.
		if len(structuralAllows) > 0 && f.AnalyzerName == "regex" &&
			f.Decision != "ALLOW" && f.TaxonomyRef == "" {
			continue
		}

		sev := decisionToSeverity(f.Decision)
		if !matched || sev > bestSeverity {
			bestSeverity = sev
			result.Decision = f.Decision
			result.TriggeredRules = []string{f.RuleID}
			result.Reasons = []string{f.Reason}
			matched = true
		} else if sev == bestSeverity {
			result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
			result.Reasons = append(result.Reasons, f.Reason)
		}
	}

	dedupeRulesAndReasons(&result)
	return result
}

// dedupeRulesAndReasons collapses identical (RuleID, Reason) pairs while
// preserving first-seen order. The shell pipeline's analyzers can each emit a
// finding for the same rule (regex + structural matching `rm -rf /` from the
// same RuleID, or a rule reachable via two pack files), and without dedupe
// the BLOCK output shows the same rule three or four times. Mirrors the MCP
// dedupe in internal/mcp/policy.go (issue #1628). Distinct RuleIDs and
// distinct reason wording for the same RuleID are preserved.
func dedupeRulesAndReasons(r *CombinedResult) {
	if len(r.TriggeredRules) <= 1 && len(r.Reasons) <= 1 {
		return
	}
	seen := make(map[string]bool, len(r.Reasons))
	rules := make([]string, 0, len(r.TriggeredRules))
	reasons := make([]string, 0, len(r.Reasons))
	n := len(r.Reasons)
	if len(r.TriggeredRules) < n {
		n = len(r.TriggeredRules)
	}
	for i := 0; i < n; i++ {
		key := r.TriggeredRules[i] + "\x00" + r.Reasons[i]
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, r.TriggeredRules[i])
		reasons = append(reasons, r.Reasons[i])
	}
	if len(r.TriggeredRules) > n {
		rules = append(rules, r.TriggeredRules[n:]...)
	}
	if len(r.Reasons) > n {
		reasons = append(reasons, r.Reasons[n:]...)
	}
	r.TriggeredRules = rules
	r.Reasons = reasons
}

// combineWeightedVote uses confidence-weighted voting.
func (c *Combiner) combineWeightedVote(findings []Finding, defaultDecision string) CombinedResult {
	result := CombinedResult{
		Decision:       defaultDecision,
		TriggeredRules: []string{},
		Reasons:        []string{},
		Findings:       findings,
	}

	weights := map[string]float64{}
	rules := map[string][]string{}
	reasons := map[string][]string{}

	for _, f := range findings {
		w := f.Confidence
		if w == 0 {
			w = 0.5
		}
		if f.Decision == "BLOCK" {
			w *= 1.5
		}
		weights[f.Decision] += w
		rules[f.Decision] = append(rules[f.Decision], f.RuleID)
		reasons[f.Decision] = append(reasons[f.Decision], f.Reason)
	}

	var bestDecision string
	var bestWeight float64
	for dec, w := range weights {
		if w > bestWeight {
			bestWeight = w
			bestDecision = dec
		}
	}

	if bestDecision != "" {
		result.Decision = bestDecision
		result.TriggeredRules = rules[bestDecision]
		result.Reasons = reasons[bestDecision]
	}

	dedupeRulesAndReasons(&result)
	return result
}

func decisionToSeverity(d string) int {
	switch d {
	case "BLOCK":
		return 3
	case "AUDIT":
		return 2
	case "ALLOW":
		return 1
	default:
		return 0
	}
}
