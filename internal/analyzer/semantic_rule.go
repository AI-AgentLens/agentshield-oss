package analyzer

// UserSemanticRule is the analyzer-side representation of a user-defined semantic
// rule from YAML. It matches against the command's classified intents produced
// by the built-in semantic analyzer.
//
// This enables users to:
//   - Override decisions for specific intent categories (e.g., ALLOW "dns-query-safe")
//   - Elevate AUDIT intents to BLOCK (e.g., BLOCK anything with risk >= "high")
//   - Suppress false positives by intent (e.g., ALLOW "persistence" for CI/CD)
//
// Runs AFTER built-in semantic rules, matching against accumulated ctx.Intents.
type UserSemanticRule struct {
	// Rule metadata
	ID         string
	Decision   string
	Confidence float64
	Reason     string
	Taxonomy   string

	// Intent matching
	Intent    string   // exact intent category match
	IntentAny []string // any of these intent categories
	RiskMin   string   // minimum risk level: "critical" > "high" > "medium" > "low" > "info"

	// Modifiers
	Negate bool
}

// MatchSemanticRule evaluates a semantic rule against the accumulated intents.
// Returns true if any intent in the list satisfies all specified predicates.
func MatchSemanticRule(intents []CommandIntent, rule UserSemanticRule) bool {
	if len(intents) == 0 {
		// No intents classified — only matches if negated
		return applyNegate(false, rule.Negate)
	}

	matched := false

	for _, intent := range intents {
		if matchesSingleIntent(intent, rule) {
			matched = true
			break
		}
	}

	return applyNegate(matched, rule.Negate)
}

// matchesSingleIntent checks if one intent satisfies all rule predicates.
func matchesSingleIntent(intent CommandIntent, rule UserSemanticRule) bool {
	// --- Exact intent category ---
	if rule.Intent != "" {
		if intent.Category != rule.Intent {
			return false
		}
	}

	// --- IntentAny: category is one of these ---
	if len(rule.IntentAny) > 0 {
		if !stringInList(intent.Category, rule.IntentAny) {
			return false
		}
	}

	// --- RiskMin: intent risk meets minimum threshold ---
	if rule.RiskMin != "" {
		if riskLevel(intent.Risk) < riskLevel(rule.RiskMin) {
			return false
		}
	}

	// At least one criterion must be specified
	if rule.Intent == "" && len(rule.IntentAny) == 0 && rule.RiskMin == "" {
		return false
	}

	return true
}

// riskLevel converts a risk string to a numeric level for comparison.
// Higher number = higher risk.
func riskLevel(risk string) int {
	switch risk {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	case "none":
		return 0
	default:
		return 0
	}
}
