package analyzer

// StatefulRule is the analyzer-side representation of a user-defined stateful
// rule from YAML. It matches multi-step attack chains within compound commands
// by checking segment sequences connected by operators.
//
// Inspired by classical control flow analysis, adapted for shell command chains:
//   - Chain steps match against command segments (executable, flags, args)
//   - Operators (&&, ||, ;, |) connect steps and must match
//   - The chain is matched as a subsequence (steps can be non-adjacent)
//
// Example: "curl -o x.sh && chmod +x x.sh && ./x.sh" matches a chain of
// [curl with -o] → [&&] → [chmod] → [&&] → [execution]
type StatefulRule struct {
	// Rule metadata
	ID         string
	Decision   string
	Confidence float64
	Reason     string
	Taxonomy   string

	// Chain pattern
	Chain []ChainStepRule // ordered sequence of steps to match

	// Modifiers
	Negate bool
}

// ChainStepRule is one step in a stateful chain pattern.
type ChainStepRule struct {
	ExecutableAny []string // segment executable is one of these
	FlagsAny      []string // segment has at least one of these flags
	FlagsNone     []string // segment must NOT have any of these flags
	ArgsAny       []string // any positional arg matches glob
	Operator      string   // operator connecting to next step: "&&", "||", ";", "|"
}

// MatchStatefulRule evaluates a stateful rule against the parsed command's
// segments and operators. The chain is matched as a subsequence — steps can
// be non-adjacent but must appear in order.
func MatchStatefulRule(parsed *ParsedCommand, rule StatefulRule) bool {
	if parsed == nil || len(parsed.Segments) == 0 || len(rule.Chain) == 0 {
		return applyNegate(false, rule.Negate)
	}

	matched := matchChain(parsed, rule.Chain)
	return applyNegate(matched, rule.Negate)
}

// matchChain attempts to match the chain steps against segments and operators
// in order. Each step must match a segment, and operator constraints must
// match the operator between the matched segments.
func matchChain(parsed *ParsedCommand, chain []ChainStepRule) bool {
	segments := parsed.Segments
	operators := parsed.Operators

	if len(segments) < countSegmentSteps(chain) {
		return false
	}

	// Track which chain step we're trying to match next
	chainIdx := 0
	lastMatchedSegIdx := -1

	for segIdx := 0; segIdx < len(segments) && chainIdx < len(chain); segIdx++ {
		step := chain[chainIdx]

		// Skip operator-only steps (they constrain the connection, not a segment)
		if step.Operator != "" && len(step.ExecutableAny) == 0 && len(step.FlagsAny) == 0 && len(step.ArgsAny) == 0 {
			// This is an operator constraint between previous and next segment steps
			// Check if the operator between lastMatched and the next match is correct
			if lastMatchedSegIdx >= 0 && lastMatchedSegIdx < len(operators) {
				if operators[lastMatchedSegIdx] != step.Operator {
					// Operator doesn't match — chain broken
					return false
				}
			}
			chainIdx++
			segIdx-- // re-check this segment against the next chain step
			continue
		}

		// Try to match this segment against the current chain step
		if matchChainStep(segments[segIdx], step) {
			// Check operator constraint on this step (if it connects to next)
			if step.Operator != "" && segIdx < len(operators) {
				if operators[segIdx] != step.Operator {
					continue // operator doesn't match, skip this segment
				}
			}

			// Check operator from previous step
			if lastMatchedSegIdx >= 0 && chainIdx > 0 {
				prevStep := chain[chainIdx-1]
				if prevStep.Operator != "" && lastMatchedSegIdx < len(operators) {
					if operators[lastMatchedSegIdx] != prevStep.Operator {
						continue // operator between prev and current doesn't match
					}
				}
			}

			lastMatchedSegIdx = segIdx
			chainIdx++
		}
	}

	// All chain steps must be matched
	return chainIdx >= len(chain)
}

// matchChainStep checks if a segment matches a single chain step.
func matchChainStep(seg CommandSegment, step ChainStepRule) bool {
	// --- ExecutableAny ---
	if len(step.ExecutableAny) > 0 {
		if !stringInList(seg.Executable, step.ExecutableAny) {
			return false
		}
	}

	// --- FlagsAny ---
	if len(step.FlagsAny) > 0 {
		found := false
		for _, flag := range step.FlagsAny {
			if segmentHasFlag(seg, flag) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// --- FlagsNone: disqualify if segment has any of these flags ---
	for _, flag := range step.FlagsNone {
		if segmentHasFlag(seg, flag) {
			return false
		}
	}

	// --- ArgsAny ---
	if len(step.ArgsAny) > 0 {
		found := false
		for _, arg := range seg.Args {
			for _, pattern := range step.ArgsAny {
				if matchArgGlob(arg, pattern) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	// At least one predicate must be specified
	if len(step.ExecutableAny) == 0 && len(step.FlagsAny) == 0 && len(step.ArgsAny) == 0 {
		return false
	}

	return true
}

// countSegmentSteps counts chain steps that match segments (not operator-only steps).
func countSegmentSteps(chain []ChainStepRule) int {
	count := 0
	for _, step := range chain {
		if len(step.ExecutableAny) > 0 || len(step.FlagsAny) > 0 || len(step.FlagsNone) > 0 || len(step.ArgsAny) > 0 {
			count++
		}
	}
	return count
}
