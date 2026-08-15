package analyzer

import "github.com/AI-AgentLens/agentshield/internal/seqmatch"

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
// match the operator between the matched segments. The subsequence skeleton
// (greedy left-to-right, gaps allowed) is the shared seqmatch.Match; the
// operator constraints are enforced by the probe below.
func matchChain(parsed *ParsedCommand, chain []ChainStepRule) bool {
	segments := parsed.Segments
	operators := parsed.Operators

	if len(segments) < countSegmentSteps(chain) {
		return false
	}

	probe := func(step ChainStepRule, stepIdx int, seg CommandSegment, segIdx, lastMatchedSegIdx int) seqmatch.Outcome {
		// Operator-only steps constrain the connection, not a segment: the
		// operator after the last matched segment must be the required one
		// (hard failure otherwise), then the same segment is re-checked
		// against the next chain step.
		if step.Operator != "" && len(step.ExecutableAny) == 0 && len(step.FlagsAny) == 0 && len(step.ArgsAny) == 0 {
			if lastMatchedSegIdx >= 0 {
				// Fail closed: if the connecting operator isn't known (index
				// out of range — e.g. the last segment, or a construct the
				// parser doesn't track operators for), don't assume it
				// satisfies the constraint. See #2889.
				if lastMatchedSegIdx >= len(operators) || operators[lastMatchedSegIdx] != step.Operator {
					return seqmatch.Abort // chain broken
				}
			}
			return seqmatch.StepSatisfied
		}

		if !matchChainStep(seg, step) {
			return seqmatch.Skip
		}

		// Check operator constraint on this step (if it connects to next).
		// Fail closed on unknown operator index — see #2889.
		if step.Operator != "" {
			if segIdx >= len(operators) || operators[segIdx] != step.Operator {
				return seqmatch.Skip // operator doesn't match or is unknown, skip this segment
			}
		}

		// Check operator from previous step. Matched segments can be
		// non-adjacent (e.g. "curl | jq | bash" matches [curl(|), bash] with
		// jq skipped in between), but the connection must be an UNBROKEN run
		// of prevStep.Operator all the way from the previously matched
		// segment to this candidate — not just the single operator
		// immediately after the previous match. Checking only that one index
		// let a chain "leak" across a statement boundary: with curl matched
		// at segIdx 0 and lastMatchedSegIdx pinned at 0, every later
		// candidate re-checked operators[0] (already verified by the
		// step.Operator check above) instead of the operator actually
		// connecting to the candidate — so "curl | grep | sed; python3 file"
		// satisfied a "download piped to interpreter" chain even though the
		// interpreter is a separate statement joined by ";", not "|" (#3277).
		if lastMatchedSegIdx >= 0 && stepIdx > 0 {
			prevStep := chain[stepIdx-1]
			if prevStep.Operator != "" {
				for i := lastMatchedSegIdx; i < segIdx; i++ {
					if i >= len(operators) || operators[i] != prevStep.Operator {
						return seqmatch.Skip // chain broken between prev match and here
					}
				}
			}
		}

		return seqmatch.Matched
	}

	return seqmatch.Match(chain, segments, nil, probe)
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
