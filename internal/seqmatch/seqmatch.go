// Package seqmatch provides the ordered-subsequence matcher shared by the
// shell stateful chain matcher (internal/analyzer, segments of one compound
// command) and the MCP cross-call sequence matcher (internal/mcp, per-session
// call history): greedy left-to-right matching with gaps allowed and a
// minimum match count per step. Greedy matching is precision-first — once a
// step matches it is committed, with no backtracking.
package seqmatch

// Outcome is the result of probing one (step, item) pair.
type Outcome int

const (
	// Skip: the item does not satisfy the step — try the next item (gap).
	Skip Outcome = iota

	// Matched: the item satisfies the step and counts toward the step's
	// minimum match count.
	Matched

	// StepSatisfied: the step is satisfied without consuming the item
	// (zero-width steps, e.g. the shell chain's operator-only constraint
	// steps); the same item is re-probed against the next step.
	StepSatisfied

	// Abort: a hard constraint violation that fails the whole sequence
	// (e.g. the shell chain's operator-only step finding the wrong operator
	// after the last committed match).
	Abort
)

// Match reports whether items satisfies steps as an ordered subsequence.
//
// Steps are matched greedily left-to-right; items that do not satisfy the
// current step are skipped (gaps allowed). A step must accumulate
// minCount(step) matched items (nil or <1 means 1) before the sequence
// advances. probe receives the current step and item with their indices plus
// lastMatchedIdx — the index of the most recently matched item, or -1 —
// so callers can enforce positional constraints (the shell side's per-step
// operator checks). All steps must be satisfied for Match to return true.
func Match[S, T any](
	steps []S,
	items []T,
	minCount func(step S) int,
	probe func(step S, stepIdx int, item T, itemIdx, lastMatchedIdx int) Outcome,
) bool {
	need := func(i int) int {
		if minCount == nil {
			return 1
		}
		if n := minCount(steps[i]); n > 1 {
			return n
		}
		return 1
	}

	stepIdx := 0
	lastMatched := -1
	got := 0

	for itemIdx := 0; itemIdx < len(items) && stepIdx < len(steps); itemIdx++ {
		switch probe(steps[stepIdx], stepIdx, items[itemIdx], itemIdx, lastMatched) {
		case Abort:
			return false
		case StepSatisfied:
			stepIdx++
			got = 0
			itemIdx-- // re-probe the same item against the next step
		case Matched:
			got++
			if got >= need(stepIdx) {
				lastMatched = itemIdx
				stepIdx++
				got = 0
			}
		case Skip:
			// gap — try the next item
		}
	}

	return stepIdx >= len(steps)
}
