package seqmatch

import "testing"

// intProbe builds a probe matching items by equality with the step value.
func intProbe(step, _ int, item, _, _ int) Outcome {
	if item == step {
		return Matched
	}
	return Skip
}

func TestMatch_OrderedSubsequenceWithGaps(t *testing.T) {
	steps := []int{1, 2, 3}
	items := []int{9, 1, 9, 2, 9, 9, 3}
	if !Match(steps, items, nil, intProbe) {
		t.Error("expected subsequence with gaps to match")
	}
}

func TestMatch_OutOfOrderFails(t *testing.T) {
	steps := []int{1, 2, 3}
	items := []int{3, 2, 1}
	if Match(steps, items, nil, intProbe) {
		t.Error("out-of-order items must not match (no backtracking)")
	}
}

func TestMatch_UnsatisfiedStepFails(t *testing.T) {
	steps := []int{1, 2, 3}
	items := []int{1, 2}
	if Match(steps, items, nil, intProbe) {
		t.Error("sequence with an unsatisfied trailing step must not match")
	}
}

func TestMatch_EmptyStepsVacuouslyTrue(t *testing.T) {
	if !Match(nil, []int{1, 2}, nil, intProbe) {
		t.Error("empty steps must match vacuously (callers guard this case)")
	}
}

func TestMatch_EmptyItemsFails(t *testing.T) {
	if Match([]int{1}, nil, nil, intProbe) {
		t.Error("non-empty steps cannot match empty items")
	}
}

func TestMatch_MinCount(t *testing.T) {
	steps := []int{1, 2}
	minCount := func(step int) int {
		if step == 1 {
			return 3
		}
		return 1
	}
	// Only two 1s before the 2 — step 1 needs three.
	if Match(steps, []int{1, 1, 2}, minCount, intProbe) {
		t.Error("step requiring 3 matches must not advance after 2")
	}
	// Three 1s (with gaps) then a 2.
	if !Match(steps, []int{1, 9, 1, 1, 2}, minCount, intProbe) {
		t.Error("expected min-count step to accumulate matches across gaps")
	}
}

func TestMatch_MinCountBelowOneTreatedAsOne(t *testing.T) {
	minCount := func(int) int { return 0 }
	if !Match([]int{1}, []int{1}, minCount, intProbe) {
		t.Error("minCount < 1 must be treated as 1")
	}
}

func TestMatch_StepSatisfiedIsZeroWidth(t *testing.T) {
	// Steps: match 1, zero-width marker (-1), then match 2 — the marker must
	// consume no item, so [1, 2] satisfies all three steps.
	steps := []int{1, -1, 2}
	probe := func(step, _ int, item, _, _ int) Outcome {
		if step == -1 {
			return StepSatisfied
		}
		if item == step {
			return Matched
		}
		return Skip
	}
	if !Match(steps, []int{1, 2}, nil, probe) {
		t.Error("zero-width step must not consume an item")
	}
	// A zero-width step never probed (items exhausted first) leaves the
	// sequence unsatisfied.
	if Match(steps, []int{1}, nil, probe) {
		t.Error("zero-width step is only satisfied when probed against an item")
	}
}

func TestMatch_AbortFailsWholeSequence(t *testing.T) {
	// Abort on the marker even though a later 1 would satisfy step 0.
	probe := func(step, _ int, item, _, _ int) Outcome {
		if item == 666 {
			return Abort
		}
		if item == step {
			return Matched
		}
		return Skip
	}
	if Match([]int{1}, []int{666, 1}, nil, probe) {
		t.Error("Abort must fail the whole sequence immediately")
	}
}

func TestMatch_LastMatchedIdxReported(t *testing.T) {
	var seen []int
	steps := []int{1, 2}
	items := []int{1, 9, 2}
	probe := func(step, _ int, item, _, lastMatchedIdx int) Outcome {
		seen = append(seen, lastMatchedIdx)
		if item == step {
			return Matched
		}
		return Skip
	}
	if !Match(steps, items, nil, probe) {
		t.Fatal("expected match")
	}
	// Probes: item0/step0 (last=-1), item1/step1 (last=0), item2/step1 (last=0).
	want := []int{-1, 0, 0}
	if len(seen) != len(want) {
		t.Fatalf("expected %d probes, got %d (%v)", len(want), len(seen), seen)
	}
	for i := range want {
		if seen[i] != want[i] {
			t.Errorf("probe %d: lastMatchedIdx = %d, want %d", i, seen[i], want[i])
		}
	}
}
