package mcp

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
)

// orderGateSeed pins the shuffle so a red run is reproducible. A random seed
// would make the gate report a different scenario set on every run, which is
// the property that makes an intermittent failure get muted rather than fixed.
const orderGateSeed = 33920816

// scenarioOrderDiff evaluates corpus twice with eval — once in registration
// order, once in the order given by perm — and returns the ids whose verdict
// differs between the two passes, sorted.
//
// eval is a parameter rather than a hard-wired call so the gate can be tested
// with a deliberately order-dependent evaluator; see
// TestMCPScenarioOrderGateDetectsOrderDependence.
func scenarioOrderDiff(corpus []scenarios.Scenario, perm []int, eval func(scenarios.Scenario) string) []string {
	registration := make(map[string]string, len(corpus))
	for _, sc := range corpus {
		registration[sc.ID] = eval(sc)
	}

	var differing []string
	for _, i := range perm {
		sc := corpus[i]
		if got := eval(sc); got != registration[sc.ID] {
			differing = append(differing, fmt.Sprintf("%s (registration=%s shuffled=%s)", sc.ID, registration[sc.ID], got))
		}
	}
	sort.Strings(differing)
	return differing
}

// permMovedCount reports how many positions perm actually moves. A permutation
// that happened to be (near-)identity would make the whole gate vacuous while
// still passing — the "0 found is a claim about your check" failure mode.
func permMovedCount(perm []int) int {
	moved := 0
	for pos, i := range perm {
		if pos != i {
			moved++
		}
	}
	return moved
}

// TestMCPScenarioVerdictsAreOrderIndependent is the fitness function for
// issue #3392: a scenario's verdict must be a function of the scenario, never
// of its position in the registration list.
//
// # Why this test exists
//
// The scenario harness shares one evaluation context across the whole corpus
// because building one costs ~110ms and there are 5.6k scenarios. Before #3392
// that context was a *MessageHandler, which accumulates per-session state that
// several detectors read (call_history, bounded_history, threshold_poisoning,
// approval_fatigue, subagent_tracker, capability_expansion). Nothing stopped a
// scenario kind from reading it, and if one had, every scenario registered
// after it would have been evaluated against state its own definition does not
// describe. That is invisible: it surfaces as an unrelated scenario flipping
// when someone inserts a scenario in the middle of the list, which reads as a
// rule regression.
//
// # What was actually measured (2026-08-31, corpus = 5612 scenarios)
//
//	shared context, registration order vs shuffled order     0 of 5612 differ
//	shared context vs a freshly built context per evaluation 0 of 5612 differ
//	each scenario evaluated twice back-to-back               0 of 5612 differ
//
// So the corpus was already order-independent, and the "29.2% corpus bypass"
// that #3392 was filed over is not explained by handler lifetime — it
// reproduces identically with a fresh handler per evaluation (see the PR).
// The hazard being closed here is structural, not observed: evaluateScenarioFromDef
// now takes a *PolicyEvaluator, which holds no session state, so reintroducing
// the coupling is a compile error rather than a silent measurement fault. This
// test is what catches the routes the type system cannot — package-level
// mutable state in a scanner, or in-place mutation of the shared scenario
// definitions.
//
// # How to keep it green
//
// Do not give a scenario kind access to session state. If cross-call sequence
// scenarios are ever wanted, they need their own entry point and their own
// explicit opt-out from this gate — never a widened parameter on the shared one.
func TestMCPScenarioVerdictsAreOrderIndependent(t *testing.T) {
	evaluator := newTestMCPEvaluator(t)
	corpus := scenarios.AllScenarios()

	if len(corpus) == 0 {
		t.Fatal("empty scenario corpus — the gate would pass vacuously")
	}

	perm := rand.New(rand.NewSource(orderGateSeed)).Perm(len(corpus)) //nolint:gosec // deterministic test shuffle, not crypto

	// Positive control on the INPUT: the shuffle must actually reorder. A
	// permutation that left everything in place would make "0 differ" mean
	// nothing at all.
	moved := permMovedCount(perm)
	if minMoved := len(corpus) / 2; moved < minMoved {
		t.Fatalf("shuffle is vacuous: only %d of %d positions moved (want >= %d)", moved, len(corpus), minMoved)
	}

	differing := scenarioOrderDiff(corpus, perm, func(sc scenarios.Scenario) string {
		return evaluateScenarioFromDef(evaluator, sc)
	})

	if len(differing) > 0 {
		t.Errorf("%d of %d scenarios changed verdict when the corpus was evaluated in a different order "+
			"(seed=%d, %d positions moved). Corpus measurements taken through this harness are not "+
			"reproducible until this is zero:\n  %v",
			len(differing), len(corpus), orderGateSeed, moved, differing)
	}

	t.Logf("order-independent: %d of %d scenarios differ between registration order and shuffle(seed=%d); %d positions moved",
		len(differing), len(corpus), orderGateSeed, moved)
}

// TestMCPScenarioOrderGateDetectsOrderDependence is the gate on the gate
// (#3130: a gate that cannot fail is worse than no gate).
//
// It drives scenarioOrderDiff — the exact comparison the real gate uses — with
// two synthetic evaluators over a synthetic corpus, so it costs nothing and
// needs no packs:
//
//   - a PURE evaluator, whose verdict depends only on the scenario, must produce
//     an empty diff. Without this the "catches it" assertion below could be
//     satisfied by a comparator that flags everything.
//   - an ORDER-DEPENDENT evaluator, whose verdict depends only on how many times
//     it has been called, must produce a non-empty diff.
func TestMCPScenarioOrderGateDetectsOrderDependence(t *testing.T) {
	const n = 64
	corpus := make([]scenarios.Scenario, n)
	for i := range corpus {
		corpus[i] = scenarios.Scenario{
			ID:               fmt.Sprintf("SYNTH-%03d", i),
			ToolName:         "synthetic",
			ExpectedDecision: "ALLOW",
			Classification:   "TN",
		}
	}
	perm := rand.New(rand.NewSource(orderGateSeed)).Perm(n) //nolint:gosec // deterministic test shuffle, not crypto

	// Negative control: a pure evaluator must look clean.
	pure := func(sc scenarios.Scenario) string {
		if sc.ID[len(sc.ID)-1] == '0' {
			return "BLOCK"
		}
		return "ALLOW"
	}
	if diff := scenarioOrderDiff(corpus, perm, pure); len(diff) != 0 {
		t.Fatalf("comparator flagged a pure evaluator: %d of %d differ — the gate reports noise, so its "+
			"clean result would prove nothing:\n  %v", len(diff), n, diff)
	}

	// Positive control: a verdict that depends on call index, not on the
	// scenario, is exactly the defect #3392 describes.
	calls := 0
	orderDependent := func(scenarios.Scenario) string {
		calls++
		if calls%2 == 0 {
			return "AUDIT"
		}
		return "BLOCK"
	}
	diff := scenarioOrderDiff(corpus, perm, orderDependent)
	if len(diff) == 0 {
		t.Fatalf("comparator did not notice an evaluator whose verdict is a pure function of call index "+
			"over %d scenarios — the real gate cannot fail", n)
	}

	t.Logf("gate self-test: pure evaluator 0 of %d flagged; order-dependent evaluator %d of %d flagged",
		n, len(diff), n)
}
