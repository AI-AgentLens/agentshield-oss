package analyzer_test

import (
	"sync"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// The parity fitness functions (TestCompoundWrappingParity #3045,
// TestLineContinuationParity #3055, TestExecWrapperParity #3057, and any that
// follow) all start from the same question: which corpus commands BLOCK today?
// Each one answering it separately meant a fresh ~1,100-rule engine plus a full
// ~2,400-command evaluation pass per test, and the analyzer package walked into
// the 10-minute go-test timeout on CI while passing locally in 7.
//
// The baseline is deterministic and read-only, so computing it once is not a
// shortcut — it is the same answer, shared. Each test still filters it for its
// own transform (quote-free, single-line, and so on): the SHARED part is the
// expensive part, the per-test part is a slice filter.
var (
	parityOnce     sync.Once
	parityEngine   *policy.Engine
	parityBaseline []testdata.TestCase
)

// blockingBaseline returns the shared pipeline engine and every corpus case
// that both expects BLOCK and actually gets it.
//
// Commands the engine already misses standalone are excluded on purpose: those
// are separate gaps, not leaks caused by the transform under test. Measuring
// against "what BLOCKs today" is what makes a non-zero leak budget meaningful.
func blockingBaseline(t *testing.T) (*policy.Engine, []testdata.TestCase) {
	t.Helper()
	parityOnce.Do(func() {
		parityEngine = newPipelineEngine(t)
		for _, tc := range testdata.AllTestCases() {
			if tc.ExpectedDecision != "BLOCK" {
				continue
			}
			if string(parityEngine.Evaluate(tc.Command, nil).Decision) == "BLOCK" {
				parityBaseline = append(parityBaseline, tc)
			}
		}
	})
	return parityEngine, parityBaseline
}

// assertProbeNotVacuous is the guard for parity sweeps that use a production
// transform as their own validity gate — TestGlobEvasionParity and
// TestGlobEvasionStructuralParity (shellparse.DeglobSensitivePaths),
// TestBraceExpansionParity and TestDoubleBraceExpansionParity
// (shellparse.ExpandBraces). Those tests skip any probe the transform does not
// resolve, which is right: a candidate a real shell would not expand either is
// not evidence of a bypass.
//
// The problem is what happens when the transform itself regresses. It stops
// resolving everything, so every candidate is skipped, `tried` collapses to 0,
// `leaks` stays empty, and the test reports PASS — vacuously green at exactly
// the moment the bypass it guards is wide open. A gate that cannot fail is
// worse than no gate: it launders an unverified claim into a green check.
//
// Verified by mutation on 2026-07-28. Neutering shellparse.ExpandBraces to
// return nil left TestBraceExpansionParity logging "0/0 leaked (budget 3)" and
// PASSING; neutering shellparse.DeglobSensitivePaths did the same to both glob
// sweeps. Neither reported anything unusual. With this floor in place all four
// fail loudly instead.
//
// The floor is set well under the measured denominator (roughly 75%) because it
// is a liveness check, not a coverage ratchet: it must survive ordinary corpus
// churn while still catching a transform that has stopped working. Ratchet UP
// as the corpus grows; never down without recording why here.
func assertProbeNotVacuous(t *testing.T, label string, tried, floor int) {
	t.Helper()
	if tried < floor {
		t.Fatalf("%s: probe produced only %d valid candidates (floor %d).\n"+
			"This test uses a production transform as its own validity gate, so a "+
			"collapsed denominator means that transform stopped resolving — the leak "+
			"count below is measured over nothing and proves nothing. Fix the transform, "+
			"or lower the floor here with the reason if the corpus genuinely shrank.",
			label, tried, floor)
	}
}
