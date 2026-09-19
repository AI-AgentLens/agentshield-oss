package analyzer

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// #3752 — the round-3 adversarial pass on #3743/#3706. Seven findings, all
// reproduced on the installed binary before this file existed: six ways the
// ordered walk still disagreed with bash about WHERE a mutation lands, and one
// cost blow-up that made a 162-byte command take seconds inside a synchronous
// IDE hook.
//
// The engine-level assertions (which RULE ID carries the block) are in
// internal/policy/env_read_scope_test.go; these pin the mechanism, so a failure
// here says which sub-fix broke.

// Finding 1 — the RHS was evaluated TWICE: once by materializeAssignValue,
// against the pre-assignment table, and once again by the outer walk when it
// descended into the same Assign.Value. Every nesting level therefore doubled
// the work, so `V1=$(V2=$(…))` cost O(2^n).
//
// The budget is deliberately loose. This is not a latency fitness function
// competing with TestPipelinePerfBudget (quarantined, #3505) — the gap it
// guards is six orders of magnitude, not a factor of two: at 30 levels the
// doubling walk is ~2^30 node visits and a single evaluation is ~30. A machine
// slow enough to fail this test at 2s would fail every other test in the
// package first, so the co-tenancy flake mode that quarantined the P95 budget
// does not apply.
const nestedAssignSubstBudget = 2 * time.Second

// nestedAssignSubst builds `V1=$(V2=$(… Vn=$(true) …))`, the shape Codex
// measured at 2.79s for 22 levels and 9.8s for 24.
func nestedAssignSubst(levels int) string {
	inner := "true"
	for i := levels; i >= 1; i-- {
		inner = fmt.Sprintf("V%d=$(%s)", i, inner)
	}
	return inner
}

func TestScopeEval_NestedAssignSubstitutionIsNotExponential(t *testing.T) {
	cmd := nestedAssignSubst(30)
	start := time.Now()
	_ = runSubstitution(t, cmd)
	elapsed := time.Since(start)
	t.Logf("30 nested assignment substitutions (%d bytes) analysed in %v (budget %v)",
		len(cmd), elapsed, nestedAssignSubstBudget)
	if elapsed > nestedAssignSubstBudget {
		t.Fatalf("30 nested assignment substitutions took %v, budget %v — the RHS is being "+
			"walked more than once per level (#3752 finding 1)", elapsed, nestedAssignSubstBudget)
	}
}

// The shape of the curve, not just one point: doubling per level is what the
// bug was, so 24 levels must not cost several times 20. A linear walk is flat
// enough that a 4x ceiling over four extra levels has enormous headroom, while
// 2^4 = 16x does not fit under it.
func TestScopeEval_NestedAssignSubstitutionScalesLinearly(t *testing.T) {
	measure := func(levels int) time.Duration {
		cmd := nestedAssignSubst(levels)
		best := time.Hour
		for i := 0; i < 3; i++ {
			start := time.Now()
			_ = runSubstitution(t, cmd)
			if d := time.Since(start); d < best {
				best = d
			}
		}
		return best
	}
	base := measure(20)
	grown := measure(24)
	t.Logf("nested assignment substitutions: 20 levels %v, 24 levels %v", base, grown)
	// A floor keeps the ratio meaningful when both are microseconds: timer
	// granularity, not the walk, would otherwise decide the verdict.
	if base < 200*time.Microsecond {
		base = 200 * time.Microsecond
	}
	if grown > 4*base {
		t.Errorf("cost grew %.1fx over four extra nesting levels (20: %v, 24: %v) — "+
			"the RHS walk is still doubling per level (#3752 finding 1)",
			float64(grown)/float64(base), base, grown)
	}
}

// The reads inside a nested RHS must survive the de-duplication of the walk:
// the fix must stop walking the value TWICE, not stop walking it at all.
func TestScopeEval_AssignRHSStillMaterializesAfterSingleWalk(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; Q=$(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; Q=$(echo $(cat "$P/id_rsa"))`,
		`P=$HOME/.ssh; Q=$(true); cat "$P/id_rsa"`,
		// A ProcSubst RHS carries statements too, and wordHasCmdSubst never
		// saw it.
		`P=$HOME/.ssh; Q=<(cat "$P/id_rsa")`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: the read inside the RHS was lost, got %v", cmd, got)
		}
	}
}

// Finding 2 — a branch that may not run must not be able to OVERWRITE a
// binding either. Suppressing only removals left `false && P=/tmp` replacing
// the protected value outright, which hides the read just as effectively as an
// `unset` would have.
func TestScopeEval_SkippedBranchWritesCannotHideABinding(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; false && P=/tmp; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; true || P=/tmp; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; if false; then P=/tmp; fi; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; for i in 1; do P=/tmp; done; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; case x in x) P=/tmp;; esac; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; while false; do P=/tmp; done; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a conditional write erased the value the skipped path leaves, got %v", cmd, got)
		}
	}
	// The export attribute is state too: `false && export -n P` must not take
	// the child's view of P away.
	for _, cmd := range []string{
		`export P=$HOME/.ssh; false && export -n P; bash -c 'cat "$P/id_rsa"'`,
		`export P=$HOME/.ssh; if false; then declare +x P; fi; bash -c 'cat "$P/id_rsa"'`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a conditional un-export was applied unconditionally, got %v", cmd, got)
		}
	}
}

// Finding 3 — `$( )` runs in a CHILD shell, so its mutations cannot reach the
// parent. openRegion isolated Subshell and left command substitution sharing
// the parent's table, so `Q=$(unset P)` erased the parent's P.
func TestScopeEval_CommandSubstitutionIsIsolated(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; Q=$(unset P); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; Q=$(P=/tmp); cat "$P/id_rsa"`,
		"P=$HOME/.ssh; Q=`unset P`; cat \"$P/id_rsa\"",
		`P=$HOME/.ssh; echo $(unset P); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; diff <(unset P) /dev/null; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a command substitution's mutation escaped into the parent, got %v", cmd, got)
		}
	}
	// Isolation contains STATE, not reads — the materialized read inside the
	// substitution still flows out.
	for _, cmd := range []string{
		`P=$HOME/.ssh; Q=$(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; echo $(cat "$P/id_rsa")`,
		`P=$HOME/.ssh; diff <(cat "$P/id_rsa") /dev/null`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: isolating the substitution swallowed its read, got %v", cmd, got)
		}
	}
}

// Finding 4 — each pipeline COMPONENT gets its own environment. One region
// around the whole pipeline undid the writes at the end but let them leak
// sideways, so the left component's assignment reached the right one.
func TestScopeEval_PipelineComponentsDoNotShareMutations(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; P=/tmp | cat "$P/id_rsa"`,
		`P=$HOME/.ssh; unset P | cat "$P/id_rsa"`,
		`P=$HOME/.ssh; P=/tmp | true | cat "$P/id_rsa"`,
		`P=$HOME/.ssh; P=/tmp |& cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a pipeline component's mutation reached its neighbour, got %v", cmd, got)
		}
	}
}

// Finding 5 — eval runs in the CURRENT shell, so inside a subshell its
// mutations must be undone with that subshell. The eval child scope shared the
// parent's maps but carried no region stack, so nothing journalled its writes
// and the enclosing subshell had nothing to restore.
func TestScopeEval_EvalInsideAnIsolatedRegionIsStillContained(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; (eval 'unset P'); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; (eval 'P=/tmp'); cat "$P/id_rsa"`,
		`P=$HOME/.ssh; eval 'unset P' | true; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; false && eval 'unset P'; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: an eval inside an isolated or skipped region mutated the parent, got %v", cmd, got)
		}
	}
	// The control: a TOP-LEVEL eval does run in this shell and its unset does
	// apply, or the fix above degenerates into "eval never mutates".
	if got := runSubstitution(t, `P=$HOME/.ssh; eval 'unset P'; cat "$P/id_rsa"`); slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("a top-level eval's unset stopped applying, got %v", got)
	}
	if got := runSubstitution(t, `eval 'P=$HOME/.ssh'; cat "$P/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("a top-level eval's binding stopped applying, got %v", got)
	}
}

// Finding 6 — bash expands a simple command's ARGUMENTS before its prefix
// assignments take effect, so `P=/tmp cat "$P/config"` passes cat the OLD P.
// Binding the prefix first made the analyzer read the new value and miss the
// read entirely.
func TestScopeEval_PrefixAssignmentDoesNotReachItsOwnArgv(t *testing.T) {
	for _, cmd := range []string{
		`P=$HOME/.ssh; P=/tmp cat "$P/id_rsa"`,
		`P=$HOME/.ssh; P=/tmp Q=/tmp cat "$P/id_rsa"`,
		`P=$HOME/.ssh; P=/tmp cat < "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: argv was expanded against the prefix binding instead of the pre-prefix environment, got %v", cmd, got)
		}
	}
	// Controls: the prefix still reaches the command's ENVIRONMENT, which is
	// the whole point of the carrier inheritance...
	if got := runSubstitution(t, `P=$HOME/.ssh bash -c 'cat "$P/id_rsa"'`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("prefix binding stopped reaching the carrier environment, got %v", got)
	}
	// ...and a prefix that names a path in its OWN argv, with no earlier
	// binding, resolves to nothing rather than to the prefix value.
	if got := runSubstitution(t, `P=$HOME/.ssh cat "$P/id_rsa"`); slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("argv resolved a prefix binding bash had not yet applied, got %v", got)
	}
}

// Finding 7 — `printf -v` with a format this layer cannot reproduce still
// EXECUTED: bash overwrote the target with something unknown. Returning
// without touching the target left the previous, protected value in place and
// produced a false BLOCK.
func TestScopeEval_PrintfVInvalidatesWhatItCannotFold(t *testing.T) {
	for _, cmd := range []string{
		`printf -v P %s "$HOME/.ssh"; printf -v P %d 42; cat "$P/id_rsa"`,
		`printf -v P %s "$HOME/.ssh"; printf -v P %q x; cat "$P/id_rsa"`,
		`printf -v P %s "$HOME/.ssh"; printf -v P %s a b; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; printf -v P %d 42; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; printf -vP %d 42; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: an unfoldable printf -v left the stale protected value in place, got %v", cmd, got)
		}
	}
	// The invalidation is a REMOVAL, so a branch that may not run cannot
	// perform it: the previous value is still what the skipped path leaves.
	// Binding the target to the empty string instead would look identical on
	// every case above and be fail-open here.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && printf -v P %d 42; cat "$P/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("a conditional printf -v invalidated a binding the skipped path leaves in place, got %v", got)
	}
	// The negative control for the invalidation: a `-v` that is DATA, not the
	// binding option, must not invalidate anything.
	for _, cmd := range []string{
		`P=$HOME/.ssh; printf %s -v P x; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; printf -- -v P %s x; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; printf %d 42; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); !slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a printf that binds nothing invalidated the binding anyway, got %v", cmd, got)
		}
	}
}

// Bash-truth negative controls. Each of these is a construct that DOES run in
// the current shell, so the state change it makes is real and the read after it
// opens nothing. Without them the six fixes above could all be satisfied by
// "never let anything change the table", which is fail-safe in exactly the way
// that makes an analyzer useless.
func TestScopeEval_CurrentShellMutationsStillApply(t *testing.T) {
	for _, cmd := range []string{
		// A brace group is NOT a subshell: it runs in the current shell.
		`P=$HOME/.ssh; { unset P; }; cat "$P/id_rsa"`,
		`P=$HOME/.ssh; { P=/tmp; }; cat "$P/id_rsa"`,
		// A subshell's ASSIGNMENT does not escape, so nothing is bound after
		// it — the fixed-point seed must not supply the value either.
		`(P=$HOME/.ssh); cat "$P/id_rsa"`,
		`(export P=$HOME/.ssh); cat "$P/id_rsa"`,
		`P2=$HOME/.ssh | true; cat "$P2/id_rsa"`,
		// printf -v with a format that folds exactly, overwritten by one that
		// folds exactly.
		`printf -v P %s "$HOME/.ssh"; printf -v P %s /tmp; cat "$P/id_rsa"`,
	} {
		if got := runSubstitution(t, cmd); slices.Contains(got, "~/.ssh/id_rsa") {
			t.Errorf("%s: a real current-shell mutation was suppressed, got %v", cmd, got)
		}
	}
}

// The conservative merge has a cost, and it is stated here rather than
// discovered later: a conditional that REPLACES a protected binding with a
// benign one keeps both, so the protected read still resolves even when the
// branch always runs. That is the same asymmetry the removal rule already had
// (`P=<prot>; true || unset P` resolves the protected value); this test exists
// so the trade-off is visible and a future change to it is deliberate.
func TestScopeEval_ConditionalOverwriteKeepsBothValues(t *testing.T) {
	got := runSubstitution(t, `P=$HOME/.ssh; if true; then P=/tmp; fi; cat "$P/id_rsa"`)
	if !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("the pre-branch value was dropped, got %v", got)
	}
	if !slices.Contains(got, "/tmp/id_rsa") {
		t.Errorf("the branch's own value was dropped, got %v", got)
	}
}

// ...and the union is not permanent. Three properties decide when a candidate
// value dies, and each is a mutation the rest of this file would not catch.
func TestScopeEval_ConditionalAlternatesLifecycle(t *testing.T) {
	// A write that DEFINITELY happens destroys every earlier candidate: after
	// `P=/etc/ok` at the top level the shell holds /etc/ok on every path, and
	// keeping the protected candidate would be a false BLOCK.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && P=/tmp; P=/etc/ok; cat "$P/id_rsa"`); slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("an unconditional rebinding did not retire the conditional candidate, got %v", got)
	}
	// A write inside a region whose effect is DISCARDED does not: a subshell
	// cannot retire a value the parent may still hold.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && P=/tmp; (P=/x); cat "$P/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("a subshell retired a candidate it cannot destroy, got %v", got)
	}
	// A candidate survives one assignment hop, or the conditional merge is
	// defeated by writing `Q=$P` before the read.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && P=/tmp; Q=$P; cat "$Q/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("the candidate was lost across an assignment, got %v", got)
	}
	// And it reaches a carrier the child can see it through.
	if got := runSubstitution(t, `export P=$HOME/.ssh; false && export P=/tmp; bash -c 'cat "$P/id_rsa"'`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("the candidate was lost at the carrier boundary, got %v", got)
	}
	// An `unset` that DEFINITELY runs retires the candidate too — the fix for
	// a conditional overwrite must not turn a real `unset` into a false BLOCK.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && P=/tmp; unset P; cat "$P/id_rsa"`); slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("an unconditional unset did not retire the conditional candidate, got %v", got)
	}
	// eval runs in THIS shell, so it shares the candidate list in both
	// directions: it can read one, and one it creates outlives it.
	if got := runSubstitution(t, `P=$HOME/.ssh; false && P=/tmp; eval 'cat "$P/id_rsa"'`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("an eval body could not see the enclosing shell's candidate, got %v", got)
	}
	if got := runSubstitution(t, `P=$HOME/.ssh; eval 'false && P=/tmp'; cat "$P/id_rsa"`); !slices.Contains(got, "~/.ssh/id_rsa") {
		t.Errorf("a candidate created inside eval did not outlive it, got %v", got)
	}
}

// The union is bounded. A command with many conditional overwrites must not
// turn each read into a combinatorial expansion — the analyzer runs
// synchronously in the IDE hook, which is the same constraint finding 1 was
// about.
func TestScopeEval_ConditionalAlternatesAreBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("P=$HOME/.ssh; ")
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&sb, "if true; then P=/tmp/%d; fi; ", i)
	}
	sb.WriteString(`cat "$P/id_rsa"`)
	start := time.Now()
	got := runSubstitution(t, sb.String())
	elapsed := time.Since(start)
	t.Logf("200 conditional overwrites: %d materialized paths in %v", len(got), elapsed)
	if elapsed > nestedAssignSubstBudget {
		t.Errorf("200 conditional overwrites took %v, budget %v", elapsed, nestedAssignSubstBudget)
	}
}
