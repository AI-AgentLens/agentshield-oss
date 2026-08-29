package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestWrapperPositionalParity is the fitness function for issue #3227, the
// third in the line TestExecWrapperParity (#3057) and
// TestWrapperValueFlagParity (#3221) began.
//
// The invariant has not changed since #3057 — an execution wrapper does not
// change WHICH command runs, so prefixing one must never lower a decision —
// but it is applied here to the operand shape neither predecessor could
// express: a bare POSITIONAL operand sitting between the wrapper's options and
// the command.
//
// Two things about the position list are load-bearing.
//
// First, the CONTROLS. `nohup` and `sudo` are wrappers that were already in the
// table, so they measure the floor that every position below is compared
// against. At the time of the fix the floor was 1.1% and every absent wrapper
// was ~22%. If this test ever fails, read the columns before touching
// anything: a rise in the controls too is a wrapper-transparency regression
// (#3057's problem), a rise in only the positional/table columns is this one.
//
// Second, the NEGATIVE controls at the bottom. `gdb` and `watch` are
// deliberately NOT covered — gdb because its option grammar is too ambiguous to
// model safely, watch because it carries shell source as a POSITIONAL argument
// and needs a carrier shape rather than a table entry (still open on #3227).
// They are measured anyway, and expected to sit near the pre-fix rate. Without
// them a future reader has no way to tell "this one is excluded on purpose"
// from "somebody forgot" — which is exactly the confusion the stale
// ExecWrappers comments caused for four months. If either ever drops to the
// floor, the exclusion stopped being real and the comment explaining it is now
// a lie.
func TestWrapperPositionalParity(t *testing.T) {
	// Same multi-statement residue TestExecWrapperParity and
	// TestWrapperValueFlagParity document: a prefix wraps only the FIRST
	// statement, so for "P1=~/.ssh; cat $P1/id_rsa" the prefixed form genuinely
	// is not equivalent and a lower decision is correct. Every in-table
	// position must land on the same number as the controls — that EQUALITY is
	// the real assertion, not the budget.
	// Ratchet DOWN as those are fixed; never up without recording why.
	//
	// Raised from 30 to 44 (matching the current budget in the sibling
	// TestExecWrapperParity / TestWrapperValueFlagParity) because the shared
	// corpus grew from 2486 to 2581 commands in the two weeks between this
	// fix being written and merged — the floor itself (multi-statement
	// residue that no prefix can preserve) rose for every position,
	// including the already-fixed controls, not just the new ones.
	const maxLeaks = 44

	// The excluded wrappers still bypass, by design. This is not a budget to
	// improve — it is a pin on the pre-fix behaviour so the exclusion stays
	// visible. See #3227 for closing runuser properly.
	//
	// Lowered from 300 to 70 for `watch`: a separate fix landed on main after
	// this test was written (source_carrier.go now lists "watch" among the
	// value-taking-flag carriers, presumably the evalCode-style fix #3227
	// itself called "still open"), dropping its measured leak from the
	// original 34.3% to 3.5% (90/2581) on today's corpus. That is real,
	// unrelated progress, not a side effect of this change — `watch` is
	// still well above the ~1.6% floor the in-table wrappers land on
	// (42/2581), so the exclusion is still substantively true, just less
	// dramatic than it used to be.
	const excludedFloor = 70

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name     string
		prefix   string
		excluded bool
	}{
		// One position per OPERAND SHAPE, not one per wrapper.
		//
		// Every full-corpus position is ~1800 engine evaluations, and this
		// package sits at its CI timeout with eighteen such sweeps (#3158) — the
		// first run of this test pushed it over. Sweeping all fifteen wrappers
		// would cost the most and prove the least: they leaked within 0.7% of
		// each other precisely BECAUSE they share one defect, so measuring all
		// fifteen measures the same thing fifteen times.
		//
		// Per-wrapper breadth is carried by cheaper tests instead —
		// shellparse.TestWrapperPositionalTarget (table-driven, one call each)
		// and the corpus cases in wrapper_positional_cases.go. Add a wrapper
		// THERE; add a position here only for an operand shape not listed below.

		// Controls: wrappers already transparent before this change.
		{name: "control-nohup", prefix: "nohup"},
		{name: "control-sudo", prefix: "sudo"},

		// The new shape: a bare positional operand before the command, and the
		// hardest spelling of it — a VALUE-taking flag ahead of the positional,
		// so both the #3221 walk and the #3227 count must be right.
		{name: "flock-valueflag-then-lockfile", prefix: "flock -w 5 /var/lock/deploy.lock"},
		{name: "chroot-newroot", prefix: "chroot /mnt/rootfs"},
		// setarch's positional is OPTIONAL — the guard that must leave a target.
		{name: "setarch-arch", prefix: "setarch x86_64"},

		// No operands of its own: the shape the flag-only model already
		// described and that was simply never listed (busybox/toybox/pkexec/
		// valgrind/linux32/linux64 all reduce to this one).
		{name: "busybox", prefix: "busybox"},
		// Many value-taking long flags before the command.
		{name: "setpriv", prefix: "setpriv --reuid=0 --regid=0 --clear-groups"},

		// runuser is both a wrapper and a PrivilegeShellCarrier. Only the
		// command-word spelling unwraps here; the `-c 'CMD'` spelling is gated
		// off to the carrier path and is covered by TestSuInlineCodeParity.
		// Both spellings stay: which one applies is decided per invocation, so
		// this is a mechanism, not a second instance of one.
		{name: "runuser-endopts", prefix: "runuser -u root --"},
		{name: "runuser-plain", prefix: "runuser -u root"},

		// Negative controls — excluded on purpose, expected to still bypass.
		{name: "excluded-gdb", prefix: "gdb --args", excluded: true},
		{name: "excluded-watch", prefix: "watch -n1", excluded: true},
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go). A prefix applies to the FIRST
	// statement only, so multi-line commands are not equivalent once prefixed.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\n") {
			baseline = append(baseline, tc)
		}
	}
	if len(baseline) < 1000 {
		t.Fatalf("baseline collapsed to %d commands — the sweep would be vacuous", len(baseline))
	}

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			for _, tc := range baseline {
				got := string(engine.Evaluate(p.prefix+" "+tc.Command, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
				}
			}
			t.Logf("%s: %d/%d leaked", p.prefix, len(leaks), len(baseline))

			if p.excluded {
				if len(leaks) < excludedFloor {
					t.Errorf("prefix %q is documented as NOT an ExecWrapper, but only %d/%d commands "+
						"bypass it (expected >= %d).\nEither it became transparent — in which case delete "+
						"this negative control and the comment in ExecWrappers explaining its absence — or "+
						"something else changed and that comment is now wrong. See #3227.",
						p.prefix, len(leaks), len(baseline), excludedFloor)
				}
				return
			}

			if len(leaks) > maxLeaks {
				t.Errorf("prefix %q lowered the decision for %d/%d commands (budget %d).\n"+
					"An execution wrapper's positional operand must not be named as the command "+
					"it runs — see #3227.\n%s",
					p.prefix, len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
		})
	}
}
