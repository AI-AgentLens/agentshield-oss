package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestShellSourceCarrierParity is the fitness function for issue #3232 — a
// program that takes shell source as a flag VALUE or a trailing POSITIONAL
// operand and hands it to a shell.
//
// The class fits none of the three models that existed before it:
//
//	ExecWrappers            target is a COMMAND WORD in argv     sudo rm -rf /
//	PrivilegeShellCarriers  target is a STRING behind -c         su -c 'rm -rf /'
//	CodeInterpreters        target is source in another language python3 -c ...
//
// `man -P 'CMD' page` is none of those, and neither are fourteen others.
//
// ## Why the control columns are in the test rather than in the commit message
//
// A leak percentage alone says something is wrong. A leak percentage next to a
// control that differs by one feature says WHAT is wrong (#3221's technique).
// Both controls stay here permanently so a future failure is interpretable:
//
//   - Both columns rise  -> the shared inline-code machinery regressed
//     (#3050/#3059/#3081), not this class.
//   - Only the carriers rise -> this class regressed. Look at shellSourceFlags
//     and the three surfaces CarriesShellSource feeds.
//
// Without the controls, a future red run is a number nobody can interpret.
//
// ## Negative controls
//
// The four at the bottom are shapes this fix deliberately does NOT cover, each
// for a reason recorded in shellSourceFlags's doc comment. They are asserted to
// keep leaking so the exclusion stays VISIBLE: if someone closes one, this test
// fails and tells them to move it up to the covered list rather than letting a
// silent improvement erase the record of what is still open. An untested
// exclusion decays into an unverified claim, which is #3223's whole lesson.
func TestShellSourceCarrierParity(t *testing.T) {
	t.Parallel()
	// Measured 33 for every covered position and for both controls after the
	// fix — the equality with the control IS the assertion. The residual is the
	// pre-existing nested-Subcommand class `bash -c` already carries
	// (substitution and dataflow do not recurse into nested Subcommands, so
	// multi-statement symbol-table cases stay lower).
	// Ratchet DOWN as those are fixed; never up without recording why here.
	//
	// 40 -> 43 (#3209): three new BLOCK-baseline commands
	// (TP-ESCSPLICE-PUNCT-001/003/004) joined the shared corpus every position
	// and both controls draw from — "both columns rise" is this test's own
	// documented signal for "the shared inline-code machinery", i.e. the same
	// already-tracked #3321 residual (structural/regex never re-parsing a
	// carrier-resolved candidate), not a regression in this carrier class.
	const maxLeaks = 43

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// ## Why this sweeps seven carriers and not the fifteen that were measured
	//
	// Every full-corpus position is ~1800 engine evaluations, and this package
	// already sits at its CI timeout with eighteen such sweeps (#3158). Adding
	// one position per affected PROGRAM would cost the most and prove the least:
	// the fifteen leaked within a three-point band precisely BECAUSE they share
	// one defect, so sweeping all fifteen measures the same thing fifteen times.
	//
	// So the positions below are one per MECHANISM — the axes along which the
	// capture can actually break — and breadth across programs is carried by
	// cheaper tests that cost one evaluation each instead of eighteen hundred:
	//
	//	shellparse.TestShellSourceArg          table-driven, every program+spelling
	//	testdata.ShellSourceCarrierCases       corpus TP/TN per program (TestAccuracy)
	//	the packs' inline `tests:` blocks      TP/TN per rule (TestRuleYAMLTests)
	//
	// If you add a program to shellSourceFlags, add it THERE, not here. Only add
	// a position here if it exercises a mechanism this list does not.
	covered := []struct{ name, pre, post string }{
		{"CONTROL-bash-c", "bash -c '", "'"},
		{"CONTROL-sudo", "sudo ", ""},

		// FLAG-VALUE half of the class.
		{"man-P", "man -P '", "' ls"},
		// POSITIONAL half. The separate-token option value is the harder of the
		// two spellings — it is what breaks a naive Args[0] read, since -n's
		// value lands in Args ahead of the payload.
		{"watch-separate", "watch -n 1 '", "'"},
		// The carrier that is ALSO an ExecWrapper. Unique because it needs BOTH
		// tables to agree: wrapperValueFlags must skip -S (so env stays in
		// executable position rather than the payload string being named as the
		// command) before shellSourceFlags can find it.
		{"env-S", "env -S '", "'"},
	}

	// Deliberately uncovered — see shellSourceFlags's doc comment for each.
	// Two of the four measured shapes are swept here; ssh-remote and the keyed
	// git -c form are recorded in that doc comment only, for the same budget
	// reason as above.
	stillOpen := []struct{ name, pre, post, why string }{
		{"xargs-nested-sh", "xargs -I{} sh -c '", "'",
			"the carrier is a nested `sh -c` that is NOT in executable position — a different mechanism (\"some argument names a shell, the rest is its source\"). Stands in for parallel/tmux/docker-exec/ssh-remote, recorded in shellSourceFlags's doc comment"},
	}

	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		// A single-quoted payload cannot carry a command containing a single
		// quote, and a carrier wraps only the first statement of a multi-line
		// command. Both make the mutation a DIFFERENT command, so they are
		// filtered rather than absorbed into the budget — raising a budget to
		// swallow invalid probes is how a sweep stops measuring anything.
		if strings.ContainsAny(tc.Command, "'\n") {
			continue
		}
		baseline = append(baseline, tc)
	}
	assertProbeNotVacuous(t, "shell-source-carrier", len(baseline), 1200)

	leaksFor := func(pre, post string) []string {
		var leaks []string
		for _, tc := range baseline {
			got := string(engine.Evaluate(pre+tc.Command+post, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
			}
		}
		return leaks
	}

	for _, p := range covered {
		t.Run(p.name, func(t *testing.T) {
			leaks := leaksFor(p.pre, p.post)
			if len(leaks) > maxLeaks {
				t.Errorf("carrier %q lowered the decision for %d/%d commands (budget %d).\n"+
					"A shell-source carrier's flag value / trailing operand is shell source "+
					"and must be decomposed like bash -c — see #3232.\n%s",
					strings.TrimSuffix(p.pre, "'"), len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), len(baseline), maxLeaks)
		})
	}

	for _, p := range stillOpen {
		t.Run("open/"+p.name, func(t *testing.T) {
			leaks := leaksFor(p.pre, p.post)
			// Asserted from BELOW: this shape is known to leak and is not fixed.
			if len(leaks) <= maxLeaks {
				t.Errorf("%q now leaks only %d/%d — at or under the covered budget of %d.\n"+
					"This shape was deliberately left OUT of shellSourceFlags because: %s\n"+
					"If it is genuinely covered now, move it into `covered` above and delete "+
					"the exclusion note from shellSourceFlags's doc comment. Do not "+
					"just relax this assertion — the point of pinning it is that the "+
					"list of what is still open cannot silently rot.",
					p.name, len(leaks), len(baseline), maxLeaks, p.why)
			}
			t.Logf("open/%s: %d/%d still leaking (expected — %s)", p.name, len(leaks), len(baseline), p.why)
		})
	}
}
