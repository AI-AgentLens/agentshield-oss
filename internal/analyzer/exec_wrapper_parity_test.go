package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestExecWrapperParity is the fitness function for issue #3057, in the same
// shape as TestCompoundWrappingParity (#3045) and TestLineContinuationParity
// (#3055).
//
// The invariant: an execution wrapper does not change WHICH command runs, so
// prefixing one must never LOWER a decision. `env rm -rf /` is exactly as
// destructive as `rm -rf /`.
//
// The sweep covers all three defects at once, and the numbers separate them:
// before the fix, recognized wrappers leaked 11.1% (regex layer blind),
// unrecognized ones 19.9%, and path-qualified spellings of RECOGNIZED wrappers
// 20.2% — worse than the bare name they resolve to.
func TestExecWrapperParity(t *testing.T) {
	t.Parallel()
	// Residue: multi-statement commands ("P1=~/.ssh; cat $P1/id_rsa") where a
	// leading wrapper only applies to the FIRST statement, so the prefixed form
	// is not actually equivalent and a lower decision is correct.
	// Ratchet DOWN as these are fixed; never up without recording why here.
	//
	// 2026-08-03 (#3193): +3, from the read-array TP cases (TP-READ-ARRAY-EXEC-
	// 001/002/003) — the `read -a`/here-string sibling of TP-ARRAY-EXEC-001/2/3
	// above, same multi-statement residue: "exec read -ra parts <<< \"rm -rf
	// /\"; \"${parts[@]}\"" only wraps the first (`read`) statement, so the
	// array-splat exec in the second statement is unaffected by the prefix and
	// a lower decision there is correct, not a regression.
	// 2026-08-11 (#3248), +2: the declaration-clause fix closes the LITERAL forms
	// (`export x=rm; $x -rf /` and its export/declare/local/readonly/typeset
	// siblings). The new TP/TN-DECLBIND corpus cases measure what is still open:
	// the keyword delivered INDIRECTLY, e.g. `$(echo export) x=rm; $x -rf /`.
	//
	// That is a genuine leak, not an unindirectable keyword like `for`/`while` —
	// verified against bash, where `$(echo export) x=echo; $x hi` both binds and
	// runs. And it is PRE-EXISTING, not introduced here: on clean main (e778a77d)
	// both `$(echo export) x=rm; $x -rf /` and `eval export x=rm; $x -rf /`
	// already AUDIT. The budget moves because these cases now MEASURE the gap.
	//
	// Ratchets DOWN when the declaration keyword is handled as a COMMAND
	// (however spelled) rather than only as a syntax.DeclClause node.
	//
	// 2026-08-11 (#3203), +5: the sibling half of #3248 — Layer 2.5 path
	// materialization (analyzer.buildSymbolTable) now also resolves
	// declare/export/typeset/readonly/local bindings, same as the
	// executable-position resolver already did. The 5 new
	// TP-SSHKEY-SUBST-DECLBIND-* cases are multi-statement
	// (`declare P1=...; declare P2=...; cat $P1/$P2`), so they fall into the
	// SAME "residue" class already carved out above for TP-SSHKEY-SUBST-001..5
	// and TP-READ-ARRAY-EXEC-*: a leading wrapper only applies to the first
	// statement, so wrapping is not equivalent and a lower decision is
	// correct, not a regression. Confirmed: TP-SSHKEY-SUBST-001..005
	// (plain-assignment form, fixed pre-#3203) already leak here identically.
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of the #3193
	// read-array here-string binding — TP-READ-SCALAR-EXEC-001/002,
	// TP-READ-MAPFILE-EXEC-001, TP-READ-READARRAY-EXEC-001. Same multi-statement
	// residue as TP-READ-ARRAY-EXEC-* directly above: "exec read zc <<< \"rm
	// -rf /\"; $zc" only wraps the first (`read`) statement, so the bare $zc
	// exec in the second statement is unaffected by the prefix and a lower
	// decision there is correct, not a regression.
	//
	// 2026-08-12 (#3238), +3 (+2 for "exec"): TP-CARRIER-INDIRECT-EXEC-001/002/
	// 003 (carrier-body indirect-exec resolution — `zc='rm -rf /'; eval "$zc"`)
	// are multi-statement for the same reason as the DECLBIND/SSHKEY-SUBST/
	// READ-SCALAR-EXEC cases above: the wrapper prefix applies to the FIRST
	// statement (`zc='rm -rf /'`) only, leaving the second (`eval "$zc"`)
	// unprefixed — same documented residue class, not a new one. One of the
	// three (-003, the compound `cd /tmp && mkfs.ext4` payload) does not leak
	// under "exec", hence +2 rather than +3 there.
	//
	// 2026-08-14 (#3249), +2 for "/usr/bin/env" (+1 for "exec"):
	// TP-SSHKEY-SPLITCONCAT-001/002 — the regex-layer/policy-engine-fallback
	// half of split-concat assignment materialization
	// (shellparse.MaterializeAssignments). Same multi-statement residue as
	// TP-SSHKEY-SUBST-* above (which already leak here unchanged, via the
	// Layer 2.5 protected-path mechanism): the assignment statement(s) sit
	// before the read site, a wrapper prefix applies to the FIRST statement
	// only, and the bare read in a later statement is unaffected by it. -002
	// (`P1=/root/.ssh; P2=id_rsa; cat $P1/$P2`) does not leak under "exec",
	// hence +1 rather than +2 there — same shape as -003's exception above.
	const maxLeaks = 43

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// Two representatives, not the whole table. Each sweep is a full corpus
	// pass (~2.4k commands x ~1.1k rules) and this package already runs two
	// other corpus-wide parity sweeps, so enumerating all 20 wrappers would
	// cost minutes of CI for signal the per-wrapper unit TPs in
	// exec_wrapper_transparency_cases.go already carry. What only a corpus
	// sweep can catch is a CLASS-wide regression, and these two cover both
	// classes: a path-qualified spelling of a wrapper already in the table, and
	// one that had to be added to it. Both also exercise the regex layer's
	// 11.1% floor, since neither was transparent there before.
	wrappers := []string{
		"/usr/bin/env", // recognized wrapper, path-qualified — 20.2% before
		"exec",         // was absent from the table entirely — 19.9% before
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local. A prefix applies to the FIRST statement only, so a multi-line
	// command is not equivalent once prefixed.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\n") {
			baseline = append(baseline, tc)
		}
	}

	for _, w := range wrappers {
		t.Run(strings.ReplaceAll(w, " ", "_"), func(t *testing.T) {
			var leaks []string
			for _, tc := range baseline {
				got := string(engine.Evaluate(w+" "+tc.Command, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
				}
			}
			if len(leaks) > maxLeaks {
				t.Errorf("wrapper %q lowered the decision for %d/%d commands (budget %d).\n"+
					"An exec wrapper does not change which command runs — see #3057.\n%s",
					w, len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", w, len(leaks), len(baseline), maxLeaks)
		})
	}
}
