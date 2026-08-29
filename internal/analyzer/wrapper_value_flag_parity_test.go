package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestWrapperValueFlagParity is the fitness function for issue #3221, the
// sequel to TestExecWrapperParity (#3057).
//
// The invariant is the same one #3057 established — an execution wrapper does
// not change WHICH command runs, so prefixing one must never lower a decision —
// but applied to the wrapper shape #3057 could not express: an option that
// takes its value as a SEPARATE token.
//
// The control positions are the load-bearing part of this test and must not be
// dropped. `sudo` alone and `sudo -u root` differ by exactly one value-taking
// flag, so running both turns a bare number into a diagnosis: at the time of
// the fix the control measured 1.1% and the value-flag form 21.3%, which is
// what proved the defect was the operand model rather than wrapper
// transparency itself. If this test ever fails, compare the two columns before
// touching anything — a rise in BOTH is a wrapper-transparency regression
// (#3057's problem), a rise in only the value-flag column is this one.
func TestWrapperValueFlagParity(t *testing.T) {
	t.Parallel()
	// The residue is the same multi-statement residue TestExecWrapperParity
	// documents: a prefix wraps only the FIRST statement, so for
	// "P1=~/.ssh; cat $P1/id_rsa" or "PATH=/tmp:$PATH git push" the prefixed
	// form genuinely is not equivalent and a lower decision is correct.
	// Measured identical (27) for the control and every value-flag position
	// after the fix — that equality is the real assertion here.
	// Ratchet DOWN as those are fixed; never up without recording why.
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
	// declare/export/typeset/readonly/local bindings. The 5 new
	// TP-SSHKEY-SUBST-DECLBIND-* cases are multi-statement
	// (`declare P1=...; declare P2=...; cat $P1/$P2`) and fall into the same
	// residue class documented above — confirmed identical to
	// TP-SSHKEY-SUBST-001..005 (plain-assignment form), which already leak
	// here unchanged.
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of the #3193
	// read-array here-string binding (TP-READ-SCALAR-EXEC-001/002,
	// TP-READ-MAPFILE-EXEC-001, TP-READ-READARRAY-EXEC-001) — same
	// multi-statement residue as TP-READ-ARRAY-EXEC-* already measured here:
	// "sudo read zc <<< \"rm -rf /\"; $zc" only wraps the first (`read`)
	// statement, so the bare $zc exec in the second statement is unaffected
	// and a lower decision there is correct, not a regression. Measured +4 for
	// control-sudo/sudo-u/strace-o/timeout-s/taskset-c (38 each) and +3 for
	// sudo-endopts (37).
	//
	// 2026-08-12 (#3238), +3 (+2 for sudo-endopts): TP-CARRIER-INDIRECT-EXEC-001/
	// 002/003 (carrier-body indirect-exec resolution — `zc='rm -rf /'; eval
	// "$zc"`) are multi-statement for the same reason the DECLBIND/SSHKEY-SUBST/
	// READ-SCALAR-EXEC cases above are: a wrapper prefix applies to the FIRST
	// statement (`zc='rm -rf /'`) only, leaving the second (`eval "$zc"`)
	// unprefixed — same documented residue class, not a new one. One of the
	// three (-003, the compound `cd /tmp && mkfs.ext4` payload) does not leak
	// under "sudo -u root --", hence +2 rather than +3 there.
	//
	// 2026-08-14 (#3249), +2 (+1 for sudo-endopts): TP-SSHKEY-SPLITCONCAT-001/
	// 002 — the regex-layer/policy-engine-fallback half of split-concat
	// assignment materialization (shellparse.MaterializeAssignments). Same
	// multi-statement residue as TP-SSHKEY-SUBST-* just above (which already
	// leak here unchanged, via the Layer 2.5 protected-path mechanism): the
	// assignment statement(s) sit before the read site, a wrapper prefix
	// applies to the FIRST statement only, and the bare read in a later
	// statement is unaffected by it. -002 (`P1=/root/.ssh; P2=id_rsa; cat
	// $P1/$P2`) does not leak under "sudo -u root --", hence +1 rather than
	// +2 there — same shape as -003's exception in the #3238 entry above.
	//
	// 2026-08-16 (#3378), +1 (+0 for sudo-endopts): TP-SHADOW-SUBSTR-ASSEMBLY-001
	// (`P=/x; cat ${P:0:1}etc${P:0:1}shadow`) — a regression lock for the
	// already-working half of #3378 (FoldConstantParamOp's constant-substring
	// fold, #3220), added alongside the two NEW single-statement cases #3378
	// closes (TP-SHADOW-SUBSTR-ASSEMBLY-002/003, `cat ${PATH:0:1}etc...` /
	// `${HOME:0:1}`, which do NOT leak here — no assignment statement to strand
	// a prefix on). Same multi-statement residue as every entry above: the
	// assignment sits before the read, so a wrapper prefix only reaches the
	// first statement. Does not leak under "sudo -u root --", hence +0 there —
	// same shape as -002's exception in the #3249 entry above.
	const maxLeaks = 44

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name   string
		prefix string
	}{
		// Control: the same wrapper with no value-taking flag. Establishes the
		// floor every position below is compared against.
		{"control-sudo", "sudo"},

		// One per distinct reason the shape model failed, not one per wrapper —
		// each sweep is a full corpus pass and the per-wrapper unit coverage
		// lives in WrapperValueFlagCases.
		{"sudo-u", "sudo -u root"},               // value is a bare word
		{"strace-o", "strace -o /tmp/trace.log"}, // value is a path
		{"timeout-s", "timeout -s KILL 5"},       // value is a name where a number was expected
		{"taskset-c", "taskset -c 0-3"},          // value is number-ish but not numeric
		{"sudo-endopts", "sudo -u root --"},      // end-of-options marker after a value flag
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
			if len(leaks) > maxLeaks {
				t.Errorf("prefix %q lowered the decision for %d/%d commands (budget %d).\n"+
					"A wrapper's value-taking option must not hand its VALUE to the analyzer "+
					"as the executable — see #3221.\n%s",
					p.prefix, len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", p.prefix, len(leaks), len(baseline), maxLeaks)
		})
	}
}
