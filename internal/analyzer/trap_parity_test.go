package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestTrapParity is the fitness function for issue #3084, sibling to
// TestHeredocShellExecParity (#3081), TestExecWrapperParity (#3057), and
// TestCompoundWrappingParity (#3045).
//
// The invariant: a command registered as a `trap` action runs exactly like the
// bare command — "trap 'rm -rf /' EXIT" is exactly as destructive as
// "rm -rf /", just deferred until the shell exits (or errs, or is signaled)
// instead of running immediately. Wrapping a command in `trap ... EXIT|ERR|
// DEBUG|RETURN` must never LOWER its decision.
//
// Before the fix, the only trap coverage was five keyword-listed regex rules
// in terminal-safety.yaml (curl/wget/nc/bash/sh/python/eval/exec/base64/xxd/
// sudo) — anything outside that keyword list slipped to AUDIT via the generic
// pseudo-signal AUDIT rule. 495/1789 BLOCKing commands (27.7%) degraded,
// including rm -rf, dd, mkfs, and find -delete — none of which mention any of
// the listed keywords. ExtractInlineCode now treats trap's action argument as
// inline shell source (the same deferred-execution shape as eval/-c/heredoc),
// so the FULL rule corpus re-evaluates it instead of a hand-picked keyword
// list.
func TestTrapParity(t *testing.T) {
	t.Parallel()
	// Residual leaks (measured 18/1789 at introduction) are the SAME
	// pre-existing nesting/parity gap already tracked for -c and heredoc, not
	// something this fix introduced — verified case-by-case: every leak in
	// this bucket (redirect-under-if, variable-substitution paths not
	// recursed into by substitution/dataflow, stateful chains split across
	// `&&`/`||`/`;`, and double-wrapped exec-wrapper commands needing
	// recursion depth 3, one past shellparse's maxParseDepth=2 cap) also
	// leaks identically under `bash -c`. Ratchet DOWN as they are fixed;
	// never up without recording why.
	//
	// Bumped 20->21 (#3208): TP-ESCSPLICE-BACKSLASH-SECONDWORD-001 (`sudo
	// d\d if=/dev/zero of=/dev/sda`) is new baseline — #3208 fixed the bare
	// form to BLOCK, but the trap-body re-parse lands in the same bucket
	// documented above. Verified: `bash -c 'sudo d\d if=/dev/zero of=/dev/sda'`
	// leaks identically — same class, not a new one. See the matching bump in
	// heredoc_shell_exec_parity_test.go for the fuller writeup.
	//
	// Bumped 21->24 (#3209): three new BLOCK-baseline commands
	// (TP-ESCSPLICE-PUNCT-001/003/004) joined the corpus, same #3321 bucket —
	// verified each leaks identically under bare `bash -c`.
	//
	// Bumped 24->26 (#3249): TP-SSHKEY-SPLITCONCAT-001/002 (split-concat
	// assignment materialization) joined the corpus and both leak as a trap
	// action — same pre-existing depth-cap bucket documented above (verified:
	// `bash -c 'p=id_rsa; cat ~/.ssh/$p'` and `bash -c 'P1=/root/.ssh;
	// P2=id_rsa; cat $P1/$P2'` leak identically).
	const maxLeaks = 26

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local. Commands containing a single quote or a newline are excluded: a
	// naive `trap '%s' EXIT` substitution would either break out of the
	// quoting (producing an invalid probe, not a valid semantics-preserving
	// transform) or span multiple trap actions — filtered out rather than
	// inflating the leak budget to absorb invalid probes.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.ContainsAny(tc.Command, "'\n") {
			baseline = append(baseline, tc)
		}
	}

	var leaks []string
	for _, tc := range baseline {
		wrapped := fmt.Sprintf("trap '%s' EXIT", tc.Command)
		got := string(engine.Evaluate(wrapped, nil).Decision)
		if rank[got] < rank["BLOCK"] {
			leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
		}
	}

	if len(leaks) > maxLeaks {
		t.Errorf("registering the command as a trap action lowered the decision for %d/%d commands (budget %d).\n"+
			"A trap action is shell source the interpreter executes on EXIT/ERR/DEBUG/RETURN/signal — see #3084.\n%s",
			len(leaks), len(baseline), maxLeaks, joinLines(leaks))
	}
	t.Logf("trap-exit: %d/%d leaked (budget %d)", len(leaks), len(baseline), maxLeaks)
}
