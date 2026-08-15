package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestProcSubstEchoParity is the fitness function for issue #3190, sibling to
// TestTrapParity (#3084), TestHeredocShellExecParity (#3081), and
// TestExecWrapperParity (#3057).
//
// The invariant: `source <(echo '<cmd>')` and `bash <(echo '<cmd>')` must
// never BLOCK less than the bare command — source/./a shell interpreter reads
// an input process substitution's fifo content and executes it as shell
// script exactly like `<cmd>` run directly, just carried through a
// process-substitution fifo instead of argv or stdin.
//
// Before the fix, ts-block-source-process-sub-rce / ts-block-procsub-input-exec
// only matched "<(curl|wget|fetch|aria2c ...)" — a hand-picked
// remote-downloader-keyword list, the same gap shape closed for `trap` by
// #3084: anything outside that keyword list (most simply, a literal
// echo/printf payload with no remote fetch at all) slipped to AUDIT.
// shellparse now extracts a literal-only echo/printf process-substitution
// payload as inline shell source and re-runs the FULL rule corpus against it
// instead of relying on the keyword list alone.
func TestProcSubstEchoParity(t *testing.T) {
	t.Parallel()
	// Residual leaks (measured 80/3594 at introduction) are the SAME
	// pre-existing nesting/parity gap already tracked for trap/-c/heredoc, not
	// something this fix introduced — verified case-by-case: every leak in
	// this bucket is a compound command (&&/;/| inside the echoed payload, or
	// a further eval/-c/wrapper needing one more recursion level than
	// shellparse's maxParseDepth=2 allows) that ALSO leaks identically under
	// the already-shipped `bash -c "<cmd>"` extraction path — e.g.
	// `bash -c "cd /tmp && mkfs.ext4 /dev/sda1"` degrades to AUDIT exactly
	// like `source <(echo 'cd /tmp && mkfs.ext4 /dev/sda1')` does. The count
	// is roughly double TestTrapParity's 18/1789 (~1%) because this test
	// sweeps two wrappers (source, bash) over the same baseline, each hitting
	// the identical depth-cap limitation. Ratchet DOWN as they are fixed;
	// never up without recording why.
	//
	// 2026-08-14 (#3249), +1: TP-SSHKEY-SPLITCONCAT-001 (split-concat
	// assignment materialization) joins the corpus and leaks under one of the
	// two wrappers — same pre-existing depth-cap bucket documented above.
	const maxLeaks = 86

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local. Commands containing a single quote or a newline are excluded: a
	// naive `<(echo '%s')` substitution would either break out of the quoting
	// (producing an invalid probe, not a valid semantics-preserving transform)
	// or span multiple echo arguments — filtered out rather than inflating the
	// leak budget to absorb invalid probes.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.ContainsAny(tc.Command, "'\n") {
			baseline = append(baseline, tc)
		}
	}

	wrappers := []string{
		`source <(echo '%s')`,
		`bash <(echo '%s')`,
	}

	var leaks []string
	tried := 0
	for _, tc := range baseline {
		for _, w := range wrappers {
			wrapped := fmt.Sprintf(w, tc.Command)
			tried++
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
			}
		}
	}

	if len(leaks) > maxLeaks {
		t.Errorf("feeding the command through a literal-echo process substitution into source/bash lowered the decision for %d/%d probes (budget %d).\n"+
			"source/./a shell interpreter reads process-substitution content and executes it exactly like the bare command — see #3190.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("procsubst-echo: %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}
