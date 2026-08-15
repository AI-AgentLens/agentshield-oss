package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestStdinSourceParity is the fitness function for issue #3242, sibling to
// TestHeredocShellExecParity (#3081) and TestProcSubstEchoParity (#3190).
//
// The invariant: a shell interpreter reads its source from stdin as readily
// as from `-c` or a heredoc. Two more spellings of that — a here-string
// (`<<<`, with ANY interpreter flag, not just the bare form) and a stdin
// redirect from a literal-only process substitution (`< <(...)`, `0< <(...)`)
// — must never BLOCK less than the bare command. Before the fix, neither
// produced a segment: the only thing standing in for the here-string form was
// ts-block-herestring-shell-exec's single hardcoded invocation shape
// (interpreter immediately followed by `<<<`), defeated by any flag
// (including `-s`, whose documented purpose IS reading from stdin); the
// stdin-redirect form had no defence at all.
//
// One probe position per MECHANISM, not one per flag — `-s` is representative
// of "any flag defeats the old regex", not a special case in its own right.
func TestStdinSourceParity(t *testing.T) {
	t.Parallel()

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local. Commands containing a single quote or a newline are excluded:
	// a naive `<<< '%s'` / `<(echo '%s')` substitution would either break out
	// of the quoting (an invalid probe, not a valid semantics-preserving
	// transform) or span multiple echo arguments.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.ContainsAny(tc.Command, "'\n") {
			baseline = append(baseline, tc)
		}
	}

	type mechanism struct {
		name    string
		wrapper string
	}
	mechanisms := []mechanism{
		{"here-string-with-flag", "bash -s <<< '%s'"},
		{"stdin-procsub", "bash < <(echo '%s')"},
	}

	// Residual leaks (measured 82/3724 at introduction) are the SAME
	// pre-existing nesting/depth-cap gap already tracked for
	// heredoc/-c/trap/procsub-echo (an already-wrapped corpus command needs
	// recursion depth 3, one past shellparse's maxParseDepth=2), not
	// something this fix introduces. Ratchet DOWN as fixed; never up without
	// recording why.
	//
	// 2026-08-14 (#3249), +4: TP-SSHKEY-SPLITCONCAT-001/002 (split-concat
	// assignment materialization) both leak under both mechanisms — wrapping
	// either command in `bash -s <<< '...'`/`bash < <(echo '...')` hits the
	// same pre-existing depth-cap gap documented above: the wrapped command
	// needs one more level of recursion than shellparse's maxParseDepth=2
	// provides for a command that ALSO carries an assignment+read pair to
	// materialize. Not a new gap; the same one, newly measured by cases that
	// didn't exist when the ceiling was last set.
	const maxLeaks = 86

	var leaks []string
	tried := 0
	for _, tc := range baseline {
		for _, m := range mechanisms {
			wrapped := fmt.Sprintf(m.wrapper, tc.Command)
			tried++
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s [%s]: BLOCK -> %s : %s", tc.ID, m.name, got, wrapped))
			}
		}
	}

	if len(leaks) > maxLeaks {
		t.Errorf("feeding the command to bash via stdin (here-string-with-flag or stdin-procsub) lowered the decision for %d/%d probes (budget %d).\n"+
			"A shell interpreter reads its source from stdin exactly like a heredoc or -c — see #3242.\n%s",
			len(leaks), tried, maxLeaks, joinLines(leaks))
	}
	t.Logf("stdin-source: %d/%d leaked (budget %d)", len(leaks), tried, maxLeaks)
}
