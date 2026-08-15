package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestLineContinuationParity is the fitness function for issue #3055, and a
// sibling of TestCompoundWrappingParity (#3045).
//
// The invariant: a backslash-newline is whitespace the shell removes before the
// command is tokenized, so continuing a line must never LOWER a decision.
// `rm \<NL>-rf /` is exactly as destructive as `rm -rf /`.
//
// Like #3045 this had to be measured corpus-wide to be seen at all. Nothing
// failed, nothing was logged, and every AST-based layer behaved correctly —
// mvdan.cc/sh yields an identical tree either way. Only the regex layer, which
// matches raw text, was blind, and it carries most of the pack corpus. When
// this shipped, 1,252 of 2,385 BLOCKing commands (52.5%) degraded to AUDIT.
//
// Two continuation positions are swept because they fail through different
// code paths: after the first word (defeats "^"-anchored rules) and at a
// later gap (defeats unanchored rules mid-pattern, which the positionSensitive
// retry gate deliberately does not cover).
func TestLineContinuationParity(t *testing.T) {
	t.Parallel()
	// Known residue at the time of writing: 17 at gap 1, 10 at gap 2. Not all of
	// it degrades to AUDIT — some reaches ALLOW, because losing the BLOCK
	// uncovers a standing ALLOW rule underneath it. Three groups:
	//   - Rules keyed on raw redirect / here-string / heredoc-delimiter text
	//     ("bash <<< ...", "echo > '--checkpoint-action=...'", "cat > Jenkinsfile
	//     << 'EOF'"). The printer re-spaces the operator the rule matches on
	//     (`> x` prints as `>x`), so the joined form misses too. The real fix is
	//     in those rules' patterns, not here.
	//   - Prose-shaped jailbreak-prefix cases ("Sure, here's how to do it: ...")
	//     that are not valid shell, so there is nothing for the parser to join.
	//   - A handful of AST-layer cases (pip config set, cat >> train.jsonl) that
	//     are worth a separate look.
	// Ratchet DOWN as these are fixed; never up without recording why here.
	const maxLeaks = 20

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name string
		n    int // continue at the nth space (1-based)
	}{
		{"after-first-word", 1},
		{"at-second-gap", 2},
	}

	// Engine and BLOCK baseline are shared across every parity sweep in this
	// package (see parity_baseline_test.go); only the per-transform filter is
	// local. A command that already contains a continuation has nothing to add.
	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\\\n") {
			baseline = append(baseline, tc)
		}
	}

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			tried := 0
			for _, tc := range baseline {
				continued, ok := continueAtSpace(tc.Command, p.n)
				if !ok {
					continue
				}
				tried++
				got := string(engine.Evaluate(continued, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
				}
			}

			if len(leaks) > maxLeaks {
				t.Errorf("continuing the line at gap %d lowered the decision for %d/%d commands (budget %d).\n"+
					"A backslash-newline is whitespace the shell deletes — it must never weaken enforcement (see #3055).\n%s",
					p.n, len(leaks), tried, maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), tried, maxLeaks)
		})
	}
}

// continueAtSpace replaces the nth UNQUOTED space on the first line of cmd with
// " \<NL>", the way a shell author (or a formatter) wraps a long line. Reports
// false when there is no such space.
//
// The quote and first-line restrictions are what make the sweep honest. A
// backslash-newline is only whitespace where the shell treats it as whitespace:
// inside quotes it is literal data, and inside a heredoc body it belongs to the
// document. Splitting there produces a DIFFERENT command, so a lower decision
// would be correct behaviour, not a leak — counting it would force the budget
// up and hide real regressions behind noise.
func continueAtSpace(cmd string, n int) (string, bool) {
	var inSingle, inDouble bool
	seen := 0
	for i := 0; i < len(cmd); i++ {
		switch c := cmd[i]; {
		case c == '\n':
			return "", false // heredoc bodies and later lines are out of scope
		case c == '\\' && !inSingle:
			i++ // escaped character, never a separator
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == ' ' && !inSingle && !inDouble:
			if seen++; seen == n {
				return cmd[:i] + " \\\n" + cmd[i+1:], true
			}
		}
	}
	return "", false
}
