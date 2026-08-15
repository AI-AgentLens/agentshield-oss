package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestSuInlineCodeParity is the fitness function for issue #3223 — `su -c
// 'CMD'` and `runuser -u USER -c 'CMD'` as inline-code carriers.
//
// This is the test whose absence let the gap live for four months. The
// ExecWrappers table excluded `su` with a comment saying `su -c 'CMD'` "carries
// inline code, a different shape (see ExtractInlineCode / InlineCodeFragments)"
// — and ExtractInlineCode did not handle `su` either. The comment described a
// division of labour that neither side implemented. A comment delegating to
// another component is a claim, and an unverified claim reads exactly like
// coverage.
//
// `bash -c` is the control, and it is the right one: `su -c` is the same
// delivery mechanism with a privilege switch bolted on, so the two must leak
// identically. A gap between the columns is the defect; a rise in both is a
// regression in the shared inline-code machinery (#3050/#3059) rather than in
// this class.
func TestSuInlineCodeParity(t *testing.T) {
	t.Parallel()
	// Residual measured identical (44) for the control and every su/runuser
	// position after the fix, and it decomposes into the pre-existing
	// nested-Subcommand classes `bash -c` already carries: substitution and
	// dataflow do not recurse into nested Subcommands, so multi-statement
	// symbol-table cases ("P1=~/.ssh; P2=id_rsa; cat $P1/$P2") stay lower.
	// That equality with the control is the real assertion.
	// Ratchet DOWN as those are fixed; never up without recording why here.
	const maxLeaks = 44

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	positions := []struct {
		name, pre, post string
	}{
		{"control-bash-c", "bash -c '", "'"},         // the shape su -c must match
		{"su-c", "su -c '", "'"},                     // no user: switch to root
		{"su-user-c", "su root -c '", "'"},           // user as a positional
		{"su-login-c", "su - root -c '", "'"},        // login shell, bare "-" operand
		{"runuser-u-c", "runuser -u root -c '", "'"}, // value-taking flag before -c
	}

	engine, allBlocking := blockingBaseline(t)
	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		// A single-quoted payload cannot carry a command that itself contains a
		// single quote, and a carrier wraps only the first statement of a
		// multi-line command. Both make the mutation a DIFFERENT command, so
		// they are filtered out rather than absorbed into the leak budget —
		// raising the budget to swallow invalid probes is how a sweep stops
		// measuring anything.
		if strings.Contains(tc.Command, "'") || strings.Contains(tc.Command, "\n") {
			continue
		}
		baseline = append(baseline, tc)
	}
	if len(baseline) < 800 {
		t.Fatalf("baseline collapsed to %d commands — the sweep would be vacuous", len(baseline))
	}

	for _, p := range positions {
		t.Run(p.name, func(t *testing.T) {
			var leaks []string
			for _, tc := range baseline {
				got := string(engine.Evaluate(p.pre+tc.Command+p.post, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, tc.Command))
				}
			}
			if len(leaks) > maxLeaks {
				t.Errorf("carrier %q lowered the decision for %d/%d commands (budget %d).\n"+
					"A privilege carrier's -c argument is shell source and must be "+
					"decomposed like bash -c — see #3223.\n%s",
					strings.TrimSuffix(p.pre, " '"), len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", p.name, len(leaks), len(baseline), maxLeaks)
		})
	}
}
