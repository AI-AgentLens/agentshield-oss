package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestCarrierBodyIndirectExecParity is the fitness function for issue #3238.
//
// Two features that each work correctly in isolation were never composed:
//   - InlineCodeFragments recovers the code a carrier runs (`eval '...'`,
//     `bash -c '...'`) — #3050/#3059.
//   - ResolveIndirectExecutable resolves an executable named through a
//     constant scalar, using a symbol table built from the whole command —
//     #3089.
//
// `addInlineCodeForms` called the first and never the second, so the moment
// the carrier's BODY is itself the indirection — `zc='rm -rf /'; eval "$zc"`
// — the fragment recovered is the literal text "$zc", and nothing resolves
// it back to "rm -rf /" before matching against the rule corpus.
//
// Measured (2026-08-12, full BLOCK-baseline corpus, single-quote-free subset,
// 1856 applicable cases) before the fix in this PR landed:
//   - eval form:    ~630/1856 leaked (~34%), matching the 34.1% reported in #3238
//   - bash -c form: same order of magnitude
//
// After wiring ResolveIndirectExecutable into addInlineCodeForms (closes the
// single-statement case) plus splitting a resolved COMPOUND payload the same
// way SplitTopLevelStatements splits the top-level command (#3045; closes the
// "the scalar's value is itself `if/for/while/{ }/&&`-joined" case):
//   - eval form:    197/1856 leaked (10.6%)
//   - bash -c form: 204/1856 leaked (11.0%)
//
// The residual is architectural, not a further regex-layer omission: of the
// 192 unique test-case IDs still leaking, 150 are Analyzer:"structural" (flag
// normalization — "rm --recursive --force" only matches after the STRUCTURAL
// analyzer expands it to "-rf", and that analyzer only ever parses
// ctx.RawCommand, never a carrier-resolved candidate string) and another 36
// are semantic/dataflow/stateful/substitution for the same reason. Only 3 of
// 192 are genuine regex-layer gaps (composition with command_intent_downgrade
// statement-scoping, and with the unset-parameter fold's need for whole-
// command assignment context) — see the follow-up issue linked in the PR.
// Extending structural/semantic/dataflow/stateful analysis to re-parse a
// resolved carrier body is a materially larger change (re-running the full
// per-analyzer AST walk on recovered text, not just adding regex candidates)
// and is intentionally out of scope here.
func TestCarrierBodyIndirectExecParity(t *testing.T) {
	t.Parallel()

	// Ratchet DOWN as fixed; never up without recording why here.
	//
	// 197/204 -> 199/206 (#3209): four new BLOCK-baseline commands
	// (TP-ESCSPLICE-PUNCT-001..004) joined the corpus this sweep draws from.
	// Wrapped in a carrier body, all four fall into the SAME already-tracked
	// residual this test's own doc comment describes (structural/regex
	// re-parsing a carrier-resolved candidate) — see #3321. Not a new gap
	// this fix introduced, just #3321's denominator growing by four.
	//
	// 199/206 -> 38/130 (#3321's own regex-layer follow-up): closes the 3
	// genuine regex-layer gaps #3321 scoped out of the structural/semantic/
	// dataflow/stateful residual, plus one more of the same shape it found
	// during verification (split-concat assignments, #3249, never folded for
	// a carrier-recovered fragment either):
	//   - IntentExcludedForStatements classified only ctx.RawCommand's own
	//     top-level statements, so a carrier's payload sitting inside a
	//     single-quoted assignment ("zc='cat ~/.ssh/id_rsa; git commit -m
	//     \"notes\"'") read as ONE opaque statement whose text served as both
	//     the match evidence and the doc-text exclusion evidence — the #2843
	//     bypass one layer up, behind the carrier's quote boundary instead of
	//     a `{ }` grouping. ctx.RawStatements now also carries carrier-
	//     resolved sub-statements (carrierResolvedStatements in intent.go), so
	//     a rule matching the carrier's resolved body classifies against that
	//     body's own statement, not the carrier invocation's.
	//   - MaterializeAssignments (split-concat: "p=id_rsa; cat ~/.ssh/$p")
	//     was folded only for ctx.RawCommand and its whole-command forms,
	//     never for a fragment recovered from inside a carrier — mirrors the
	//     NormalizeUnsetParamExp treatment retryCandidates() already gave
	//     every added candidate.
	// The residual is still the structural/semantic/dataflow/stateful
	// re-entrancy #3321 scoped out as a separate design question — not
	// closed by this fix, and not expected to be.
	const maxLeaksEval = 40
	const maxLeaksBashC = 132

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, allBlocking := blockingBaseline(t)

	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		// The wrapper below single-quotes the whole command as the scalar's
		// value — a command containing a single quote (or a newline, which
		// blockingBaseline itself does not filter) can't be represented that
		// way without its own escaping logic, so it's out of scope for this
		// sweep rather than a false leak.
		if strings.ContainsAny(tc.Command, "'\n") {
			continue
		}
		baseline = append(baseline, tc)
	}

	transforms := map[string]struct {
		render   func(cmd string) string
		maxLeaks int
	}{
		"eval": {
			render:   func(cmd string) string { return fmt.Sprintf(`zc='%s'; eval "$zc"`, cmd) },
			maxLeaks: maxLeaksEval,
		},
		"bash-c": {
			render:   func(cmd string) string { return fmt.Sprintf(`zc='%s'; bash -c "$zc"`, cmd) },
			maxLeaks: maxLeaksBashC,
		},
	}

	for name, tr := range transforms {
		t.Run(name, func(t *testing.T) {
			var leaks []string
			for _, tc := range baseline {
				wrapped := tr.render(tc.Command)
				got := string(engine.Evaluate(wrapped, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
				}
			}
			assertProbeNotVacuous(t, "carrier-body-indirect-exec/"+name, len(baseline), len(baseline)*3/4)
			if len(leaks) > tr.maxLeaks {
				t.Errorf("delivering a carrier's body via a constant scalar (%s) lowered the decision for %d/%d commands (budget %d).\n"+
					"A carrier body named through indirection runs the same command as writing it directly — see #3238.\n%s",
					name, len(leaks), len(baseline), tr.maxLeaks, joinLines(leaks))
			}
			t.Logf("carrier-body-indirect-exec/%s: %d/%d leaked (budget %d)", name, len(leaks), len(baseline), tr.maxLeaks)
		})
	}
}
