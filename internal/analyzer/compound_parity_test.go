package analyzer_test

import (
	"fmt"
	"testing"

)

// TestCompoundWrappingParity is a fitness function for issue #3045.
//
// The invariant: wrapping a command in a bash compound construct must never
// LOWER its decision. `{ rm -rf /; }` is exactly as destructive as `rm -rf /`,
// so if one BLOCKs the other must too.
//
// This is deliberately a corpus-wide sweep rather than a handful of examples,
// because the original bug was invisible per-rule: nothing failed, no error was
// logged, and ctx.Parsed stayed non-nil — the structural/semantic/dataflow/
// stateful analyzers just silently iterated an empty segment list. The only way
// to see it was to measure the whole corpus both ways. When this bug shipped,
// 492 of 2,370 BLOCKing commands (20.8%) degraded under a brace wrapper.
//
// A tiny residue is tolerated (see maxLeaks) rather than asserting zero, so the
// test stays honest about known-imperfect coverage instead of being weakened to
// whatever passes today. Ratchet it DOWN as the remaining cases are fixed;
// never up without recording why here.
func TestCompoundWrappingParity(t *testing.T) {
	t.Parallel()
	// Both items of prior known residue are now resolved (#3047):
	//   - "cat /dev/zero > /dev/sda" under `if` was fixed at the root: the
	//     parser bubbled every statement's redirects into a single top-level
	//     list and dataflow.checkRedirectFlows paired ALL of them with
	//     Segments[0] unconditionally — correct only when the redirect-bearing
	//     statement happens to be first. `if`'s own condition ("true") occupies
	//     Segments[0], so the redirect got attributed to the wrong statement.
	//     Fixed by attaching each statement's redirects to the CommandSegment
	//     that actually owns them (internal/shellparse/parse.go).
	//   - "nohup/setsid claude --skill ... &" was never actually broken in the
	//     product — it was a bug in THIS harness. The generic "%s; <keyword>"
	//     wrapper formats produce syntactically INVALID bash whenever the
	//     substituted command ends in "&" ("cmd &; fi" — verified with
	//     `bash -n`: "syntax error near unexpected token ';'"), which makes
	//     mvdan.cc/sh fail to parse and fall back to treating the whole
	//     wrapped string as one opaque, unsplittable statement. No real shell
	//     would ever run such a command, so it was never an exploitable leak —
	//     just a false reading from an invalid probe. Fixed by joining with a
	//     newline instead of "; ", which terminates a statement (background or
	//     not) the same way regardless of how it ends.
	const maxLeaks = 0

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}

	wrappers := []struct{ name, format string }{
		{"brace", "{ %s\n}"},
		{"if", "if true; then %s\nfi"},
		{"for", "for i in 1; do %s\ndone"},
	}

	// Baseline and engine are shared across every parity sweep in this package
	// (see parity_baseline_test.go) — re-deriving them per test was what pushed
	// the package past the CI go-test timeout.
	engine, baseline := blockingBaseline(t)

	for _, w := range wrappers {
		t.Run(w.name, func(t *testing.T) {
			var leaks []string
			for _, tc := range baseline {
				wrapped := string(engine.Evaluate(fmt.Sprintf(w.format, tc.Command), nil).Decision)
				if rank[wrapped] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, wrapped, tc.Command))
				}
			}

			if len(leaks) > maxLeaks {
				t.Errorf("compound wrapping %q lowered the decision for %d/%d commands (budget %d).\n"+
					"Wrapping a command in a bash compound must never weaken enforcement — see #3045.\n%s",
					w.format, len(leaks), len(baseline), maxLeaks, joinLines(leaks))
			}
			t.Logf("%s: %d/%d leaked (budget %d)", w.name, len(leaks), len(baseline), maxLeaks)
		})
	}
}

func joinLines(in []string) string {
	out := ""
	for _, s := range in {
		out += "  " + s + "\n"
	}
	return out
}
