package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestSetPositionalParity is the fitness function for issue #3237, the
// positional-parameter sibling of TestIndirectExecNameParity (#3089/#3090)
// and TestArrayIndirectExecNameParity (#3091).
//
// The invariant: an executable name (or the whole command) delivered through
// bash's positional parameters ($1, $@, ...) via `set --` runs EXACTLY the
// same command as writing it directly, so binding it this way must never
// LOWER the decision:
//
//	set -- rm; $1 -rf /            == rm -rf /
//	set -- rm -rf /; "$@"          == rm -rf /
//
// Before the fix, shellparse.buildExecSymbols had no notion of positional
// parameters at all — `set` is a plain CallExpr with no syntax.Assign, so it
// was invisible to the Assigns-based scalar/array collection #3089/#3091
// already do. resolveExecParamExp bailed on any bare digit or "@"/"*"
// parameter name, so $1/"$@" stayed unresolved: no structural/semantic/
// dataflow/stateful rule keyed on the real executable matched, and the regex
// layer missed it too since the raw text never has the executable name
// adjacent to its flags/args. Measured at 61.4% (positional-index) and 34.4%
// (positional-splat) of the BLOCKing corpus before the fix — the fourth and,
// per the issue, final binding mechanism in this family (scalar #3089/#3090,
// array literal #3091, read -a #3193, set -- #3237).
//
// Resolution is deliberately conservative to hold precision at 100%: only a
// `set --` whose every word is a fully-literal, positionally-defined operand
// is registered (setPositionalElems is all-or-nothing, mirroring
// literalArrayElems); any `shift` anywhere in the command disables positional
// resolution entirely (positions can be removed/renumbered, which this
// whole-file table cannot model); and a $1 reference inside a function body
// never resolves through an outer `set --` (functions rebind their own
// positionals) — see withoutPositionals and containsFuncDecl in
// internal/shellparse/parse.go.
func TestSetPositionalParity(t *testing.T) {
	t.Parallel()
	// Residual leaks (9/2295 measured on positional-index, 0/837 on
	// positional-splat) decompose into recognized, pre-existing classes, none
	// of them a new bypass:
	//   - Synthetic-transform artifacts: wrapping prose-shaped guardian/
	//     jailbreak test text ("set -- Sure,; $1 here's how...") produces
	//     nonsense shell the guardian flags as PROSE, not as a runnable
	//     command — same class the array-splat sweep documents.
	//   - Heredoc/redirect composition gaps ("set -- tee; $1 file <<EOF"):
	//     the executable resolves fine, but detection hangs off heredoc-body
	//     analysis — the same narrow residual #3081/#3089/#3091 already left.
	//   - A handful of semantic.go's built-in rules match via
	//     strings.Contains(ctx.RawCommand, ...) rather than through
	//     ctx.Parsed (see semantic.go's own comment on ifsNormalizedRaw/
	//     unsetFoldedRaw/braceFoldedRaw). None of those literal-substring
	//     rules incorporate ANY indirect-executable resolution — scalar
	//     (#3089), array (#3091), or positional (#3237) — as a candidate
	//     form, so a rule like sem-block-pip-config-index misses "set --
	//     pip; $1 config set ... extra-index-url" exactly as it already
	//     misses "x=pip; $x config set ..." today. Pre-existing gap, not a
	//     regression introduced here.
	//   - Composition with a DIFFERENT indirection mechanism one level down:
	//     "set -- read; $1 -ra c <<< '...'" resolves $1 to "read" correctly,
	//     but readArrayHereStringElems (the read -a NAME <<< detector inside
	//     buildExecSymbols) only recognizes a LITERAL "read" token at
	//     call.Args[0] — it's a single-pass, non-recursive check, so it never
	//     sees an executable that itself required resolution to read "read".
	// Ratchet DOWN as fixed; never up without recording why.
	//
	// 2026-08-11 (#3203), +4: analyzer.buildSymbolTable (Layer 2.5 path
	// materialization) now also resolves DeclClause bindings. The 5 new
	// TP-SSHKEY-SUBST-DECLBIND-* cases compose with positional-index
	// indirection the same way the pre-existing TP-DECLBIND-001/002 already
	// did — `set -- declare; $1 P1=~/.ssh; ...` resolves $1 to the literal
	// "declare", but that resolution happens on a plain CallExpr, which never
	// carries the DeclClause node the literal spelling would have.
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of #3193
	// (TP-READ-SCALAR-EXEC-*/TP-READ-MAPFILE-EXEC-*/TP-READ-READARRAY-EXEC-*)
	// compose with positional-index indirection via the SAME "composition with
	// a different indirection mechanism one level down" class already
	// documented above for read -a: `set -- read; $1 zc <<< "rm -rf /"; $zc`
	// resolves $1 to "read" correctly, but readScalarHereStringElem/
	// mapfileHereStringElems (like readArrayHereStringElems before them) only
	// recognize a LITERAL "read"/"mapfile"/"readarray" token at call.Args[0].
	const maxLeaksIndex = 20
	const maxLeaksSplat = 3

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, allBlocking := blockingBaseline(t)

	// Reserved words/keywords can't be delivered as a positional parameter
	// and invoked the way a real executable can — wrapping them produces
	// invalid shell, not a genuine indirection, so they're excluded rather
	// than counted as leaks (identical list to the scalar/array parity
	// sweeps).
	notIndirectable := map[string]bool{
		"for": true, "while": true, "until": true, "if": true, "case": true,
		"select": true, "coproc": true, "time": true, "function": true,
		"do": true, "done": true, "then": true, "else": true, "fi": true, "esac": true,
	}
	// A word is safe as a `set --` operand when it survives verbatim as a
	// bare word — no quoting, expansion, or control character that would
	// re-tokenize the set invocation or the surrounding command.
	setArgSafeWord := func(w string) bool {
		return w != "" && !strings.ContainsAny(w, "'\"$`;|&<>(){}=*?[]~#!\\")
	}

	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\n") {
			baseline = append(baseline, tc)
		}
	}

	// positional-index: deliver only the executable name via $1 (mirrors the
	// scalar/array transforms' exec-only scope). "$1" replaces the first
	// word; the rest of the command stays literal text.
	t.Run("positional-index", func(t *testing.T) {
		var leaks []string
		var applicable int
		for _, tc := range baseline {
			idx := strings.IndexByte(tc.Command, ' ')
			if idx < 0 {
				continue
			}
			first, rest := tc.Command[:idx], tc.Command[idx:]
			if !setArgSafeWord(first) || notIndirectable[first] {
				continue
			}
			applicable++
			wrapped := fmt.Sprintf(`set -- %s; $1%s`, first, rest)
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
			}
		}
		assertProbeNotVacuous(t, "set-positional/positional-index", applicable, 200)
		if len(leaks) > maxLeaksIndex {
			t.Errorf("delivering the executable name via positional-index lowered the decision for %d/%d commands (budget %d).\n"+
				`A positional parameter bound by "set --" runs the same command as writing it directly — see #3237.`+"\n%s",
				len(leaks), applicable, maxLeaksIndex, joinLines(leaks))
		}
		t.Logf("set-positional/positional-index: %d/%d leaked (budget %d)", len(leaks), applicable, maxLeaksIndex)
	})

	// positional-splat: wrap the WHOLE command's words as `set --` operands
	// and re-expand them with "$@". Applicable only when every word is
	// set-arg-safe.
	t.Run("positional-splat", func(t *testing.T) {
		var leaks []string
		var applicable int
		for _, tc := range baseline {
			fields := strings.Fields(tc.Command)
			if len(fields) == 0 {
				continue
			}
			safe := true
			for _, f := range fields {
				if !setArgSafeWord(f) {
					safe = false
					break
				}
			}
			if !safe || notIndirectable[fields[0]] {
				continue
			}
			applicable++
			wrapped := fmt.Sprintf(`set -- %s; "$@"`, strings.Join(fields, " "))
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
			}
		}
		assertProbeNotVacuous(t, "set-positional/positional-splat", applicable, 200)
		if len(leaks) > maxLeaksSplat {
			t.Errorf("delivering the command via positional-splat lowered the decision for %d/%d commands (budget %d).\n"+
				`A "$@" expansion of a "set --" binding runs the same command as writing it directly — see #3237.`+"\n%s",
				len(leaks), applicable, maxLeaksSplat, joinLines(leaks))
		}
		t.Logf("set-positional/positional-splat: %d/%d leaked (budget %d)", len(leaks), applicable, maxLeaksSplat)
	})
}
