package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestIndirectExecNameParity is the fitness function for issue #3089, sibling
// to TestExecWrapperParity (#3057) and TestHeredocShellExecParity (#3081).
//
// The invariant: an executable name delivered through one level of
// indirection — a scalar variable ("x=rm; $x -rf /") or a trivial command
// substitution ("$(echo rm) -rf /" / "`echo rm` -rf /") — runs EXACTLY the
// same command as writing the executable directly. Wrapping a command this
// way must never LOWER its decision.
//
// Before the fix, shellparse.callExprToSegment took the executable word
// verbatim ("$x", "$(echo rm)"), so no structural/semantic/dataflow/stateful
// rule keyed on the real executable ever matched — and the regex layer
// missed it too, since the raw text no longer has the executable name
// adjacent to its flags/args. Measured against the full BLOCK-baseline
// corpus (2416 cases) before the fix:
//   - scalar-var form:  1413/2329 leaked (60.7%)
//   - cmdsubst form:    1284/2329 leaked (55.1%)
//
// This is the largest single bypass class found in this codebase to date
// (see [[transform-parity-sweep-bypass-classes]]) — bigger than the
// line-continuation (52.5%) and bash -c (32%) classes.
func TestIndirectExecNameParity(t *testing.T) {
	t.Parallel()
	// Residual leaks decompose into two categories, neither a real bypass:
	//   - Synthetic-transform artifacts: wrapping a shell RESERVED WORD
	//     (for/while/if/...) or prose-shaped guardian/jailbreak test text in
	//     "x=<word>; $x ..." produces invalid/nonsense shell that could never
	//     run that way in a real shell — the corpus has no way to filter
	//     these out generically, so a handful survive the sweep.
	//   - Third-order composition gaps (indirect-exec + heredoc-body-as-sink,
	//     e.g. "x=cat; $x > file <<EOF"): same class of narrow residual left
	//     by prior parity fixes (#3081 left 26.4%->2.4%, decomposing into two
	//     known pre-existing classes). Second-order composition (indirect-exec
	//     wrapping an ALREADY-covered carrier — env/nice/timeout, bash -c,
	//     eval, trap) IS closed: ResolveIndirectExecutable's result is fed
	//     back through StripExecWrapperPrefix/InlineCodeFragments.
	// Ratchet DOWN as fixed; never up without recording why.
	//
	// 2026-08-11 (#3203), +5: analyzer.buildSymbolTable (Layer 2.5 path
	// materialization) now also resolves DeclClause bindings, same shape as
	// the #3248 cmdsubst bump below — the 5 new TP-SSHKEY-SUBST-DECLBIND-*
	// cases measure the keyword delivered indirectly through a scalar var.
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of #3193
	// (TP-READ-SCALAR-EXEC-*/TP-READ-MAPFILE-EXEC-*/TP-READ-READARRAY-EXEC-*)
	// measure the same indirectly-delivered-builtin-name gap through a scalar
	// var: `x=read; $x zc <<< "rm -rf /"; $zc` resolves $x to "read"
	// correctly, but readScalarHereStringElem/mapfileHereStringElems (like
	// readArrayHereStringElems before them) only recognize a LITERAL
	// "read"/"mapfile"/"readarray" token at call.Args[0].
	const maxLeaksScalarVar = 21
	// 2026-08-11 (#3248), +1: the declaration-clause fix closes the LITERAL forms
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
	// 2026-08-11 (#3203), +5: same bump, cmdsubst position — analyzer.
	// buildSymbolTable now resolves DeclClause bindings too, and the 5 new
	// TP-SSHKEY-SUBST-DECLBIND-* cases measure the same indirectly-delivered-
	// keyword gap through $(echo declare)/$(echo export)/etc.
	//
	// 2026-08-12 (#3239), +4: same bump, cmdsubst position — the scalar/mapfile
	// siblings of #3193 measure the same gap through $(echo read)/$(echo
	// mapfile)/$(echo readarray).
	const maxLeaksCmdSubst = 18

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, allBlocking := blockingBaseline(t)

	// Reserved words/keywords can't be assigned to a variable and invoked as
	// "$x" the way a real executable can — wrapping them produces invalid
	// shell, not a genuine indirection, so they're excluded from the sweep
	// rather than counted as leaks.
	notIndirectable := map[string]bool{
		"for": true, "while": true, "until": true, "if": true, "case": true,
		"select": true, "coproc": true, "time": true, "function": true,
		"do": true, "done": true, "then": true, "else": true, "fi": true, "esac": true,
	}
	validFirstWord := func(first string) bool {
		if first == "" || strings.ContainsAny(first, "'\"$`;|&<>(){}=") {
			return false
		}
		return !notIndirectable[first]
	}

	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\n") {
			baseline = append(baseline, tc)
		}
	}

	transforms := map[string]struct {
		render   func(first, rest string) string
		maxLeaks int
	}{
		"scalar-var": {
			render:   func(first, rest string) string { return fmt.Sprintf("x=%s;$x%s", first, rest) },
			maxLeaks: maxLeaksScalarVar,
		},
		"cmdsubst": {
			render:   func(first, rest string) string { return fmt.Sprintf("$(echo %s)%s", first, rest) },
			maxLeaks: maxLeaksCmdSubst,
		},
	}

	for name, tr := range transforms {
		t.Run(name, func(t *testing.T) {
			var leaks []string
			var applicable int
			for _, tc := range baseline {
				idx := strings.IndexByte(tc.Command, ' ')
				if idx < 0 {
					continue
				}
				first, rest := tc.Command[:idx], tc.Command[idx:]
				if !validFirstWord(first) {
					continue
				}
				applicable++
				wrapped := tr.render(first, rest)
				got := string(engine.Evaluate(wrapped, nil).Decision)
				if rank[got] < rank["BLOCK"] {
					leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
				}
			}
			if len(leaks) > tr.maxLeaks {
				t.Errorf("delivering the executable name via %s lowered the decision for %d/%d commands (budget %d).\n"+
					"An indirect executable name runs the same command as writing it directly — see #3089.\n%s",
					name, len(leaks), applicable, tr.maxLeaks, joinLines(leaks))
			}
			t.Logf("indirect-exec-name/%s: %d/%d leaked (budget %d)", name, len(leaks), applicable, tr.maxLeaks)
		})
	}
}
