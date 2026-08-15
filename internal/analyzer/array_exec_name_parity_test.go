package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestArrayIndirectExecNameParity is the fitness function for issue #3091,
// the array-based sibling of TestIndirectExecNameParity (#3089/#3090).
//
// The invariant: an executable name (or the whole command) delivered through a
// bash array element runs EXACTLY the same command as writing it directly, so
// wrapping it this way must never LOWER its decision:
//
//	a=(rm -rf /); "${a[@]}"          == rm -rf /
//	a=(rm -rf /); "${a[*]}"          == rm -rf /
//	a=(rm); ${a[0]} -rf /            == rm -rf /
//
// Before the fix, shellparse.buildExecSymbols skipped array assignments
// entirely and resolveExecParamExp bailed on any indexed expansion, so the
// executable word stayed "${a[@]}"/"${a[0]}" — no structural/semantic/
// dataflow/stateful rule keyed on the real executable ever matched, and the
// regex layer missed it too since the raw text never has the executable name
// adjacent to its flags/args. This is the same fail-open class #3090 closed
// for scalar/cmdsubst indirection, and the largest known remaining bypass at
// the time it was filed.
//
// Resolution is deliberately conservative to hold precision at 100%: only
// constant, fully-literal, positionally-defined array literals are resolved
// (a single dynamic or explicitly-indexed element bails the whole array), so a
// resolved array genuinely IS the command it expands to.
func TestArrayIndirectExecNameParity(t *testing.T) {
	t.Parallel()
	// array-splat is fully closed (0 leaks): "a=(<cmd>); \"${a[@]}\"" expands to
	// the whole command, which shellparse now splits back into argv so every
	// analyzer sees the real executable + args (#3091). The small budget is
	// pure regression headroom for future corpus growth — a resolver regression
	// spikes this to dozens (it was 90/820 before the argv-split fix), so even
	// a low ceiling catches it.
	//
	// array-index residuals are NOT new bypasses — they are exactly the two
	// categories the scalar sweep (#3089/#3090) already documents, surfaced
	// here by the same corpus:
	//   - Synthetic-transform artifacts: wrapping prose-shaped guardian/
	//     jailbreak test text ("a=(Sure,); ${a[0]} here's how ...") produces
	//     nonsense shell the guardian flags as PROSE, not as a runnable command.
	//   - Heredoc/redirect composition gaps ("a=(cat); ${a[0]} > f << 'EOF'"):
	//     the executable resolves fine, but detection hangs off heredoc-body/
	//     redirect analysis — the same narrow composition residual #3081/#3089
	//     left. The element-by-element form also resolves only the EXECUTABLE
	//     position (mirroring the scalar resolver's exec-only scope); the
	//     dominant realistic form ("${a[@]}", whole-command) is fully closed by
	//     the splat sweep above. Widening resolution to argument positions is
	//     the tracked follow-up to #3091.
	// Ratchet DOWN as fixed; never up without recording why.
	const maxLeaksSplat = 3
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
	// 2026-08-11 (#3203), +5: the sibling half of the #3248 declaration-clause
	// fix — analyzer.buildSymbolTable (Layer 2.5 path materialization) now
	// also resolves declare/export/typeset/readonly/local bindings, closing
	// the bare-command form (`declare P1=~/.ssh; declare P2=id_rsa; cat
	// $P1/$P2` now BLOCKs). The 5 new TP-SSHKEY-SUBST-DECLBIND-* cases measure
	// what composing with array-indirection still leaves open:
	//
	//	a=(declare); ${a[0]} P1=~/.ssh; declare P2=id_rsa; cat $P1/$P2
	//
	// `${a[0]}` is not a literal word, so mvdan.cc/sh parses this CallExpr's
	// trailing "P1=~/.ssh" as a plain Arg, not an Assign/DeclClause — the
	// declare-vs-plain-command distinction is a PARSE-TIME classification on
	// the literal executable word, and it's lost the moment the word is
	// itself indirected. `declare` still binds P1 at runtime (it parses its
	// own NAME=value args), but no AST node says so. Same shape as the
	// already-documented heredoc/redirect residual above: resolving it needs
	// executable-indirection resolution (#3091) to run BEFORE symbol-table
	// construction, not another DeclClause case.
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of #3193 — the new
	// TP-READ-SCALAR-EXEC-*/TP-READ-MAPFILE-EXEC-*/TP-READ-READARRAY-EXEC-*
	// cases measure the SAME residual as the DECLBIND entry directly above,
	// one indirection layer removed: "a=(read); ${a[0]} zc <<< \"rm -rf /\";
	// $zc". readScalarHereStringElem/mapfileHereStringElems (like
	// readArrayHereStringElems before them) require call.Args[0] to be the
	// LITERAL token "read"/"mapfile"/"readarray" — `${a[0]}` is a ParamExp,
	// not a Lit, so literalWordValue bails and the binding is never
	// recognized. Composing an array-indirected builtin name with a
	// binding-builtin is the same "indirection stacks past what any single
	// resolver targets" shape, not a new gap.
	const maxLeaksIndex = 20

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, allBlocking := blockingBaseline(t)

	// Reserved words/keywords can't be delivered as an array element and
	// invoked the way a real executable can — wrapping them produces invalid
	// shell, not a genuine indirection, so they're excluded rather than
	// counted as leaks (identical list to the scalar parity sweep).
	notIndirectable := map[string]bool{
		"for": true, "while": true, "until": true, "if": true, "case": true,
		"select": true, "coproc": true, "time": true, "function": true,
		"do": true, "done": true, "then": true, "else": true, "fi": true, "esac": true,
	}
	// A word is array-safe when it survives verbatim as a bare element of
	// "a=( ... )" — no quoting, expansion, or control character that would
	// re-tokenize the array literal or the surrounding command.
	arraySafeWord := func(w string) bool {
		return w != "" && !strings.ContainsAny(w, "'\"$`;|&<>(){}=*?[]~#!\\")
	}

	var baseline []testdata.TestCase
	for _, tc := range allBlocking {
		if !strings.Contains(tc.Command, "\n") {
			baseline = append(baseline, tc)
		}
	}

	// array-splat: wrap the WHOLE command's words as array elements and expand
	// them with "${a[@]}". Applicable only when every word is array-safe.
	t.Run("array-splat", func(t *testing.T) {
		var leaks []string
		var applicable int
		for _, tc := range baseline {
			fields := strings.Fields(tc.Command)
			if len(fields) == 0 {
				continue
			}
			safe := true
			for _, f := range fields {
				if !arraySafeWord(f) {
					safe = false
					break
				}
			}
			if !safe || notIndirectable[fields[0]] {
				continue
			}
			applicable++
			wrapped := fmt.Sprintf(`a=(%s); "${a[@]}"`, strings.Join(fields, " "))
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
			}
		}
		if len(leaks) > maxLeaksSplat {
			t.Errorf("delivering the command via array-splat lowered the decision for %d/%d commands (budget %d).\n"+
				`An array expanded with "${a[@]}" runs the same command as writing it directly — see #3091.`+"\n%s",
				len(leaks), applicable, maxLeaksSplat, joinLines(leaks))
		}
		t.Logf("array-indirect-exec/array-splat: %d/%d leaked (budget %d)", len(leaks), applicable, maxLeaksSplat)
	})

	// array-index: deliver only the executable name via a single-element array
	// (mirrors the scalar-var transform's exec-only scope). "${a[0]}" replaces
	// the first word; the rest of the command stays literal text.
	t.Run("array-index", func(t *testing.T) {
		var leaks []string
		var applicable int
		for _, tc := range baseline {
			idx := strings.IndexByte(tc.Command, ' ')
			if idx < 0 {
				continue
			}
			first, rest := tc.Command[:idx], tc.Command[idx:]
			if !arraySafeWord(first) || notIndirectable[first] {
				continue
			}
			applicable++
			wrapped := fmt.Sprintf(`a=(%s); ${a[0]}%s`, first, rest)
			got := string(engine.Evaluate(wrapped, nil).Decision)
			if rank[got] < rank["BLOCK"] {
				leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
			}
		}
		if len(leaks) > maxLeaksIndex {
			t.Errorf("delivering the executable name via array-index lowered the decision for %d/%d commands (budget %d).\n"+
				"An array element in executable position runs the same command as writing it directly — see #3091.\n%s",
				len(leaks), applicable, maxLeaksIndex, joinLines(leaks))
		}
		t.Logf("array-indirect-exec/array-index: %d/%d leaked (budget %d)", len(leaks), applicable, maxLeaksIndex)
	})
}
