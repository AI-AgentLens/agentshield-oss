package analyzer_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestDeclClauseBindingParity is the fitness function for the declaration-clause
// symbol-table blind spot.
//
// The invariant: `export x=rm` binds x exactly as `x=rm` does. Writing the
// declaration keyword must therefore never lower a decision.
//
// Bash parses a declaration as *syntax.DeclClause rather than as a CallExpr
// carrying Assigns, and both constant-symbol collectors walked CallExpr only.
// DequoteCommand had already hit this wall in #2984 and grown its own
// `case *syntax.DeclClause`; the lesson was never propagated to the two
// collectors. Measured over the 2314-command single-line BLOCKing baseline
// against the 0.4% plain-`x=rm` control:
//
//	export / declare / local / readonly / typeset / `declare -x`  1436/2314  62.1%
//	`export x=Z<exe>; ${x#Z} …` (composed with #3244's operators) 1694/2314  73.2%
//
// Six spellings with zero spread is one shared defect, so one corpus position
// proves the wiring and the per-keyword breadth lives in the cheap
// shellparse.TestDeclClauseAssigns table — same sizing rule as
// TestParamExpOperatorParity.
func TestDeclClauseBindingParity(t *testing.T) {
	// Same #3089 synthetic-transform residual as every other exec-name sweep.
	//
	// 2026-08-11 (#3203), +5: analyzer.buildSymbolTable (Layer 2.5 path
	// materialization) now also resolves DeclClause bindings, matching this
	// resolver. The 5 new TP-SSHKEY-SUBST-DECLBIND-* cases measure the same
	// pre-existing "keyword delivered indirectly" gap this file's own scope
	// deliberately excludes (indirection resolves ${x/Q/} etc. to the literal
	// keyword, but the keyword's OWN CallExpr no longer carries the Assigns
	// that made it a DeclClause in the first place — see array_exec_name and
	// wrapper parity tests for the fuller writeup of this shape).
	//
	// 2026-08-12 (#3239), +4: the scalar/mapfile siblings of #3193
	// (TP-READ-SCALAR-EXEC-*/TP-READ-MAPFILE-EXEC-*/TP-READ-READARRAY-EXEC-*)
	// measure the same gap — `export x=read;$x zc <<< "rm -rf /"; $zc` binds
	// x to "read" correctly, but $x's own CallExpr is no longer the DeclClause
	// that made readScalarHereStringElem/mapfileHereStringElems recognize the
	// literal keyword in the first place.
	const maxLeaks = 21

	rank := map[string]int{"ALLOW": 0, "AUDIT": 1, "REQUIRE_APPROVAL": 2, "BLOCK": 3}
	engine, allBlocking := blockingBaseline(t)

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

	var leaks []string
	var applicable int
	for _, tc := range allBlocking {
		if strings.Contains(tc.Command, "\n") {
			continue
		}
		idx := strings.IndexByte(tc.Command, ' ')
		if idx < 0 {
			continue
		}
		first, rest := tc.Command[:idx], tc.Command[idx:]
		if !validFirstWord(first) {
			continue
		}
		applicable++
		wrapped := fmt.Sprintf("export x=%s;$x%s", first, rest)
		got := string(engine.Evaluate(wrapped, nil).Decision)
		if rank[got] < rank["BLOCK"] {
			leaks = append(leaks, fmt.Sprintf("%s: BLOCK -> %s : %s", tc.ID, got, wrapped))
		}
	}

	assertProbeNotVacuous(t, "decl-clause-binding", applicable, 1500)
	if len(leaks) > maxLeaks {
		t.Errorf("binding the executable name with `export` instead of a bare assignment lowered the decision for %d/%d commands (budget %d).\n"+
			"`export x=rm` binds x identically to `x=rm` — see shellparse.DeclClauseAssigns.\n%s",
			len(leaks), applicable, maxLeaks, joinLines(leaks))
	}
	t.Logf("decl-clause-binding: %d/%d leaked (budget %d)", len(leaks), applicable, maxLeaks)

	_ = testdata.TestCase{}
}
