package shellparse

import "mvdan.cc/sh/v3/syntax"

// DeclClauseAssigns returns the value-bearing assignments of a declaration
// clause — `export x=rm`, `declare x=rm`, `local`, `readonly`, `typeset` — for
// the symbol-table walkers that resolve constant bindings.
//
// # Why this is a separate node type at all
//
// Bash's grammar parses a declaration as *syntax.DeclClause, NOT as a
// *syntax.CallExpr carrying Assigns. Any walker that keys on CallExpr therefore
// sees `export x=rm` as no binding at all. DequoteCommand hit this exact wall in
// #2984 and grew its own `case *syntax.DeclClause` — but the lesson stopped
// there. Both constant-symbol collectors (shellparse.buildExecSymbols for the
// executable slot, analyzer.buildSymbolTable for argument materialization) kept
// walking CallExpr only, so one extra word in front of an ordinary assignment
// turned off single-hop indirection resolution entirely:
//
//	x=rm;$x -rf /            -> BLOCK    (#3089 resolves it)
//	export x=rm;$x -rf /     -> AUDIT
//
// Measured over the 2314-command single-line BLOCKing baseline against that
// 0.4% control, every spelling leaked identically:
//
//	export / declare / local / readonly / typeset / declare -x   1436/2314  62.1%
//
// Six numbers with no spread is one defect, not six — so it gets one helper
// both callers share, rather than a `case` copied into each walker where the
// next reader has to diff them.
//
// # The two flags that change the semantics
//
// Returns nil — declining the whole clause — when the declaration carries:
//
//   - `-n` (nameref). `declare -n ref=cmd` makes `$ref` expand to the value of
//     the variable NAMED cmd, not to the string "cmd". Folding it as a scalar
//     would resolve `$ref` to the wrong thing, and a wrong fold is a false
//     positive. The `declare -n` + eval chain has its own dedicated rule
//     (ts-block-nameref-eval-chain) precisely because it is not a plain binding.
//   - `-i` (integer). `declare -i n=3+4` stores 7, not "3+4" — the value is
//     arithmetic-evaluated at assignment time.
//
// A naked argument (`declare -x`, or the bare `export x` re-export form, which
// binds nothing) is skipped rather than recorded, so a caller cannot mistake it
// for a binding to the empty string.
func DeclClauseAssigns(d *syntax.DeclClause) []*syntax.Assign {
	if d == nil {
		return nil
	}
	var out []*syntax.Assign
	for _, a := range d.Args {
		if a == nil {
			continue
		}
		// Flags arrive as naked args with no Name — `declare -n x=y` is
		// [<naked "-n">, <x=y>].
		if a.Name == nil || a.Name.Value == "" {
			if a.Naked && a.Value != nil {
				if flag, ok := literalWordValue(a.Value); ok && declFlagChangesSemantics(flag) {
					return nil
				}
			}
			continue
		}
		if a.Naked || a.Value == nil {
			continue
		}
		out = append(out, a)
	}
	return out
}

// declFlagChangesSemantics reports whether a declaration flag makes the
// assigned text differ from the value the variable ends up holding. Bundled
// spellings (`declare -xn`) count, so the check is per-character.
func declFlagChangesSemantics(flag string) bool {
	if len(flag) < 2 || flag[0] != '-' {
		return false
	}
	for _, c := range flag[1:] {
		if c == 'n' || c == 'i' {
			return true
		}
	}
	return false
}
