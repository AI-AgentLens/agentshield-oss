package shellparse

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// FoldConstantParamOp applies a parameter-expansion OPERATOR to an
// already-known constant value and returns the text a real shell produces.
//
// Issue #3220. The constant-scalar resolvers (#3089's resolveExecParamExp,
// substitution.go's appendPart) both fold the bare `$x` / `${x}` shape and
// then bail on every operator form — slice, replace, prefix/suffix removal,
// case modification — because "an operator makes it dynamic". That reasoning
// is right for an unbound variable and wrong for a bound one: when the value
// AND the operator's operands are both compile-time constants, the result is
// too. `x=rQm; ${x/Q/} -rf /` runs exactly `rm -rf /`, deterministically,
// every time.
//
// That gap was the largest bypass class measured in this codebase: over the
// BLOCKing corpus, re-spelling the executable as `${x/Q/}` downgraded
// 1721/2265 commands (76.0%) and as `${x:0:N}` 1712/2265 (75.6%) — past the
// 75.1% unset-parameter class (#3206) and the 68.6% ${IFS} class (#3044). It
// is the natural attacker move the moment #3089 closed plain `$x`: the
// variable is still constant, only the spelling of the read changed.
//
// Every fold here is exact or it does not happen. Three guards enforce that:
//
//   - Glob-free patterns only. Bash pattern operators (`/pat/`, `#pat`, `%pat`)
//     take GLOBS, not literals, so `${x/[a-z]/}` is not a string replace.
//     Rather than reimplement bash globbing — where being subtly wrong means
//     folding to a command the shell never runs — any pattern containing
//     `*?[\` is refused. Glob-free patterns make the small/large operator
//     pair (`#` vs `##`) identical, which is why they share a branch.
//   - Constant integer slice bounds only. A negative offset counts from the
//     end and a negative length trims from it; both are refused rather than
//     approximated, as is any non-literal (arithmetic or parameter-valued)
//     bound.
//   - One operator at a time, and never combined with an index, `${!x}`
//     indirection, or `${#x}` length. Those are separate shapes with their own
//     resolution rules; mixing them here would fold a value bash never forms.
//
// Anything that fails a guard returns ok=false and the caller keeps the word
// unresolved — the exact behaviour that existed before this fix, so a refused
// fold can only ever be a missed detection, never a wrong one.
func FoldConstantParamOp(val string, part *syntax.ParamExp) (string, bool) {
	if part == nil {
		return "", false
	}
	// Shapes that are not "an operator applied to this scalar" at all: an
	// array index selects a different value, ${!x} reads a different variable
	// entirely, and ${#x}/${%x} yield a count rather than a transformation.
	if part.Excl || part.Length || part.Width ||
		part.NestedParam != nil || part.Index != nil {
		return "", false
	}

	// Bash permits exactly one of these per expansion. Anything else is a
	// shape this function was not written for.
	switch {
	case part.Slice != nil && part.Repl == nil && part.Exp == nil:
		return foldSliceOp(val, part.Slice)
	case part.Repl != nil && part.Slice == nil && part.Exp == nil:
		return foldReplaceOp(val, part.Repl)
	case part.Exp != nil && part.Slice == nil && part.Repl == nil:
		return foldExpansionOp(val, part.Exp)
	}
	return "", false
}

// foldSliceOp computes ${val:off} / ${val:off:len}. Bash counts in characters,
// not bytes, so the value is sliced as runes — folding a multi-byte value by
// byte offset would produce a string the shell never forms.
func foldSliceOp(val string, sl *syntax.Slice) (string, bool) {
	if sl == nil || sl.Offset == nil {
		return "", false
	}
	off, ok := constArithmInt(sl.Offset)
	if !ok || off < 0 {
		return "", false
	}
	runes := []rune(val)
	if off >= len(runes) {
		return "", true // bash yields the empty string past the end
	}
	out := runes[off:]
	if sl.Length != nil {
		n, ok := constArithmInt(sl.Length)
		if !ok || n < 0 {
			return "", false
		}
		if n < len(out) {
			out = out[:n]
		}
	}
	return string(out), true
}

// foldReplaceOp computes ${val/pat/rep} and ${val//pat/rep}.
func foldReplaceOp(val string, r *syntax.Replace) (string, bool) {
	pat, ok := literalPatternValue(r.Orig)
	if !ok || pat == "" {
		return "", false
	}
	// ${x/#pat/rep} and ${x/%pat/rep} anchor the match to the start/end of the
	// value. syntax.Replace has no field for that anchor — it stays inside the
	// pattern word — so a pattern that begins with one is a shape this fold
	// would silently get wrong, and is refused.
	if strings.HasPrefix(pat, "#") || strings.HasPrefix(pat, "%") {
		return "", false
	}
	rep, ok := literalWordValue(r.With)
	if !ok {
		return "", false
	}
	if r.All {
		return strings.ReplaceAll(val, pat, rep), true
	}
	return strings.Replace(val, pat, rep, 1), true
}

// foldExpansionOp computes the prefix/suffix-removal and case-modification
// operators. The removal pair collapses to Trim{Prefix,Suffix} because
// literalPatternValue has already refused every pattern where "shortest match"
// and "longest match" could differ.
func foldExpansionOp(val string, e *syntax.Expansion) (string, bool) {
	if e == nil {
		return "", false
	}
	switch e.Op {
	case syntax.RemSmallPrefix, syntax.RemLargePrefix:
		pat, ok := literalPatternValue(e.Word)
		if !ok || pat == "" {
			return "", false
		}
		return strings.TrimPrefix(val, pat), true
	case syntax.RemSmallSuffix, syntax.RemLargeSuffix:
		pat, ok := literalPatternValue(e.Word)
		if !ok || pat == "" {
			return "", false
		}
		return strings.TrimSuffix(val, pat), true
	case syntax.UpperAll, syntax.UpperFirst, syntax.LowerAll, syntax.LowerFirst:
		// The optional pattern argument (${x^^[aeiou]}) restricts WHICH
		// characters change case; only the no-pattern form is folded.
		if !emptyPatternWord(e.Word) {
			return "", false
		}
		return foldCase(val, e.Op), true
	}
	// Default/alternate/assign/error (:- := :? :+) and the @-operators are
	// deliberately not folded here. The unset-variable side of the default
	// operators is owned by NormalizeUnsetParamExp (#3206); duplicating it
	// would give one shape two disagreeing resolvers.
	return "", false
}

func foldCase(val string, op syntax.ParExpOperator) string {
	switch op {
	case syntax.UpperAll:
		return strings.ToUpper(val)
	case syntax.LowerAll:
		return strings.ToLower(val)
	}
	runes := []rune(val)
	if len(runes) == 0 {
		return val
	}
	if op == syntax.UpperFirst {
		runes[0] = []rune(strings.ToUpper(string(runes[0])))[0]
	} else {
		runes[0] = []rune(strings.ToLower(string(runes[0])))[0]
	}
	return string(runes)
}

// literalPatternValue renders a bash PATTERN word to its literal text, refusing
// any word that is dynamic (via literalWordValue) or that carries glob
// metacharacters. See FoldConstantParamOp's doc comment for why a glob is
// refused rather than interpreted.
func literalPatternValue(w *syntax.Word) (string, bool) {
	v, ok := literalWordValue(w)
	if !ok {
		return "", false
	}
	if strings.ContainsAny(v, `*?[\`) {
		return "", false
	}
	return v, true
}

// emptyPatternWord reports whether a case-modification operator was written
// with no pattern argument (${x,,} rather than ${x,,[aeiou]}).
func emptyPatternWord(w *syntax.Word) bool {
	if w == nil || len(w.Parts) == 0 {
		return true
	}
	v, ok := literalWordValue(w)
	return ok && v == ""
}

// constArithmInt reads a slice bound that is a plain integer literal, reusing
// the same arithmLiteral primitive the constant-array index resolver (#3091)
// uses. An arithmetic or parameter-valued bound returns ok=false.
func constArithmInt(e syntax.ArithmExpr) (int, bool) {
	lit := arithmLiteral(e)
	if lit == "" {
		return 0, false
	}
	n, err := strconv.Atoi(lit)
	if err != nil {
		return 0, false
	}
	return n, true
}
