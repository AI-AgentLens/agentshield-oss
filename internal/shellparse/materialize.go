package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// MaterializeAssignments returns a reconstruction of command with constant
// `Name=value` assignments propagated into every word that reads them via a
// simple $NAME/${NAME} expansion (optionally through a constant parameter-
// expansion operator, e.g. ${NAME/foo/bar}), mirroring DequoteCommand's
// "parse -> rewrite words in place -> print" shape.
//
// internal/analyzer/substitution.go (Layer 2.5) already performs this exact
// resolution, but its output (ctx.MaterializedPaths) has exactly one
// consumer: the protected_paths glob check in engine.go — roughly ten
// `~/`-rooted entries. None of the ~1,100 pack rules keyed on path/keyword
// literals in command_regex, structural args_any, or dataflow sinks ever see
// a materialized value:
//
//	P1=/root/.ssh; P2=id_rsa; cat $P1/$P2
//
// reads exactly the file sec-block-ssh-private blocks, and AUDITs — 234/1139
// (20.5%) of the BLOCK corpus leaked this way (issue #3249). Folding this as
// a TEXT rewrite, the same shape as DequoteCommand/NormalizeUnsetParamExp/
// ExpandBraces, makes the materialized spelling visible to every text-
// matching rule (wired into RegexAnalyzer's candidate-form list) and, wired
// into parseWithDepth's pre-parse fold chain, to structural/semantic/
// dataflow/stateful as well — all four consume shellparse.Parse's AST, so a
// single fold point fixes every layer downstream of it.
//
// Deliberately simpler than substitution.go's buildSymbolTable: no CmdSubst
// decoder-pipeline folding (`$(echo BASE64 | base64 -d)`) — that stays Layer
// 2.5's job, since it needs analyzer-package helpers shellparse cannot
// import (analyzer already imports shellparse). Only scalar `NAME=value`
// bindings (CallExpr assigns and DeclClause — export/declare/local/
// readonly/typeset) are tracked, resolved to a fixed point so short chains
// (P2=$P1/sub) fold fully.
//
// Same over-approximation as buildExecSymbols/buildSymbolTable: assignments
// are collected from the WHOLE file regardless of branch/scope position, and
// prefix assignments (`FOO=bar cmd`) are treated as if they applied
// script-wide rather than to just that one command's environment. This can
// occasionally resolve a usage to the "wrong" (differently-scoped) constant,
// but never to an attacker-controlled or dynamic value — resolution is
// additive, never weakening, and an unresolved case falls back to exactly
// today's behavior.
//
// Returns "" (a no-op sentinel) when the command has no `$`, no assignments,
// nothing was actually rewritten, or parsing fails — callers should fall
// back to the original text in all four cases.
func MaterializeAssignments(command string) string {
	if !strings.Contains(command, "$") {
		return ""
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return ""
	}

	syms := buildMaterializeSymbols(file)
	if len(syms) == 0 {
		return ""
	}

	changed := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			for _, w := range n.Args {
				if materializeWordInPlace(w, syms) {
					changed = true
				}
			}
		case *syntax.DeclClause:
			for _, a := range n.Args {
				if a.Value != nil && materializeWordInPlace(a.Value, syms) {
					changed = true
				}
			}
		case *syntax.Redirect:
			if n.Word != nil && materializeWordInPlace(n.Word, syms) {
				changed = true
			}
		case *syntax.TestClause:
			if materializeTestExprInPlace(n.X, syms) {
				changed = true
			}
		}
		return true
	})
	if !changed {
		return ""
	}

	var sb strings.Builder
	printer := syntax.NewPrinter()
	if err := printer.Print(&sb, file); err != nil {
		return ""
	}
	// The printer always terminates a script with a trailing newline; strip
	// it so the reconstruction compares like a single command_regex subject.
	return strings.TrimSuffix(sb.String(), "\n")
}

// materializePending is a not-yet-resolved `Name=value` binding awaiting a
// later fixed-point pass, mirroring substitution.go's buildSymbolTable.
type materializePending struct {
	name string
	word *syntax.Word
}

// buildMaterializeSymbols scans every CallExpr and DeclClause assignment and
// returns the constant symbol table for values statically resolvable via
// resolveConstWord, iterating to a fixed point so short chains (P1=/root/.ssh;
// P2=$P1/sub) resolve fully. Bound the iteration count to len(pending)+1 so a
// malformed input can't loop.
func buildMaterializeSymbols(file *syntax.File) map[string]string {
	var pending []materializePending
	addAssigns := func(assigns []*syntax.Assign) {
		for _, asn := range assigns {
			if asn.Name == nil || asn.Name.Value == "" {
				continue
			}
			pending = append(pending, materializePending{name: asn.Name.Value, word: asn.Value})
		}
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			addAssigns(node.Assigns)
		case *syntax.DeclClause:
			addAssigns(DeclClauseAssigns(node))
		}
		return true
	})

	if len(pending) == 0 {
		return nil
	}

	syms := make(map[string]string, len(pending))
	maxPasses := len(pending) + 1
	for pass := 0; pass < maxPasses; pass++ {
		progressed := false
		stillPending := pending[:0]
		for _, p := range pending {
			if p.word == nil {
				if _, exists := syms[p.name]; !exists {
					syms[p.name] = ""
					progressed = true
				}
				continue
			}
			if val, ok := resolveConstWord(p.word, syms); ok {
				if existing, exists := syms[p.name]; !exists || existing != val {
					syms[p.name] = val
					progressed = true
				}
			} else {
				stillPending = append(stillPending, p)
			}
		}
		pending = stillPending
		if !progressed || len(pending) == 0 {
			break
		}
	}

	if len(syms) == 0 {
		return nil
	}
	return syms
}

// resolveConstWord renders w to a string by concatenating its Parts against
// syms. Returns ok=false when any Part can't be statically resolved
// (CmdSubst, arithmetic, unbound variable, etc.) — mirrors
// substitution.go's materializeWord, minus the CmdSubst decoder-pipeline
// fold (analyzer-package-only, see the package doc comment above).
func resolveConstWord(w *syntax.Word, syms map[string]string) (string, bool) {
	if w == nil {
		return "", true
	}
	var sb strings.Builder
	for _, p := range w.Parts {
		if !appendConstPart(&sb, p, syms) {
			return "", false
		}
	}
	return sb.String(), true
}

// appendConstPart writes one WordPart into sb against syms, returning false
// if the part can't be statically resolved. Mirrors substitution.go's
// appendPart.
func appendConstPart(sb *strings.Builder, p syntax.WordPart, syms map[string]string) bool {
	switch part := p.(type) {
	case *syntax.Lit:
		sb.WriteString(part.Value)
		return true
	case *syntax.SglQuoted:
		sb.WriteString(part.Value)
		return true
	case *syntax.DblQuoted:
		for _, dp := range part.Parts {
			if !appendConstPart(sb, dp, syms) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		if part.Param == nil || part.Param.Value == "" {
			return false
		}
		val, bound := syms[part.Param.Value]
		// Bail on array indices, length/width queries, indirect refs, the
		// zsh nested-param form — these select a DIFFERENT value than the
		// scalar syms[name] entry. The exception is an operator whose
		// operands are ALSO constant (substring, search-replace,
		// prefix/suffix removal, case change) applied to a variable already
		// known to hold a constant — see FoldConstantParamOp (#3220).
		if part.Slice != nil || part.Repl != nil || part.Exp != nil ||
			part.Index != nil || part.NestedParam != nil ||
			part.Length || part.Width || part.Excl {
			if !bound {
				return false
			}
			folded, ok := FoldConstantParamOp(val, part)
			if !ok {
				return false
			}
			sb.WriteString(folded)
			return true
		}
		if !bound {
			return false
		}
		sb.WriteString(val)
		return true
	default:
		// CmdSubst, ArithmExp, ProcSubst, ExtGlob — not statically
		// resolvable here (CmdSubst decoder-pipeline folding stays Layer
		// 2.5's job, see package doc comment above).
		return false
	}
}

// materializeWordInPlace rewrites w's Parts in place to a single Lit holding
// its fully-resolved value, IF the word contains at least one part that
// isn't a plain literal (so there's something to materialize) AND every
// such part resolves via syms. A word that's already pure literal text, or
// that contains any part that can't be resolved, is left completely
// untouched — partial materialization would corrupt the remaining dynamic
// syntax. Mirrors dequoteWordInPlace's all-or-nothing-per-word shape.
//
// Whether the resolved value must be re-quoted depends on whether bash would
// word-split it. A bare top-level ParamExp (`/root/.ssh/$p`) is unquoted, so
// bash DOES split a multi-word resolution — printing it as a flat Lit and
// letting a downstream re-parse re-tokenize it on whitespace reproduces that
// splitting correctly (hasBareParamExp branch). But a ParamExp wrapped in a
// DblQuoted (`"$zc"`) is split-protected regardless of its content — the
// whole word is ONE argv token in real bash no matter what zc resolves to —
// so the reconstruction must reproduce that boundary explicitly (issue
// #3352: bash -c "$zc" printed as a bare unquoted Lit lost its quoting,
// so a re-parse split zc's multi-word value into extra argv tokens and
// bash -c's own "-c" only takes the first word after it, truncating the
// effective payload to a single word and hiding everything after it from
// every AST-based analyzer).
func materializeWordInPlace(w *syntax.Word, syms map[string]string) bool {
	if w == nil || !partsRequireMaterialization(w.Parts) {
		return false
	}
	val, ok := resolveConstWord(w, syms)
	if !ok {
		return false
	}
	if hasBareParamExp(w.Parts) {
		w.Parts = []syntax.WordPart{&syntax.Lit{ValuePos: w.Pos(), ValueEnd: w.End(), Value: val}}
		return true
	}
	w.Parts = []syntax.WordPart{&syntax.Lit{ValuePos: w.Pos(), ValueEnd: w.End(), Value: shellSingleQuote(val)}}
	return true
}

// hasBareParamExp reports whether parts contains a top-level *syntax.ParamExp
// — an expansion with no enclosing DblQuoted/SglQuoted. Only a bare
// top-level expansion is subject to bash word-splitting; one nested inside a
// DblQuoted is protected no matter what it resolves to.
func hasBareParamExp(parts []syntax.WordPart) bool {
	for _, p := range parts {
		if _, ok := p.(*syntax.ParamExp); ok {
			return true
		}
	}
	return false
}

// shellSingleQuote renders val as single-quoted shell source text that
// re-parses to exactly val as one argv token. Single quotes can't escape a
// quote character internally, so an embedded `'` must close the quoted span,
// emit the literal quote via a backslash escape outside it, then reopen the
// span — the standard POSIX idiom.
func shellSingleQuote(val string) string {
	if !strings.Contains(val, "'") {
		return "'" + val + "'"
	}
	return "'" + strings.ReplaceAll(val, "'", `'\''`) + "'"
}

// partsRequireMaterialization reports whether parts contains at least one
// part that isn't a plain literal (Lit or SglQuoted, recursively for
// DblQuoted contents) — mirrors substitution.go's partsRequireSubstitution.
func partsRequireMaterialization(parts []syntax.WordPart) bool {
	for _, p := range parts {
		switch part := p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			continue
		case *syntax.DblQuoted:
			if partsRequireMaterialization(part.Parts) {
				return true
			}
		default:
			return true
		}
	}
	return false
}

// materializeTestExprInPlace recurses through a `[[ ... ]]` test expression
// to reach its Word operands, mirroring dequoteTestExpr.
func materializeTestExprInPlace(expr syntax.TestExpr, syms map[string]string) bool {
	switch e := expr.(type) {
	case *syntax.Word:
		return materializeWordInPlace(e, syms)
	case *syntax.UnaryTest:
		return materializeTestExprInPlace(e.X, syms)
	case *syntax.BinaryTest:
		// Evaluate both sides unconditionally — this is a mutation walk, not
		// a boolean short-circuit.
		left := materializeTestExprInPlace(e.X, syms)
		right := materializeTestExprInPlace(e.Y, syms)
		return left || right
	case *syntax.ParenTest:
		return materializeTestExprInPlace(e.X, syms)
	default:
		return false
	}
}
