package analyzer

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// SubstitutionAnalyzer (Layer 2.5) materializes shell commands by propagating
// constant variable assignments through the AST. It exists because rules that
// match credential-path literals (e.g., ~/.ssh/id_rsa) are bypassed by the
// trivial split-concat pattern:
//
//	P1=~/.ssh; P2=id_rsa; cat $P1/$P2
//
// The structural analyzer never inspected `*syntax.Assign` nodes, so the
// materialized path was invisible to the policy engine. Layer 2.5 fills that
// gap: it walks the AST, collects assignments whose right-hand side is
// statically constant (literals + already-resolved vars, no command
// substitutions or unknown vars), and appends any reconstructed argument that
// could be a path to ctx.MaterializedPaths. The engine re-runs protected-path
// matching against those after the pipeline, so the same policy that catches
// `cat ~/.ssh/id_rsa` now catches the split-concat form.
//
// Decoder pipelines (`cat $(echo b64 | base64 -d)`) are out of scope here —
// see #1699 for the constant-fold extension that plugs into this same layer.
type SubstitutionAnalyzer struct{}

// NewSubstitutionAnalyzer constructs the Layer 2.5 analyzer. Stateless — no
// configuration knobs today; if we ever need a max-vars or max-iterations
// guard, add it here.
func NewSubstitutionAnalyzer() *SubstitutionAnalyzer {
	return &SubstitutionAnalyzer{}
}

func (a *SubstitutionAnalyzer) Name() string { return "substitution" }

// Analyze re-parses ctx.RawCommand with mvdan.cc/sh, builds a symbol table
// from constant `Name=value` assignments, and substitutes those into every
// CallExpr argument. Materialized strings are appended to
// ctx.MaterializedPaths for the engine to re-check.
//
// Why re-parse instead of reading ctx.Parsed: shellparse.CommandSegment is a
// flattened view (Args []string) that drops the AST's Assign nodes. Layer 2.5
// needs the full *syntax.File to see assignments and ParamExp nodes
// individually. The cost is microseconds per command — irrelevant compared to
// the rest of the pipeline.
//
// Returns no Findings: this layer enriches the context, the engine enforces.
func (a *SubstitutionAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	if ctx.RawCommand == "" {
		return nil
	}

	// Canonicalize ${IFS}/$IFS word-splitting separators to literal spaces
	// first (#3044), same as the primary parse path in shellparse.Parse —
	// this layer re-parses independently rather than reusing ctx.Parsed (see
	// doc comment above), so it needs its own copy of the fix or a
	// split-concat assignment chain joined by ${IFS} instead of a literal
	// space silently stayed invisible to symbol-table construction.
	rawCommand := ctx.RawCommand
	if normalized := shellparse.NormalizeIFS(rawCommand); normalized != "" {
		rawCommand = normalized
	}
	// Same reasoning one step further: a split-concat assignment chain whose
	// pieces are glued with an unset-parameter splice ("P=/et${zqx}c/shadow")
	// is invisible to symbol-table construction until the splice is folded.
	if normalized := shellparse.NormalizeUnsetParamExp(rawCommand); normalized != "" {
		rawCommand = normalized
	}

	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(rawCommand), "")
	if err != nil {
		// Parse failure is not Layer 2.5's problem — the regex layer still
		// covers literal cases and the structural layer's fallback handles
		// crude tokenization. Stay silent.
		return nil
	}

	// Note: don't early-return on empty syms. Pure-constant decoder pipelines
	// like `cat $(echo BASE64 | base64 -d)` have no assignments, yet they're
	// the canonical attack shape #1699 needs to fold. materializeArgs handles
	// the empty-syms case correctly (no var lookups attempted).
	syms := buildSymbolTable(file)

	materialized := materializeArgs(file, syms)
	if len(materialized) == 0 {
		return nil
	}

	// Dedupe to keep the engine's protected-path scan tight; commands that
	// reference $VAR multiple times shouldn't blow up the materialized list.
	seen := make(map[string]struct{}, len(ctx.MaterializedPaths)+len(materialized))
	for _, p := range ctx.MaterializedPaths {
		seen[p] = struct{}{}
	}
	for _, p := range materialized {
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		ctx.MaterializedPaths = append(ctx.MaterializedPaths, p)
	}

	return nil
}

// buildSymbolTable scans every CallExpr and collects assignments whose value
// is statically materializable. Iterates to a fixed point so chains like
//
//	P1=~/.ssh
//	P2=$P1/sub
//
// resolve fully (P2 is unmaterializable on pass 1, materializable on pass 2
// once P1 is in the table).
//
// Bound the iteration count to len(syms-candidates)+1 so a malformed input
// can't put us in a loop. In practice attacks use shallow chains (1-3 deep);
// the bound is just a safety net.
func buildSymbolTable(file *syntax.File) map[string]string {
	type pendingAssign struct {
		name string
		word *syntax.Word
	}
	var pending []pendingAssign

	addAssigns := func(assigns []*syntax.Assign) {
		for _, asn := range assigns {
			if asn.Name == nil || asn.Name.Value == "" {
				continue
			}
			pending = append(pending, pendingAssign{name: asn.Name.Value, word: asn.Value})
		}
	}

	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.CallExpr:
			addAssigns(node.Assigns)
		case *syntax.DeclClause:
			// `declare`/`export`/`typeset`/`readonly`/`local` parse as
			// *syntax.DeclClause, not a CallExpr carrying Assigns — a walker
			// keyed on CallExpr sees no binding at all. #3299 closed this for
			// the executable-position resolver (shellparse.buildExecSymbols);
			// this is the sibling gap in path materialization (#3203):
			//
			//	P1=~/.ssh; P2=id_rsa; cat $P1/$P2               -> materialized
			//	declare P1=~/.ssh; declare P2=id_rsa; cat $P1/$P2 -> NOT materialized
			//
			// DeclClauseAssigns already declines `-n`/`-i` (semantics-changing
			// flags) and naked re-declarations, so no new false-positive surface.
			addAssigns(shellparse.DeclClauseAssigns(node))
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
				// Empty assignment (FOO=) — record as empty string.
				if _, exists := syms[p.name]; !exists {
					syms[p.name] = ""
					progressed = true
				}
				continue
			}
			if val, ok := materializeWord(p.word, syms); ok {
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

	return syms
}

// materializeArgs walks every CallExpr argument, redirect target, and
// `[[ ... ]]` test operand, returning the materialized form of each word that
// requires substitution to surface its concrete value. Pure-literal words
// (just Lit / SglQuoted, possibly nested in DblQuoted) are skipped — they've
// already been seen unchanged by the regex/structural layers, so re-emitting
// them would just clutter the protected-path scan.
//
// "Requires substitution" covers: ParamExp ($VAR / ${VAR}), CmdSubst
// ($(...)), and any other non-literal Part. The decision to attempt
// materialization is intentionally generous — materializeWord bails cleanly
// on values it can't fold (unknown vars, unrecognized decoders), so we're
// trading a microsecond of extra parsing for symmetric coverage of the
// substitution and decoder-fold cases.
//
// Redirect targets and TestClause operands are walked in addition to
// CallExpr args because a split-concat credential path doesn't have to
// appear as a command argument to be read: `P1=~/.ssh; P2=id_rsa; cat <
// $P1/$P2` and `P1=~/.ssh; P2=id_rsa; [[ -f $P1/$P2 ]]` both resolve the same
// path a real shell would open, but a walk scoped to CallExpr.Args alone
// never sees either — the path stayed out of ctx.MaterializedPaths entirely,
// so the protected-path post-pass in engine.go had nothing to check (#3325,
// residual of the AST-walker-blind-spot class #3322 closed for
// shellparse.DequoteCommand). Mirrors dequote.go's Redirect/TestClause cases
// and dequoteTestExpr's TestExpr recursion.
func materializeArgs(file *syntax.File, syms map[string]string) []string {
	var out []string
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			for _, w := range n.Args {
				appendMaterializedWord(w, syms, &out)
			}
		case *syntax.Redirect:
			appendMaterializedWord(n.Word, syms, &out)
		case *syntax.TestClause:
			materializeTestExpr(n.X, syms, &out)
		}
		return true
	})
	return out
}

// appendMaterializedWord materializes w (if it needs substitution at all)
// and appends the result to out. Shared by CallExpr args, Redirect targets,
// and TestClause operands so all three surfaces apply identical logic.
func appendMaterializedWord(w *syntax.Word, syms map[string]string, out *[]string) {
	if !wordRequiresSubstitution(w) {
		return
	}
	if val, ok := materializeWord(w, syms); ok && val != "" {
		*out = append(*out, val)
	}
}

// materializeTestExpr recurses through a `[[ ... ]]` test expression to reach
// its Word operands — TestExpr's only concrete implementations
// (mvdan.cc/sh/v3/syntax) are *BinaryTest ("a == b"), *UnaryTest ("-f x"),
// *ParenTest ("( ... )"), and *Word (a bare word used as a boolean test), so
// a single case on *syntax.TestClause can't reach the words directly. Mirrors
// dequoteTestExpr in dequote.go.
func materializeTestExpr(expr syntax.TestExpr, syms map[string]string, out *[]string) {
	switch e := expr.(type) {
	case *syntax.Word:
		appendMaterializedWord(e, syms, out)
	case *syntax.UnaryTest:
		materializeTestExpr(e.X, syms, out)
	case *syntax.BinaryTest:
		materializeTestExpr(e.X, syms, out)
		materializeTestExpr(e.Y, syms, out)
	case *syntax.ParenTest:
		materializeTestExpr(e.X, syms, out)
	}
}

// materializeWord renders a Word to a string by concatenating its Parts.
// Returns ok=false when any Part can't be statically resolved (CmdSubst,
// arithmetic, ${VAR:-default}, unknown var, etc.) — the caller treats that as
// "not materializable yet" and defers.
func materializeWord(w *syntax.Word, syms map[string]string) (string, bool) {
	if w == nil {
		return "", true
	}
	var sb strings.Builder
	for _, p := range w.Parts {
		if !appendPart(&sb, p, syms) {
			return "", false
		}
	}
	return sb.String(), true
}

// appendPart writes one WordPart into sb, returning false if the part can't
// be statically resolved. Split out so DblQuoted (which contains its own
// nested parts) can recurse with the same logic.
func appendPart(sb *strings.Builder, p syntax.WordPart, syms map[string]string) bool {
	switch part := p.(type) {
	case *syntax.Lit:
		sb.WriteString(part.Value)
		return true
	case *syntax.SglQuoted:
		// Single-quoted strings are entirely literal in bash — no expansion
		// happens inside, so the value is the inner text verbatim.
		sb.WriteString(part.Value)
		return true
	case *syntax.DblQuoted:
		for _, dp := range part.Parts {
			if !appendPart(sb, dp, syms) {
				return false
			}
		}
		return true
	case *syntax.ParamExp:
		// Only resolve the simple shapes: $NAME and ${NAME}. Anything fancier
		// (${NAME:-default}, ${NAME//foo/bar}, ${NAME:0:3}, $1, $@, $?) is
		// unsafe to fold without a runtime: bail out.
		if part.Param == nil || part.Param.Value == "" {
			return false
		}
		val, bound := syms[part.Param.Value]
		// Bail on array indices, length/width queries, indirect refs (${!a}),
		// and the zsh nested-param form — these select a DIFFERENT value than
		// the scalar `syms[name]` entry, so no fold here is correct for them.
		//
		// The exception is an operator whose operands are ALSO constant —
		// substring (${a:0:3}), search-replace (${a/foo/bar}), prefix/suffix
		// removal, case change — applied to a variable already known to hold a
		// constant. `p=/etc/shadQow; cat ${p/Q/}` reads /etc/shadow on every
		// shell; refusing to materialize it hid the path from every rule keyed
		// on the real spelling (#3220, the argument-position half of the same
		// bypass class as the executable-position fold in shellparse).
		if part.Slice != nil || part.Repl != nil || part.Exp != nil ||
			part.Index != nil || part.NestedParam != nil ||
			part.Length || part.Width || part.Excl {
			if !bound {
				return false
			}
			folded, ok := shellparse.FoldConstantParamOp(val, part)
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
	case *syntax.CmdSubst:
		// Layer 2.5 extension (#1699): try to fold a constant decoder
		// pipeline like `$(echo BASE64 | base64 -d)` to its decoded value.
		// If the inner command isn't a recognized decoder pipeline operating
		// on a statically resolvable input, bail — the runtime semantics are
		// otherwise unknown and a wrong fold would produce false BLOCKs.
		val, ok := tryFoldDecoderPipeline(part, syms)
		if !ok {
			return false
		}
		sb.WriteString(val)
		return true
	default:
		// ArithmExp, ProcSubst, ExtGlob — not statically resolvable.
		return false
	}
}

// wordRequiresSubstitution reports whether the word contains at least one
// part that isn't a plain literal. Pure-literal words (just Lit or
// SglQuoted, recursively for DblQuoted contents) are skipped by
// materializeArgs because their value is already visible to the literal-
// matching layers — there's nothing to "materialize."
//
// Returns true for words containing ParamExp ($VAR), CmdSubst ($(...)),
// arithmetic, process substitution, etc. We don't pre-check whether those
// nodes will actually resolve — materializeWord makes the final
// determination and bails cleanly when it can't.
func wordRequiresSubstitution(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	return partsRequireSubstitution(w.Parts)
}

func partsRequireSubstitution(parts []syntax.WordPart) bool {
	for _, p := range parts {
		switch part := p.(type) {
		case *syntax.Lit, *syntax.SglQuoted:
			continue
		case *syntax.DblQuoted:
			if partsRequireSubstitution(part.Parts) {
				return true
			}
		default:
			return true
		}
	}
	return false
}
