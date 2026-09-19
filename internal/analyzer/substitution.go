package analyzer

import (
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/mountspec"
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
	// The fixed-point table SEEDS the ordered walk, which is what still
	// resolves a forward reference or a function body defined before its
	// variable is bound — see substitution_scope.go.
	syms := buildSymbolTable(file)

	ev := newScopeEval(syms)
	ev.walk(file)
	materialized := ev.out

	// Publish the resolved bindings before the materialized-path early
	// return: `export KUBECONFIG=$HOME/.kube/config` has no CallExpr
	// argument, redirect or test operand at all, so the walk finds nothing
	// and this method used to return with the binding invisible.
	// The engine attributes an assignment into a consumer's environment
	// credential slot; it never blocks on one (#3630).
	ctx.Assignments = appendAssignments(ctx.Assignments, mergeSyms(syms, ev.ownedBindings()))

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

// appendAssignments folds the resolved symbol table into out, sorted by name
// so two runs on the same command report the same binding first (map range
// order is randomised, and the engine names ONE variable in the audit
// reason). Empty values are dropped: `FOO=` binds nothing a path check could
// match, and keeping it would only pad the context.
func appendAssignments(out []Assignment, syms map[string]string) []Assignment {
	if len(syms) == 0 {
		return out
	}
	names := make([]string, 0, len(syms))
	for name, val := range syms {
		if val == "" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out = append(out, Assignment{Name: name, Value: syms[name]})
	}
	return out
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

// Where the argument walk lives now (#3706): scopeEval in
// substitution_scope.go. It covers the same surfaces this function did —
// every CallExpr argument, redirect target and `[[ … ]]` test operand — and
// adds source ordering, so a word is materialized against the bindings that
// are live where it is written.
//
// Pure-literal words (just Lit / SglQuoted, possibly nested in DblQuoted) are
// still skipped: they have already been seen unchanged by the regex and
// structural layers, so re-emitting them would only clutter the protected-path
// scan.
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

// materializedMountSources returns the host paths a container bind mount in
// this call reads, once its spec has been substituted (#3630).
//
// The literal spellings (`docker run -v ~/.creds:/mnt img`) are already
// covered by the normalizer's own extraction; this exists for the
// variable-indirected form the whole layer was built for —
// `V=$HOME/.creds; docker run -v $V:/mnt img` — where the source is only a
// path after the symbol table is applied.
//
// Unmaterializable words become "" rather than being dropped, so a flag and
// its value keep their adjacency and `-v` is not silently paired with the
// word after its own operand.
func materializedMountSources(call *syntax.CallExpr, resolve func(*syntax.Word) (string, bool)) []string {
	if len(call.Args) < 2 {
		return nil
	}
	exe, ok := literalWord(call.Args[0])
	if !ok || !mountspec.IsContainerRuntime(exe) {
		return nil
	}
	words := make([]string, 0, len(call.Args)-1)
	for _, w := range call.Args[1:] {
		val, ok := resolve(w)
		if !ok {
			val = ""
		}
		words = append(words, val)
	}
	return mountspec.Sources(words)
}

// literalWord renders a word that is a single plain literal. Anything
// dynamic in the command position is not a runtime name we can trust.
func literalWord(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return "", false
	}
	return lit.Value, true
}

// textOnlyCommands are executables whose positional arguments are text to
// emit, never files to open. Mirror of normalize/argclass.go AllPositionalText.
var textOnlyCommands = map[string]bool{"echo": true, "printf": true}

// isTextOnlyCommand reports whether the call's command word is a text-only
// executable. Only a plain literal command word is recognised; anything
// dynamic keeps the conservative path and is materialized.
//
// echo/printf arguments are text, not file accesses — the normalizer
// classifies them the same way (argclass.go AllPositionalText), which is why
// `echo ~/.kube/config` passes. Materializing them made
// `echo $HOME/.kube/config` a protected-path hit while the tilde spelling was
// not (adversarial review, 2026-09-02). Redirects on the same call
// (`echo x >> ~/.ssh/authorized_keys`) are separate nodes and still
// materialize. `printf -v NAME …` is a BINDING rather than text — it is read
// by bindFromBuiltin before this gate is consulted (#3706).
func isTextOnlyCommand(call *syntax.CallExpr) bool {
	if len(call.Args) == 0 || len(call.Args[0].Parts) != 1 {
		return false
	}
	lit, ok := call.Args[0].Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	return textOnlyCommands[lit.Value]
}

// A pure-literal word has nothing to substitute, but if it is an interpreter
// one-liner its file-access literals are still invisible to the path check —
// `python3 -c "open('/Users/x/.ssh/id_rsa')"` never reached protected_paths.
// scopeEval.materialize surfaces those (interp_paths.go), and a materialized
// word may itself be a script whose file-access arguments are only concrete
// after the fold (`open('~/.ssh/id_rsa')` once $HOME or $P resolved).
//
// TestExpr's only concrete implementations (mvdan.cc/sh/v3/syntax) are
// *BinaryTest ("a == b"), *UnaryTest ("-f x"), *ParenTest ("( … )"), and
// *Word, so a single case on *syntax.TestClause cannot reach the words
// directly — scopeEval.materializeTest recurses, mirroring dequoteTestExpr in
// dequote.go.

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
		return appendParamExp(sb, part, syms)
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

// appendParamExp writes one parameter expansion into sb, returning false when
// it cannot be resolved exactly.
//
// The scalar shapes ($NAME, ${NAME}) fold to the symbol-table entry. Operator
// shapes fold only when the operator's operands are ALSO constant — see
// shellparse.FoldConstantParamOp — with two additions from #3706, both of them
// exact rather than heuristic:
//
//	${v:-word} on a BOUND v      the default branch is dead code; the value is v
//	${!v}                        indirection, when both hops are in the table
func appendParamExp(sb *strings.Builder, part *syntax.ParamExp, syms map[string]string) bool {
	if part.Param == nil || part.Param.Value == "" {
		return false
	}

	// ${!v} reads the variable NAMED by v. Deterministic when this command
	// binds both hops: `v=KUBECONFIG; KUBECONFIG=~/.kube/config; cat ${!v}`
	// opens the same file `cat $KUBECONFIG` does. Only the bare indirection is
	// folded — combined with any other operator it is a different shape
	// (${!prefix*} enumerates NAMES, not a value).
	if part.Excl {
		if part.Slice != nil || part.Repl != nil || part.Exp != nil ||
			part.Index != nil || part.NestedParam != nil || part.Length || part.Width {
			return false
		}
		target, bound, _ := lookupSym(syms, part.Param.Value)
		if !bound || !isShellIdentifier(target) {
			return false
		}
		val, bound, _ := lookupSym(syms, target)
		if !bound {
			return false
		}
		sb.WriteString(val)
		return true
	}

	val, bound, homeFold := lookupSym(syms, part.Param.Value)

	// The default/alternate/assign/error family, applied to a name this
	// command BINDS. Which branch the shell takes depends only on whether the
	// variable is set and non-empty — both of which are known here — so the
	// result is exact and the default word's own dynamism is irrelevant:
	// `export KUBECONFIG=~/.kube/config; cat ${KUBECONFIG:-$HOME/x}` reads
	// ~/.kube/config on every shell. The UNSET side of these operators is
	// deliberately left to shellparse.NormalizeUnsetParamExp (#3206), which
	// runs over the raw text before this layer and owns the "is the variable
	// set in the caller's environment" question; folding it here too would
	// give one shape two resolvers that can disagree.
	if part.Exp != nil && part.Slice == nil && part.Repl == nil &&
		part.Index == nil && part.NestedParam == nil && !part.Length && !part.Width {
		if folded, ok, handled := foldBoundDefaultOp(val, bound, part.Exp, syms); handled {
			if !ok {
				return false
			}
			sb.WriteString(folded)
			return true
		}
	}

	// Bail on array indices, length/width queries and the zsh nested-param
	// form — these select a DIFFERENT value than the scalar `syms[name]`
	// entry, so no fold here is correct for them.
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
		part.Length || part.Width {
		// A TRANSFORMING operator is refused on the $HOME fold: `~` stands in
		// for the home directory as a path prefix, but it is not the string
		// bash holds, so `${HOME:0:1}` would fold to "~" where bash yields
		// "/". The default-family operators above return the value whole and
		// are unaffected.
		if !bound || homeFold {
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
}

// foldBoundDefaultOp applies the default/assign/alternate/error operators to a
// variable whose set-ness and value are known.
//
// handled=false means "not one of these operators" — the caller falls through
// to FoldConstantParamOp. handled=true with ok=false means "this operator, but
// the variable is not bound here": refused on purpose, because the branch the
// shell takes then depends on the caller's environment.
func foldBoundDefaultOp(val string, bound bool, e *syntax.Expansion, syms map[string]string) (string, bool, bool) {
	if e == nil {
		return "", false, false
	}
	switch e.Op {
	// `:-` `:=` `:?` treat an EMPTY value as unset; `-` `=` `?` do not.
	case syntax.DefaultUnsetOrNull, syntax.AssignUnsetOrNull:
		if bound && val != "" {
			return val, true, true
		}
		if bound {
			// Bound but EMPTY: the shell takes the default branch, and it
			// takes it deterministically — this command cleared the variable
			// itself. Folding to the default is what stops
			// `V=<protected>; V=; cat ${V:-/tmp/x}` from resolving back to the
			// value V used to hold (#3743).
			def, ok := materializeWord(e.Word, syms)
			return def, ok, true
		}
		return "", false, true
	case syntax.ErrorUnsetOrNull:
		// `${V:?msg}` on an empty V ABORTS the shell, so the command never
		// reads anything. Refuse rather than fold to a value that is not read.
		if bound && val != "" {
			return val, true, true
		}
		return "", false, true
	case syntax.DefaultUnset, syntax.AssignUnset, syntax.ErrorUnset:
		if bound {
			return val, true, true
		}
		return "", false, true
	// The alternate operators yield the WORD when the variable is set — the
	// mirror image, and the shape `cat ${KUBECONFIG:+$KUBECONFIG}` uses.
	case syntax.AlternateUnsetOrNull:
		if !bound {
			return "", false, true
		}
		if val == "" {
			return "", true, true
		}
		alt, ok := materializeWord(e.Word, syms)
		return alt, ok, true
	case syntax.AlternateUnset:
		if !bound {
			return "", false, true
		}
		alt, ok := materializeWord(e.Word, syms)
		return alt, ok, true
	}
	return "", false, false
}

// lookupSym resolves a variable name against the symbol table, folding $HOME.
//
// $HOME is the one variable every shell binds before the command runs, and the
// one real scripts spell instead of `~`. Left unbound it made
// `P=$HOME/.ssh; cat $P/id_rsa` unmaterializable — the whole word was dropped
// and the split-concat protection (#1698) silently did not apply (measured
// 2026-09-02: exit 0 with protected_paths ["~/.ssh/**"]). It folds to `~`,
// which is what the engine's expandPath and the existing tests already treat as
// the home prefix. An explicit binding in the command wins over the fold.
//
// The third result flags that the value came from the fold rather than the
// table, so callers that TRANSFORM the value (slice, replace, trim) can refuse:
// `~` is a faithful stand-in for the home prefix, not for the literal string
// bash holds.
func lookupSym(syms map[string]string, name string) (string, bool, bool) {
	if val, ok := syms[name]; ok {
		return val, true, false
	}
	if name == "HOME" {
		return "~", true, true
	}
	return "", false, false
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
