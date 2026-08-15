package shellparse

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"mvdan.cc/sh/v3/syntax"
)

// DequoteCommand returns a reconstruction of command with shell quote/escape
// artifacts removed from every purely-static word (no $VAR / $(...) / backtick
// / arithmetic content), while leaving dynamic words, executable-position
// aliasing (handled separately by NormalizeExecName) and non-CallExpr text
// untouched. It mirrors the quote removal a real shell performs on argument
// words before a command runs, so surfaces that compare raw command text
// directly — like RegexAnalyzer's command_regex matching, which runs before
// any AST-aware normalization — can also be checked against the
// post-quote-removal spelling.
//
// Without this, a quote-spliced path (`~/.ss'h'/id_r'sa'`) resolves to the
// real `~/.ssh/id_rsa` at runtime but evades any regex written against the
// unquoted spelling (issue #2854, follow-up to #2813/#2814 which fixed only
// the structural protected_paths/args_any glob-matching surfaces via
// pathnorm.StripShellQuotes).
//
// Returns "" (a no-op sentinel) when the command has no quote/backslash
// characters at all, when nothing was actually rewritten, or when parsing
// fails — callers should fall back to the original raw command in all three
// cases.
func DequoteCommand(command string) string {
	if !strings.ContainsAny(command, `'"\`) {
		return ""
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return ""
	}

	changed := false
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			// Plain command arguments (`cat foo`) and leading prefix
			// assignments (`FOO=BAR'BAZ' cmd`).
			for _, w := range n.Args {
				if dequoteWordInPlace(w) {
					changed = true
				}
			}
			for _, a := range n.Assigns {
				if a.Value != nil && dequoteWordInPlace(a.Value) {
					changed = true
				}
			}
		case *syntax.DeclClause:
			// export/declare/local/readonly/typeset — bash's grammar parses
			// these as a distinct node from CallExpr, so `export
			// AGENTSHIELD_BYPA'S'S=1` was previously invisible to this walk
			// entirely (issue #2984 follow-up: the enterprise self-protection
			// layer's sp-block-bypass-env rule matches exactly this shape).
			for _, a := range n.Args {
				if a.Value != nil && dequoteWordInPlace(a.Value) {
					changed = true
				}
			}
		case *syntax.Redirect:
			// Redirect targets (`> file`, `>> file`, `< file`) are a sibling
			// field on the enclosing statement, not a CallExpr arg — a
			// spliced output path (`> ~/.agentshield/poli'c'y.yaml`) was
			// previously left untouched.
			if n.Word != nil && dequoteWordInPlace(n.Word) {
				changed = true
			}
		case *syntax.TestClause:
			// `[[ ... ]]` conditions (`[[ -f \/dev/shm/x ]] && source
			// /dev/shm/x`) parse to their own node, not a CallExpr -- a
			// spliced word inside the test expression was previously
			// invisible to this walk entirely, the same gap CallExpr and
			// DeclClause each closed for their own shape (issue #3322,
			// follow-up to #3209/#3208).
			if dequoteTestExpr(n.X) {
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

// dequoteWordInPlace rewrites w's Parts in place to a single Lit with quote
// artifacts removed, IF every part is statically resolvable (Lit, SglQuoted,
// or DblQuoted containing only Lit parts). A word containing any dynamic
// expansion (ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob, or a
// DblQuoted wrapping one of those) is left completely untouched — its
// runtime value can't be resolved statically, and partially dequoting would
// corrupt the expansion syntax. Reports whether it rewrote the word.
//
// Deliberately scoped to words with 2+ parts — a genuine inline splice
// (`~/.ss'h'/id_r'sa'` parses as Lit+SglQuoted+Lit+SglQuoted). A word that is
// a single whole-argument quote (`-d '{"json":...}'`, `-m "commit message"`,
// `echo "text"`) is left untouched: many existing command_regex_exclude
// patterns key off "a quote character immediately follows this flag" as
// their doc-text/flag-value heuristic (e.g. sec-block-etc-shadow's
// `-d\s+["']` exclude, ts-block-proc-kcore-redirect's `^(echo|printf|cat)\s+['"]`
// exclude) — stripping that quote would silently defeat those exclusions and
// turn routine curl/echo/git-commit text into new false positives. Splicing
// requires 2+ parts by definition, so this scoping loses no exploit coverage.
func dequoteWordInPlace(w *syntax.Word) bool {
	// ANSI-C quoting ($'...') and locale-translated quoting ($"...") are both
	// escape-DECODING mechanisms, never a "quoted flag value" convention —
	// unlike '...'/"..." they're never what a command_regex_exclude's "quote
	// character follows this flag" heuristic means to detect (see the func
	// doc comment above for that heuristic). So a lone single-part $'...' or
	// $"..." word (the common "$'\x72\x6d' -rf /" / "$\"rm\" -rf /" shapes)
	// must still be decoded even though it fails the 2+-parts
	// splice-detection guard below; only genuine whole-argument '...'/"..."
	// quoting stays scoped to 2+ parts.
	if len(w.Parts) < 2 && !hasDollarQuoted(w) {
		// A single bare Lit can still carry an obfuscating backslash escape
		// with no quote/expansion boundary at all ("r\m" — see
		// FoldObfuscatingBackslashes's doc comment for why alphanumeric
		// escapes are always safe to fold on a whole word). mvdan/sh keeps
		// such an escape inside the Lit's raw Value rather than splitting it
		// into a separate part, so this is a distinct gap from the splice
		// case above, not something the 2+-parts check was ever meant to
		// catch (issue #3208).
		return foldLoneLitEscapes(w)
	}
	var b strings.Builder
	hadQuotes := false
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// A top-level Lit can still carry an unquoted backslash escape
			// (`\d` → `d`) — mvdan/sh's parser doesn't resolve those either
			// (see NormalizeExecName's doc comment), so route through the
			// same primitive the structural fix (#2813/#2814) uses for
			// identical quote/escape semantics everywhere.
			v := pathnorm.StripShellQuotes(p.Value)
			if v != p.Value {
				hadQuotes = true
			}
			b.WriteString(v)
		case *syntax.SglQuoted:
			hadQuotes = true
			if p.Dollar {
				// $'...' ANSI-C quoting: decode escape sequences (\xHH,
				// \NNN octal, \uHHHH/\UHHHHHHHH, \n\t\r...) into the actual
				// runtime bytes, instead of writing the still-encoded raw
				// text. Without this, an attacker splitting an encoded
				// executable/path across adjacent $'...' fragments
				// ($'\x72'$'\x6d' instead of a single $'\x72\x6d') evades
				// both the ts-block-ansic-{hex,octal,unicode}-escape regex
				// rules (which only match 2+ escapes within ONE span) and
				// every other rule keyed on the decoded literal text, since
				// the merged-but-undecoded form here never actually
				// resolves to "rm" or "credentials" (issue #3099).
				decoded, _ := pathnorm.DecodeANSICEscapes(p.Value)
				b.WriteString(decoded)
			} else {
				b.WriteString(p.Value)
			}
		case *syntax.DblQuoted:
			hadQuotes = true
			for _, inner := range p.Parts {
				lit, ok := inner.(*syntax.Lit)
				if !ok {
					return false // dynamic content inside double quotes — leave whole word alone
				}
				b.WriteString(lit.Value)
			}
		default:
			return false // ParamExp/CmdSubst/ArithmExp/ProcSubst/ExtGlob — dynamic, leave alone
		}
	}
	if !hadQuotes {
		return false // nothing to strip; avoid needless AST mutation
	}
	w.Parts = []syntax.WordPart{&syntax.Lit{ValuePos: w.Pos(), ValueEnd: w.End(), Value: b.String()}}
	return true
}

// dequoteTestExpr recurses through a [[ ... ]] test expression to reach its
// Word operands, the same shape CallExpr's Args loop reaches CallExpr's word
// arguments. TestExpr's only concrete implementations (mvdan.cc/sh/v3/syntax)
// are *BinaryTest ("a == b"), *UnaryTest ("-f x"), *ParenTest ("( ... )"), and
// *Word (a bare word used as a boolean test) — the first three are recursive
// wrappers around further TestExpr values, not leaves, so a single case on
// *syntax.TestClause can't reach the words directly; this walks down to them.
func dequoteTestExpr(expr syntax.TestExpr) bool {
	switch e := expr.(type) {
	case *syntax.Word:
		return dequoteWordInPlace(e)
	case *syntax.UnaryTest:
		return dequoteTestExpr(e.X)
	case *syntax.BinaryTest:
		// Evaluate both sides unconditionally — this is a mutation walk, not
		// a boolean short-circuit, and both operands can independently carry
		// a splice.
		left := dequoteTestExpr(e.X)
		right := dequoteTestExpr(e.Y)
		return left || right
	case *syntax.ParenTest:
		return dequoteTestExpr(e.X)
	default:
		return false
	}
}

// hasDollarQuoted reports whether w contains at least one ANSI-C ($'...') or
// locale-translated ($"...") quoted part, both of which — unlike plain
// '...'/"..." — are always an escape-encoding mechanism rather than a
// "quoted flag value" convention, so they must be decoded even as a lone
// single-part word.
func hasDollarQuoted(w *syntax.Word) bool {
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.SglQuoted:
			if p.Dollar {
				return true
			}
		case *syntax.DblQuoted:
			if p.Dollar {
				return true
			}
		}
	}
	return false
}

// foldLoneLitEscapes handles the one shape dequoteWordInPlace's main splice
// logic never sees: a word with no quote/expansion boundary at all, just a
// bare Lit carrying an obfuscating backslash escape in its raw text ("r\m").
// Scoped to a single Lit part specifically — any other single-part shape
// (SglQuoted, DblQuoted, ParamExp, ...) either doesn't need this fold or is
// already reachable through hasDollarQuoted above.
func foldLoneLitEscapes(w *syntax.Word) bool {
	if len(w.Parts) != 1 {
		return false
	}
	lit, ok := w.Parts[0].(*syntax.Lit)
	if !ok {
		return false
	}
	folded, changed := pathnorm.FoldObfuscatingBackslashes(lit.Value)
	if !changed {
		return false
	}
	w.Parts = []syntax.WordPart{&syntax.Lit{ValuePos: w.Pos(), ValueEnd: w.End(), Value: folded}}
	return true
}
