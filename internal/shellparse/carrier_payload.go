package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
)

// payloadValue resolves the shell source a carrier hands to a shell, given the
// raw text of the argv word that carried it.
//
// Bash performs quote removal on a carrier's argv word BEFORE the carrier ever
// sees it, so the payload is that word's runtime VALUE. `unwrapOuterQuotes`
// approximates that by stripping one outer quote pair, which is only equal to
// quote removal when the word happens to be a single whole quoted span — the
// shape #3050 measured and fixed. When the word boundaries inside the payload
// are hidden by escaping or per-word quoting instead, the approximation breaks
// and the payload survives reconstruction verbatim:
//
//	bash -c rm\ -rf\ /        the whole payload is ONE Lit, escapes intact
//	bash -c rm' '-rf' '/      Lit + SglQuoted + Lit + SglQuoted + Lit
//	bash -c 'rm'\ '-rf'\ '/'  first and last chars are quotes of DIFFERENT spans
//
// Re-parsed, each of those is one word — an executable literally named
// "rm -rf /" — so every structural and semantic check keyed on
// Executable == "rm" misses. Measured over the BLOCKing corpus the escaped-space
// form leaked 75.4% against a 1.0% control, on all eight carrier surfaces at
// once, because all eight reconstruct through this one primitive (#3241).
//
// Every one of those spellings really does execute — verified against bash, not
// inferred from the parse.
//
// The resolver is deliberately narrow: it answers only for a word it can resolve
// STATICALLY and in full. Anything else — a dynamic part whose value is not
// knowable here, or text that does not parse as exactly one word — falls back to
// unwrapOuterQuotes, so the behaviour this replaces is a strict subset of the
// behaviour it adds.
func payloadValue(raw string) string {
	if v, ok := resolveWordValue(raw); ok {
		return v
	}
	return unwrapOuterQuotes(raw)
}

// resolveWordValue returns the runtime value of raw when raw is exactly one
// statically-resolvable shell word, and reports whether it resolved.
//
// NOT reused from dequoteWordInPlace, and the difference is the point.
// dequoteWordInPlace skips a single whole-argument quote on purpose: it rewrites
// the command text that command_regex rules are matched against, where many
// `command_regex_exclude` patterns key off "a quote character immediately
// follows this flag" as their doc-text heuristic, so stripping that quote would
// silently defeat them (see its doc comment). Here the opposite is required —
// removing the whole-argument quote is exactly what the carrier's own shell
// does, and is already today's behaviour via unwrapOuterQuotes. Two callers,
// two correct answers; sharing one would break one of them.
func resolveWordValue(raw string) (string, bool) {
	// Fast path. With no quote or escape character there is nothing for quote
	// removal to do, and the parse would be pure cost on the common case.
	if !strings.ContainsAny(raw, `'"\`) {
		return "", false
	}
	// A payload is captured from a single argv operand, so it must parse as a
	// lone word. Requiring that — rather than taking the first word of whatever
	// parses — is what keeps a multi-word or operator-bearing string out: those
	// are already shell source in their own right and reconstruct correctly
	// without help.
	word, ok := parseLoneWord(raw)
	if !ok {
		return "", false
	}
	var b strings.Builder
	for _, part := range word.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			// Unquoted context: a backslash here IS an escape, so removing it
			// is quote removal, not mangling.
			b.WriteString(pathnorm.StripShellQuotes(p.Value))
		case *syntax.SglQuoted:
			if p.Dollar {
				decoded, _ := pathnorm.DecodeANSICEscapes(p.Value)
				b.WriteString(decoded)
				continue
			}
			// Single quotes are literal to the shell — the content is the
			// value, escapes and all.
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, inner := range p.Parts {
				lit, isLit := inner.(*syntax.Lit)
				if !isLit {
					// A ParamExp/CmdSubst inside the quotes: the word's value
					// is not knowable statically.
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			// ParamExp, CmdSubst, ArithmExp, ProcSubst, ExtGlob.
			return "", false
		}
	}
	return b.String(), true
}

// parseLoneWord parses raw and returns the single word it consists of.
//
// Rejects anything with more structure than one bare word — a second word, a
// redirect, an assignment, an operator, a compound command — because those are
// not the shape this resolver models. `'rm -rf /'` IS one word (a quoted span);
// `rm -rf /` is three and needs no resolution.
func parseLoneWord(raw string) (*syntax.Word, bool) {
	parser := syntax.NewParser(syntax.KeepComments(false))
	file, err := parser.Parse(strings.NewReader(raw), "")
	if err != nil || file == nil || len(file.Stmts) != 1 {
		return nil, false
	}
	stmt := file.Stmts[0]
	if len(stmt.Redirs) > 0 || stmt.Background || stmt.Negated {
		return nil, false
	}
	call, isCall := stmt.Cmd.(*syntax.CallExpr)
	if !isCall || len(call.Assigns) > 0 || len(call.Args) != 1 {
		return nil, false
	}
	return call.Args[0], true
}
