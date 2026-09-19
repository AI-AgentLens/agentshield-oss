package shellparse

import (
	"path"
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// QuotedProgramArgPlaceholder is the text substituted for a redacted
// wholly-quoted program argument. Opaque and single-token for the same
// reason as LoopItemPlaceholder and HeredocBodyPlaceholder: it must survive
// re-parsing as shell and match no shipped rule pattern.
const QuotedProgramArgPlaceholder = "QUOTEDPROGRAMARG"

// quotedProgramArgSinks are executables whose arguments are parsed as their
// OWN domain-specific program syntax (an awk/sed script, a Perl one-liner, a
// jq filter) and never handed to a shell for re-interpretation. A word that
// is ENTIRELY wrapped in one shell quote, passed to one of these, can never
// trigger a zsh glob qualifier: filename generation only applies to unquoted
// words on the INVOKING shell's own command line, and none of these programs
// re-parses its argument as shell source. Deliberately excludes bash/sh/zsh/
// dash/ksh/eval/source/. and any interpreter that can itself execute a shell
// command from a string (python3 -c, node -e, ruby -e) — those are carriers,
// not data/DSL sinks (see the shell-source-carrier class this codebase
// already tracks for wrapper/interpreter arguments), and a quoted word
// handed to a carrier is not proven inert: a nested `zsh -c '…'` re-parses
// its argument as zsh source, where the same glob qualifier is live again.
var quotedProgramArgSinks = map[string]bool{
	"awk": true, "gawk": true, "mawk": true, "nawk": true,
	"sed": true, "gsed": true,
	"perl": true,
	"jq":   true,
}

// QuotedProgramArgs finds words in command that are ENTIRELY a single- or
// double-quoted shell literal (the whole word, no unquoted characters
// concatenated before or after it) passed as an argument to one of
// quotedProgramArgSinks, together with a rendering of command in which those
// words have been replaced by QuotedProgramArgPlaceholder.
//
// # Why this exists
//
// ts-block-zsh-glob-qualifier-exec keys on the TEXT `(e<punct>…<punct>)` /
// `(+ident)` — the syntax zsh uses to attach executable code to a glob
// pattern (`*(e:CMD:)`). That syntax is only live when the containing word is
// UNQUOTED on the invoking shell's command line — zsh never performs
// filename generation on a word that is entirely inside a shell quote, so
// the identical byte sequence inside an awk program string,
//
//	awk '{if(e!=""){print e}}'
//
// is inert: awk parses `(e!="")` as its own C-like conditional syntax, and
// the enclosing shell never sees an unquoted glob to expand. See #3631.
//
// # What is deliberately NOT covered
//
// The exclusion requires the WHOLE word to be one shell quote — a word that
// mixes quoted and unquoted segments (`*(e:'CMD':)`, the real attack shape:
// the outer `*(e:…:)` glob syntax is unquoted, only the CMD payload inside it
// is quoted) is never redacted, because isWhollyQuoted rejects a word with
// more than one Part. PositionExcluded's own attribution/subtraction check
// additionally requires the rule's pattern to still match the item text in
// isolation and to stop matching once it is removed, so this function
// widening its allowlist can only ever narrow a BLOCK, never invent one.
func QuotedProgramArgs(command string) (items []string, redacted string) {
	if !strings.ContainsAny(command, "'\"") {
		return nil, ""
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, ""
	}

	var spans []byteSpan
	syntax.Walk(file, func(node syntax.Node) bool {
		ce, ok := node.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}
		exe := path.Base(NormalizeExecName(staticWord(ce.Args[0])))
		if !quotedProgramArgSinks[exe] {
			return true
		}
		for _, w := range ce.Args[1:] {
			if !isWhollyQuoted(w) {
				continue
			}
			s, e := int(w.Pos().Offset()), int(w.End().Offset())
			if s < 0 || e > len(command) || s >= e {
				continue
			}
			spans = append(spans, byteSpan{s, e})
		}
		return true
	})
	if len(spans) == 0 {
		return nil, ""
	}

	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last {
			continue // overlapping span — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteString(QuotedProgramArgPlaceholder)
		last = s.end
		items = append(items, command[s.start:s.end])
	}
	sb.WriteString(command[last:])

	out := sb.String()
	if out == command {
		return nil, ""
	}
	return items, out
}

// isWhollyQuoted reports whether w is exactly one shell quote — a single
// SglQuoted or DblQuoted part covering the whole word, with no unquoted
// characters concatenated before or after it (`'x'y` and `x'y'` both fail,
// since a partially-quoted word can still carry an unquoted glob qualifier
// alongside a quoted payload — see the real attack shape above).
func isWhollyQuoted(w *syntax.Word) bool {
	if w == nil || len(w.Parts) != 1 {
		return false
	}
	switch w.Parts[0].(type) {
	case *syntax.SglQuoted, *syntax.DblQuoted:
		return true
	default:
		return false
	}
}
