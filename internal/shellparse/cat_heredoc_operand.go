package shellparse

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// CatReadsFileOperandInsteadOfHeredoc reports whether command contains a
// `cat` statement that redirects a heredoc or here-string (<<, <<-, <<<)
// while also naming a non-flag operand to read. GNU/BSD cat reads stdin
// only when invoked with no operand or an explicit `-`; any other operand
// makes cat read that FILE and ignore stdin entirely, so the heredoc/
// here-string bash still sets up is inert filler cat never consumes
// (#3964) — `cat ~/.ssh/id_rsa <<< x` reads the key, not x.
//
// `tee` is deliberately NOT covered here: unlike cat, tee always reads
// stdin regardless of its operands — they name additional destinations to
// ALSO write to, not an alternative source — so a `tee FILE <<EOF` heredoc
// genuinely feeds tee and the InHeredoc label is correct on it as-is.
//
// A dynamic operand (`cat "$F" <<EOF`) cannot be proven to be `-`, so it is
// conservatively treated as a file operand — the caller withdraws the
// inertness label rather than assume the read is safe. A `--`
// end-of-options marker followed by a dash-prefixed literal filename
// (`cat -- -x <<EOF`) is a known residual: the prefix check below reads
// the guarded operand as a flag and misses it, same as before this fix.
func CatReadsFileOperandInsteadOfHeredoc(command string) bool {
	if !strings.Contains(command, "<<") {
		return false
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return false
	}

	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		st, ok := node.(*syntax.Stmt)
		if !ok || len(st.Redirs) == 0 {
			return true
		}
		ce, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}

		hasHeredoc := false
		for _, r := range st.Redirs {
			if r == nil {
				continue
			}
			switch r.Op {
			case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
				hasHeredoc = true
			}
		}
		if !hasHeredoc {
			return true
		}

		words := make([]string, len(ce.Args))
		for i, a := range ce.Args {
			words[i] = WordToString(a)
		}
		stripped := StripExecWrappers(words)
		if len(stripped) == 0 {
			return true
		}
		offset := len(words) - len(stripped)
		exe := staticWord(ce.Args[offset])
		if exe == "" || path.Base(NormalizeExecName(exe)) != "cat" {
			return true
		}

		for _, arg := range ce.Args[offset+1:] {
			w := staticWord(arg)
			if w == "-" || (w != "" && strings.HasPrefix(w, "-")) {
				continue // stdin marker, or a boolean cat flag (-A, -b, -e, -n, ...)
			}
			// Either a literal file operand, or a dynamic word that cannot
			// be proven to be "-" — either way cat may not read the heredoc.
			found = true
			return false
		}
		return true
	})
	return found
}
