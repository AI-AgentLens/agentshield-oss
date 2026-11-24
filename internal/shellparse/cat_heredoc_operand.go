package shellparse

import (
	"path"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// CatTeeReadsBesidesHeredoc reports whether command contains a `cat` or
// `tee` statement that redirects a heredoc or here-string (<<, <<-, <<<) and
// ALSO reads something else, so the heredoc body is not (or not only) what
// the statement handles. The in_heredoc label's claim, "the body is data
// written to a file", is false for such a statement, and the caller withdraws
// the label. Two shapes:
//
//  1. `cat` with a file operand (#3964). GNU/BSD cat reads stdin only when
//     invoked with no operand or an explicit `-`; any other operand makes cat
//     read that FILE and ignore stdin entirely, so the heredoc/here-string
//     bash still sets up is inert filler cat never consumes — `cat
//     ~/.ssh/id_rsa <<< x` reads the key, not x. `tee` has no such shape:
//     its operands are extra destinations, not a source.
//
//  2. An input redirect onto stdin from a file or another descriptor, on
//     `cat` or `tee` (#4965): `< FILE`, `0< FILE`, `<> FILE`, `<&N`. In bash
//     (and zsh with NO_MULTIOS, and sh) the LAST input redirect on fd 0 wins,
//     so `tee out <<< x < /etc/shadow` copies /etc/shadow, not x. zsh with
//     its default MULTIOS option reads EVERY input redirect on fd 0 in turn,
//     so the file is read in either order there — `tee out < FILE <<< x`
//     copies FILE then x. zsh is the shell agents use on macOS, so the order
//     of the two redirects does not matter here. Measured on bash 3.2 and
//     5.3, zsh 5.9 with and without MULTIOS, and /bin/sh (PR for #4965).
//
//     Not an input redirect onto stdin, and so left alone: an output
//     redirect, a redirect onto another descriptor (`3< FILE` opens FILE but
//     cat/tee never read fd 3), a process substitution used as an operand,
//     a second here-string or heredoc (also text), closing stdin (`<&-`,
//     reads nothing) and duplicating stdin onto itself (`<&0`, which names
//     no content in the statement). A `<` inside the quoted body is text,
//     not a redirect, and the parser already sees it that way.
//
// A dynamic operand (`cat "$F" <<EOF`) or descriptor (`<&$fd`) cannot be
// proven to be `-` / `0`, so it is conservatively treated as reading
// something else — the caller withdraws the inertness label rather than
// assume the read is safe. A `--` end-of-options marker followed by a
// dash-prefixed literal filename (`cat -- -x <<EOF`) is a known residual:
// the prefix check below reads the guarded operand as a flag and misses it,
// same as before #3964.
//
// Withdrawing the label can only raise a decision (the rule's own match is
// still required), never lower one.
func CatTeeReadsBesidesHeredoc(command string) bool {
	if !strings.Contains(command, "<<") {
		return false
	}
	file, err := ParseText(command, syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
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

		hasHeredoc, stdinFromElsewhere := false, false
		for _, r := range st.Redirs {
			if r == nil {
				continue
			}
			switch r.Op {
			case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
				hasHeredoc = true
			default:
				if redirectFeedsStdinFromElsewhere(r) {
					stdinFromElsewhere = true
				}
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
		if exe == "" {
			return true
		}
		switch path.Base(NormalizeExecName(exe)) {
		case "cat":
			if stdinFromElsewhere || catHasFileOperand(ce.Args[offset+1:]) {
				found = true
			}
		case "tee":
			if stdinFromElsewhere {
				found = true
			}
		}
		return !found
	})
	return found
}

// catHasFileOperand reports whether cat's arguments name something other
// than stdin: any word that is not `-` and not a flag. A dynamic word is
// counted, since it cannot be proven to be `-`.
func catHasFileOperand(args []*syntax.Word) bool {
	for _, arg := range args {
		w := staticWord(arg)
		if w == "-" || (w != "" && strings.HasPrefix(w, "-")) {
			continue // stdin marker, or a boolean cat flag (-A, -b, -e, -n, ...)
		}
		return true
	}
	return false
}

// redirectFeedsStdinFromElsewhere reports whether r points the command's
// stdin (fd 0, the default for these operators) at a file (`<`, `<>`) or at
// another descriptor (`<&N`). Closing stdin (`<&-`) and duplicating it onto
// itself (`<&0`) bring in no content named in the statement and do not count.
func redirectFeedsStdinFromElsewhere(r *syntax.Redirect) bool {
	if r.N != nil {
		// `3< FILE` opens FILE on fd 3, which cat/tee never read. A named
		// descriptor (`{fd}< FILE`) is never fd 0 either.
		if n, err := strconv.Atoi(r.N.Value); err != nil || n != 0 {
			return false
		}
	}
	switch r.Op {
	case syntax.RdrIn, syntax.RdrInOut:
		return true
	case syntax.DplIn:
		w := staticWord(r.Word)
		return w != "-" && w != "0" // "" (dynamic) counts: cannot be proven to be either
	}
	return false
}
