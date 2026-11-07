package shellparse

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// StripStderrRedirects returns command with every redirect that leaves the
// command's STDOUT where it was removed, and every `|&` rewritten to `|`, so
// a rule written for pipe adjacency (`cat <history> | grep ...`) sees the
// command the way the data flows (#4610). Concretely it removes:
//
//   - a stderr redirect to a file: `2>/dev/null`, `2>>log`, `2>|log`;
//   - an fd duplication: `2>&1`, `>&2`, `1>&2`, `<&3`, `>&-`.
//
// It does NOT remove `&>`/`&>>` or a plain `>file`: those move stdout, so the
// pipe downstream no longer receives the data and the adjacency would be a
// reading the shell does not perform.
//
// Every other byte stays exactly as written (separators included), the same
// way FoldLeadingExecWord edits only the bytes it folds. Returns "" when the
// command has nothing to strip or does not parse.
//
// This is an ADDITIONAL reading for restricting rules, never a replacement:
// the caller keeps matching the raw text and every existing form, and an
// ALLOW rule never sees this one (a redirect removed must not vouch for a
// command, #4088).
func StripStderrRedirects(command string) string {
	if !strings.Contains(command, ">") && !strings.Contains(command, "<&") && !strings.Contains(command, "|&") {
		return ""
	}
	file := parseBashFile(command)
	if file == nil {
		return ""
	}
	type span struct {
		start, end int
		repl       string
	}
	var spans []span
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Stmt:
			for _, r := range x.Redirs {
				if stderrOnlyRedirect(r) {
					spans = append(spans, span{int(r.Pos().Offset()), int(r.End().Offset()), ""})
				}
			}
		case *syntax.BinaryCmd:
			if x.Op == syntax.PipeAll {
				o := int(x.OpPos.Offset())
				spans = append(spans, span{o, o + 2, "|"})
			}
		}
		return true
	})
	if len(spans) == 0 {
		return ""
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var b strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last || s.end > len(command) || s.start > s.end {
			continue // nested inside a span already removed
		}
		start, end := s.start, s.end
		if s.repl == "" {
			// Take the blank run on one side with the redirect, so
			// `x 2>/dev/null | y` reads `x | y`, not `x  | y`.
			if start > last && isBlank(command[start-1]) {
				for start > last && isBlank(command[start-1]) {
					start--
				}
			} else {
				for end < len(command) && isBlank(command[end]) {
					end++
				}
			}
		}
		b.WriteString(command[last:start])
		b.WriteString(s.repl)
		last = end
	}
	b.WriteString(command[last:])
	out := b.String()
	if out == command {
		return ""
	}
	return out
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// stderrOnlyRedirect reports whether r leaves stdout where it was: an fd
// duplication of any descriptor, or a write/append/clobber of fd 2 to a file.
func stderrOnlyRedirect(r *syntax.Redirect) bool {
	switch r.Op {
	case syntax.DplOut, syntax.DplIn:
		return true
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
		return r.N != nil && r.N.Value == "2"
	}
	return false
}
