package shellparse

import (
	"sort"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/pathnorm"
	"mvdan.cc/sh/v3/syntax"
)

// ANSICNULReading returns command with every $'...' body cut at the first
// escape that bash decodes to byte 0, or "" when no body has one. A command
// the parser rejects is cut by text instead
// (pathnorm.CutDollarQuotedSpansAtNUL).
//
// bash builds the decoded body as a C string, so nothing from that escape to
// the closing quote reaches the word: r$'\0'm runs rm, $'rm\0zz' runs rm
// (#4540). The rewrite writes that directly (the first keeps an empty $'...'
// span between r and m, the second becomes $'rm'), so the text says what
// bash runs and no later layer has to know about the NUL. Every other byte is
// kept as written: the cuts are spliced out of the original text, not
// re-printed. pathnorm.ANSICNULIndex has the escape list.
//
// The caller (policy.Engine.EvaluateANSICNUL) evaluates this text as a SECOND
// reading and keeps it only when strictly more restrictive, the construction
// of #3991, #4194, #4289 and #4387. It must never replace the as-written
// text: zsh keeps the NUL and runs what follows it in eval, trap, alias and
// source, so for those the dropped text is live.
//
// At the top level only spans the parser sees as $'...' are cut. Text an
// executor re-parses is cut by text (#4542): a heredoc body, and the content
// of a quoted argument (`bash -c "...$'\0'..."`, `eval '...'`), where the
// span only becomes a $'...' when the carrier parses it. That can cut a span
// bash would leave alone in a quoted argument nobody runs; the reading only
// ever raises a decision, so the cost is a stricter reading of that text.
func ANSICNULReading(command string) string {
	if !strings.Contains(command, "$'") || !mayHaveNULEscape(command) {
		return ""
	}
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		// Every layer falls back to text when the parse fails, so the
		// reading does too.
		return pathnorm.CutDollarQuotedSpansAtNUL(command)
	}
	type cut struct {
		start, end int
		repl       string
	}
	var cuts []cut
	// textCut cuts the $'...' spans found by text inside command[a:b], the
	// source an executor re-parses (#4542): a heredoc body, or the payload of
	// a quoted argument such as bash -c '...'. The tree has no $'...' node
	// there, so the walk cannot see them.
	textCut := func(a, b int) {
		if a < 0 || b > len(command) || a >= b {
			return
		}
		if r := pathnorm.CutDollarQuotedSpansAtNUL(command[a:b]); r != "" {
			cuts = append(cuts, cut{a, b, r})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.Redirect:
			if n.Hdoc != nil {
				textCut(int(n.Hdoc.Pos().Offset()), int(n.Hdoc.End().Offset()))
			}
			return true
		case *syntax.CallExpr:
			if !isNULCarrierCall(n) {
				return true
			}
			// A shell, eval or trap re-parses its quoted arguments as source.
			for _, w := range n.Args[1:] {
				for _, part := range w.Parts {
					switch q := part.(type) {
					case *syntax.DblQuoted:
						a := int(q.Left.Offset()) + 1
						if q.Dollar {
							a++
						}
						textCut(a, int(q.Right.Offset()))
					case *syntax.SglQuoted:
						if !q.Dollar {
							textCut(int(q.Left.Offset())+1, int(q.Right.Offset()))
						}
					}
				}
			}
			return true
		}
		q, ok := node.(*syntax.SglQuoted)
		if !ok {
			return true
		}
		if !q.Dollar {
			return true
		}
		at := pathnorm.ANSICNULIndex(q.Value)
		if at < 0 {
			return true
		}
		body, end := int(q.Left.Offset())+2, int(q.Right.Offset())
		// Cut only where the tree maps onto the text byte for byte. A span
		// that does not is left as written: a missed cut is a coverage gap
		// in a reading that can only raise, never a relaxation.
		if body < 2 || end > len(command) || end-body != len(q.Value) ||
			command[body-2:body] != "$'" || command[body:end] != q.Value {
			return true
		}
		cuts = append(cuts, cut{body + at, end, ""})
		return true
	})
	if len(cuts) == 0 {
		return ""
	}
	// A text cut over a heredoc body or quoted payload can contain spans the
	// walk also cut (a $'...' inside a substitution there). Keep the outer
	// range; the text cut already covers the inner one.
	sort.Slice(cuts, func(i, j int) bool {
		if cuts[i].start != cuts[j].start {
			return cuts[i].start < cuts[j].start
		}
		return cuts[i].end > cuts[j].end
	})
	kept := cuts[:0]
	for _, c := range cuts {
		if len(kept) > 0 && c.start < kept[len(kept)-1].end {
			continue
		}
		kept = append(kept, c)
	}
	// Splice from the end so earlier offsets stay valid.
	out := command
	for i := len(kept) - 1; i >= 0; i-- {
		c := kept[i]
		out = out[:c.start] + c.repl + out[c.end:]
	}
	return out
}

// mayHaveNULEscape is the cheap gate in front of the parse: every escape
// pathnorm.ANSICNULIndex reports starts with one of these byte pairs, so a
// command with none of them has nothing to cut. `$'\n'` and `$'\t'`, the
// common spellings in real traffic, pay one scan and no parse.
func mayHaveNULEscape(command string) bool {
	for i := strings.IndexByte(command, '\\'); i >= 0 && i+1 < len(command); {
		switch command[i+1] {
		case '0', '4', 'x', 'u', 'U', 'c':
			return true
		}
		j := strings.IndexByte(command[i+1:], '\\')
		if j < 0 {
			return false
		}
		i += 1 + j
	}
	return false
}

// isNULCarrierCall reports a call whose quoted arguments an executor parses
// as shell source: a shell interpreter (also behind sudo, env and the like,
// which keep the shell as a later word), eval, or trap.
func isNULCarrierCall(call *syntax.CallExpr) bool {
	for _, w := range call.Args {
		name, ok := literalExecWord(w)
		if !ok {
			continue
		}
		if name == "eval" || name == "trap" || IsShellInterpreter(name) {
			return true
		}
	}
	return false
}
