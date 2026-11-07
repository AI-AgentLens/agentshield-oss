package shellparse

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// HomeTildeReading returns command with two tilde prefixes written the way
// the shell expands them (#4596), or "" when there is nothing to rewrite or
// the command does not parse:
//
//   - `~<login>` (the prefix naming the account login) becomes loginHome.
//     The caller passes "~" when that account's home is $HOME, so the packs'
//     `~/` spelling and protected_paths both see the path they are written
//     against.
//   - `~+` becomes cwd ($PWD), only when cwd is absolute.
//
// bash and zsh both expand a tilde prefix only at the start of an unquoted
// word (and after `=` in an assignment, which the parser gives as the value's
// own word), and only when no character of the prefix is quoted. So the
// rewrite applies to a word whose first part is an unquoted literal starting
// with `~`, and the prefix is the literal up to its first `/`; when the
// literal has no `/` the prefix must be the whole word. Heredoc bodies are
// never rewritten: the shell does not tilde-expand them.
//
// `~-` ($OLDPWD) is not resolvable statically and is left as written.
//
// This is an ADDITIONAL reading: the caller keeps the as-written evaluation
// and takes this one only when strictly more restrictive.
func HomeTildeReading(command, login, loginHome, cwd string) string {
	if !strings.Contains(command, "~") {
		return ""
	}
	if login == "" && cwd == "" {
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
	visitWord := func(w *syntax.Word) {
		if w == nil || len(w.Parts) == 0 {
			return
		}
		lit, ok := w.Parts[0].(*syntax.Lit)
		if !ok || !strings.HasPrefix(lit.Value, "~") {
			return
		}
		prefix := lit.Value
		if i := strings.IndexByte(prefix, '/'); i >= 0 {
			prefix = prefix[:i]
		} else if len(w.Parts) > 1 {
			return // part of the prefix is quoted or expanded: no tilde expansion
		}
		name := prefix[1:]
		var repl string
		switch {
		case name == "+" && strings.HasPrefix(cwd, "/"):
			repl = strings.TrimRight(cwd, "/")
			if repl == "" {
				repl = "/"
			}
		case login != "" && name == login && loginHome != "":
			repl = loginHome
		default:
			return
		}
		start := int(lit.Pos().Offset())
		end := start + len(prefix)
		if end > len(command) || command[start:end] != prefix {
			return // the literal is not the raw bytes (escapes): leave it
		}
		spans = append(spans, span{start, end, repl})
	}
	syntax.Walk(file, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.Redirect:
			if x.N != nil {
				syntax.Walk(x.N, func(syntax.Node) bool { return true })
			}
			if x.Word != nil {
				syntax.Walk(x.Word, func(m syntax.Node) bool {
					if w, ok := m.(*syntax.Word); ok {
						visitWord(w)
					}
					return true
				})
			}
			return false // never descend into a heredoc body
		case *syntax.Word:
			visitWord(x)
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
		if s.start < last {
			continue
		}
		b.WriteString(command[last:s.start])
		b.WriteString(s.repl)
		last = s.end
	}
	b.WriteString(command[last:])
	if out := b.String(); out != command {
		return out
	}
	return ""
}
