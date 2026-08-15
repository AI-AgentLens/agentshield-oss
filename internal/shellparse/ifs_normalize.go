package shellparse

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// NormalizeIFS returns a reconstruction of command with unquoted $IFS /
// ${IFS} word-splitting separators collapsed to a literal space, so the
// AST every downstream analyzer consumes reflects the argument boundaries a
// real shell resolves at runtime rather than the unsplit source text.
//
// $IFS defaults to space/tab/newline in every POSIX shell. Because that
// default is whitespace, `rm${IFS}-rf${IFS}/` and `rm -rf /` are the same
// invocation once the shell expands and field-splits it — but mvdan.cc/sh
// (like any parser operating on pre-expansion text) sees no whitespace in
// the source, so it parses the whole thing as ONE unsplit word. Every
// analyzer keyed on argument shape (executable name, flags, protected-path
// arguments) silently stops matching: this is the "field separators
// supplied through a variable rather than literal whitespace" class named
// in taxonomy node
// unauthorized-execution/agentic-attacks/pre-expansion-command-guard-bypass
// (issue #3044). Measured against the corpus of commands this engine
// BLOCKs standalone, wrapping every literal space as ${IFS} instead
// downgraded 68% of them (1657/2414) — the largest single bypass class
// found on this codebase to date, well past the 20.8% compound-wrapping
// gap (#3045) and the 52.5% line-continuation gap (#3055).
//
// Deliberately conservative: bails (returns "") if the command reassigns
// IFS anywhere ("IFS=x", "export IFS=x", ...), since the default-whitespace
// assumption no longer holds and guessing the wrong separator character
// could produce an incorrect canonical form. That leaves explicit
// IFS-reassignment obfuscation as a known, narrower residual gap — it
// requires an extra statement to set up and is not the form used by any
// surveyed real-world bypass, unlike the bare ${IFS} substitution this
// closes.
//
// Returns "" (a no-op sentinel, same convention as DequoteCommand) when the
// command has no "IFS" text, when IFS is explicitly reassigned, when
// nothing was actually rewritten, or when parsing fails — callers fall
// back to the original raw command in all four cases.
func NormalizeIFS(command string) string {
	if !strings.Contains(command, "IFS") {
		return ""
	}

	reader := strings.NewReader(command)
	parser := syntax.NewParser(syntax.KeepComments(false), syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(reader, "")
	if err != nil {
		return ""
	}

	if ifsReassigned(file) {
		return ""
	}

	type span struct{ start, end int }
	var spans []span
	syntax.Walk(file, func(node syntax.Node) bool {
		w, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		// Only top-level Parts of this Word — a ParamExp nested inside a
		// DblQuoted (`"${IFS}"`) is a separate WordPart owned by the
		// DblQuoted, never visited here, and correctly left alone: a
		// double-quoted expansion does not undergo field splitting, so it
		// is not a separator no matter what IFS holds. SglQuoted can't
		// contain a ParamExp at all — single quotes are fully literal.
		for _, part := range w.Parts {
			pe, ok := part.(*syntax.ParamExp)
			if !ok || pe.Param == nil || pe.Param.Value != "IFS" {
				continue
			}
			// Bare $NAME/${NAME} only. Any modifier form (${IFS:-x},
			// ${IFS/a/b}, ${#IFS}, ${!IFS}, ...) doesn't carry the plain
			// "current word-splitting characters" meaning being
			// canonicalized here, so leave it untouched.
			if pe.Slice != nil || pe.Repl != nil || pe.Exp != nil ||
				pe.Index != nil || pe.NestedParam != nil ||
				pe.Length || pe.Width || pe.Excl {
				continue
			}
			spans = append(spans, span{int(pe.Pos().Offset()), int(pe.End().Offset())})
		}
		return true
	})

	if len(spans) == 0 {
		return ""
	}

	var sb strings.Builder
	last := 0
	for _, s := range spans {
		if s.start < last || s.start > len(command) || s.end > len(command) {
			continue // malformed offset — skip defensively, never corrupt the text
		}
		sb.WriteString(command[last:s.start])
		sb.WriteByte(' ')
		last = s.end
	}
	sb.WriteString(command[last:])
	// A substituted span at the very start or end of the text (a statement
	// beginning "${IFS}dd ..." right after a ";" separator, say) leaves a
	// literal leading/trailing space. Every consumer either re-parses the
	// result (whitespace-insensitive) or does literal text matching against
	// "^"/"$"-anchored patterns, where a stray boundary space is exactly the
	// kind of gap this function exists to close, not reintroduce.
	return strings.TrimSpace(sb.String())
}

// ifsReassigned reports whether the command assigns IFS anywhere, via a
// plain assignment ("IFS=, cmd") or a declaration builtin ("export IFS=,",
// "local IFS=,", "declare IFS=,", "readonly IFS=,").
func ifsReassigned(file *syntax.File) bool {
	reassigned := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if reassigned {
			return false
		}
		switch n := node.(type) {
		case *syntax.CallExpr:
			for _, a := range n.Assigns {
				if a.Name != nil && a.Name.Value == "IFS" {
					reassigned = true
					return false
				}
			}
		case *syntax.DeclClause:
			for _, a := range n.Args {
				if a.Name != nil && a.Name.Value == "IFS" {
					reassigned = true
					return false
				}
			}
		}
		return true
	})
	return reassigned
}
