package shellparse

import (
	"sort"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// FoldQuotedCommandWords returns cmd with every whole-quoted command word
// written bare, in place, and "" when there is nothing to fold (the no-op
// sentinel the normalizers here use). Bash removes the quotes, so
// `X=1 'cp' a b`, `sudo 'cp' a b` and `echo $('cp' a b)` run `cp`.
//
// FoldLeadingExecWord reads the first word of a statement; this reads the word
// each simple command runs, which is not the first word after an assignment
// prefix or an exec wrapper, and not a statement start inside a substitution
// (#4728). The target is found with the walk the regex layer's wrapper strip
// uses (execWrapperTarget), so the two cannot disagree about what a wrapper
// runs. Assignments are not in CallExpr.Args, so a prefix needs no handling.
//
// Only a word that is exactly one single- or double-quoted span of plain
// literal text is folded (no `$`, no backquote, no escape inside), so the fold
// reproduces the word bash produces. The text between words, separators
// included, is untouched. A command the bash parser rejects returns "".
//
// It reads the top-level parse only: a quoted word inside the shell source a
// carrier hands to a shell is text here. FoldQuotedCommandWordsInPayloads
// reads those too.
//
// A caller matches this reading IN ADDITION to the text as written, never
// instead of it: it can only add a match.
func FoldQuotedCommandWords(cmd string) string {
	return applyWordEdits(cmd, quotedCommandWordEdits(cmd, 0, false))
}

// FoldQuotedCommandWordsInPayloads is FoldQuotedCommandWords that also folds
// the whole-quoted command words of the shell source a carrier hands to a
// shell, in place in cmd (#4920):
//
//	bash -c '"cp" a CLAUDE.md'            ->  bash -c 'cp a CLAUDE.md'
//	bash -s <<< 'echo x; "cp" a b'        ->  bash -s <<< 'echo x; cp a b'
//	bash < <(echo '"mv" a .cursorrules')  ->  bash < <(echo 'mv a .cursorrules')
//
// The output is the command's bare twin: the same carrier, the same payload
// with its command words unquoted, every other byte as written. That is what
// lets a caller evaluate it as a second reading and get exactly the decision
// the bare twin gets.
//
// # Which payloads
//
// A payload is recognised only where the parser itself decomposes one, so the
// two cannot disagree about what is shell source: the statement's own segment,
// built by the parser's walkStmt, must satisfy CarriesShellSource, and the
// payload is the argv word, here-string, heredoc body or `<(echo …)` argument
// whose value is the text ExtractInlineCode returns for it (`-c`, eval, trap,
// su/runuser -c, the shell-source carriers of source_carrier.go, a heredoc or
// here-string or stdin process substitution fed to a shell, `source <(…)`).
// Code interpreters (`python3 -c`) are not carriers here, for the reason
// CarriesShellSource gives: their payload is not shell source.
//
// An emitting statement piped into a shell (`echo '…' | bash`, `printf '…' |
// sh`) is deliberately NOT read here, although the regex stage's
// executed-text candidates read it. Its payload's value is not its literal
// text whenever the emitter decodes escapes (`printf '\n"cp" …\n' | sh`), so
// this byte-for-byte fold could read only the plain spelling: that admitted
// the plain form into TestEmittedEscapeParity's denominator while its
// escape-prefixed spellings decided as on main, and the sweep went over
// budget (#4929). The fix that reads both composes this fold with the
// escape-decoding reading (decodeEscapes, emitted_escape.go) and is its own
// change; until then the piped form decides exactly as on main, pinned in
// TestFoldQuotedCommandWordsInPayloads_4920 and the policy row tests.
//
// # Which spellings
//
// The fold edits bytes of the outer text, so a payload is read only when its
// value IS its text: one single-quoted span, one double-quoted span of plain
// literal text with no backslash, or a heredoc body of plain literal text
// with no backslash. Anything else (an escaped `\"cp\"` inside double quotes,
// an expansion, a payload joined from several argv words) is not folded: a
// miss, never a wrong rewrite. Nested carriers are read up to
// maxPayloadFoldDepth levels.
func FoldQuotedCommandWordsInPayloads(cmd string) string {
	return applyWordEdits(cmd, quotedCommandWordEdits(cmd, 0, true))
}

// maxPayloadFoldDepth bounds how many nested carrier payloads
// FoldQuotedCommandWordsInPayloads reads (`bash -c 'bash -c "…"'` is two).
// Each level parses only a payload that holds a quote character.
const maxPayloadFoldDepth = 3

// wordEdit replaces text[start:end] with repl.
type wordEdit struct {
	start, end int
	repl       string
}

// quotedCommandWordEdits returns the folds of text's whole-quoted command
// words, as edits in text's own offsets. With payloads, it also returns the
// folds inside every carrier payload whose value is its text, shifted into
// text's offsets.
func quotedCommandWordEdits(text string, depth int, payloads bool) []wordEdit {
	if !strings.ContainsAny(text, `'"`) {
		return nil
	}
	file := parseBashFile(text)
	if file == nil {
		return nil
	}
	var edits []wordEdit
	seen := map[int]bool{}
	add := func(e wordEdit) {
		if e.start < 0 || e.end > len(text) || e.start >= e.end || seen[e.start] {
			return
		}
		seen[e.start] = true
		edits = append(edits, e)
	}
	fold := func(w *syntax.Word) {
		lit, ok := wholeQuotedLiteral(w)
		if !ok {
			return
		}
		add(wordEdit{int(w.Pos().Offset()), int(w.End().Offset()), lit})
	}
	readPayloads := payloads && depth+1 < maxPayloadFoldDepth
	var syms *ExecSymbols
	if readPayloads {
		syms = buildExecSymbols(file)
	}
	foldPayload := func(p payloadSpan) {
		for _, e := range quotedCommandWordEdits(p.value, depth+1, true) {
			add(wordEdit{p.start + e.start, p.start + e.end, e.repl})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			if len(n.Args) == 0 {
				return true
			}
			target, _, hops := execWrapperHops(n)
			fold(n.Args[0])
			for _, h := range hops {
				fold(n.Args[h])
			}
			if target < len(n.Args) {
				fold(n.Args[target])
			}
		case *syntax.Stmt:
			if readPayloads {
				for _, p := range carrierPayloads(n, text, syms) {
					foldPayload(p)
				}
			}
		}
		return true
	})
	return edits
}

// applyWordEdits applies edits to cmd in one forward pass and returns "" when
// nothing changed. An edit overlapping an earlier one is dropped, keeping the
// text as written there.
func applyWordEdits(cmd string, edits []wordEdit) string {
	if len(edits) == 0 {
		return ""
	}
	// One forward pass: rebuilding the string per edit cost O(edits x length)
	// (#4792 pass 1, follow-up 1).
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var b strings.Builder
	b.Grow(len(cmd))
	prev := 0
	for _, e := range edits {
		if e.start < prev {
			continue // overlapping edit: keep the text as written
		}
		b.WriteString(cmd[prev:e.start])
		b.WriteString(e.repl)
		prev = e.end
	}
	b.WriteString(cmd[prev:])
	out := b.String()
	if out == cmd {
		return ""
	}
	return out
}

// payloadSpan is shell source a carrier hands to a shell whose value is the
// exact text at text[start : start+len(value)].
type payloadSpan struct {
	value string
	start int
}

// carrierPayloads returns the payloads of stmt when the parser's own segment
// for it carries shell source: every word of the statement (argv, here-string,
// heredoc body, the argument of a `<(echo …)`) whose value is the text
// ExtractInlineCode returns for that segment.
func carrierPayloads(stmt *syntax.Stmt, text string, syms *ExecSymbols) []payloadSpan {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil
	}
	// Candidates first, and only those holding a quote character (nothing
	// else can carry a quoted command word), so a statement with none never
	// pays for its segment.
	var cands []payloadSpan
	consider := func(p payloadSpan, ok bool) {
		if ok && strings.ContainsAny(p.value, `'"`) {
			cands = append(cands, p)
		}
	}
	considerWord := func(w *syntax.Word) {
		consider(quotedPayloadSpan(w, text))
		for _, arg := range procSubstEchoArgs(w) {
			consider(quotedPayloadSpan(arg, text))
		}
	}
	for _, w := range call.Args[1:] {
		considerWord(w)
	}
	for _, r := range stmt.Redirs {
		if r.Hdoc != nil {
			consider(heredocPayloadSpan(r.Hdoc, text))
		}
		considerWord(r.Word)
	}
	if len(cands) == 0 {
		return nil
	}
	// The parser's segment for this one statement, with maxDepth 1 so the
	// payload is not sub-parsed here: CarriesShellSource and ExtractInlineCode
	// read exactly the fields walkStmt fills for the parse every analyzer sees.
	pc := &ParsedCommand{}
	walkStmt(pc, stmt, text, 0, 1, syms)
	if len(pc.Segments) != 1 || !CarriesShellSource(pc.Segments[0]) {
		return nil
	}
	code := strings.TrimSpace(ExtractInlineCode(pc.Segments[0]))
	if code == "" {
		return nil
	}
	var out []payloadSpan
	for _, p := range cands {
		if strings.TrimSpace(p.value) == code {
			out = append(out, p)
		}
	}
	return out
}

// procSubstEchoArgs returns the argument words of the echo / printf a bare
// `<(…)` word runs, when it is the literal-only shape resolveProcSubstLiteral
// accepts, and nil otherwise.
func procSubstEchoArgs(w *syntax.Word) []*syntax.Word {
	if w == nil || len(w.Parts) != 1 {
		return nil
	}
	ps, ok := w.Parts[0].(*syntax.ProcSubst)
	if !ok {
		return nil
	}
	if _, ok := resolveProcSubstLiteral(ps); !ok {
		return nil
	}
	return ps.Stmts[0].Cmd.(*syntax.CallExpr).Args[1:]
}

// quotedPayloadSpan returns the payload a word holds when its value is its
// text: one single-quoted span, or one double-quoted span of plain literal
// text with no backslash (inside double quotes `\"`, `\\` and `\$` are
// escapes, so the value would not be the text).
func quotedPayloadSpan(w *syntax.Word, text string) (payloadSpan, bool) {
	if w == nil || len(w.Parts) != 1 {
		return payloadSpan{}, false
	}
	switch p := w.Parts[0].(type) {
	case *syntax.SglQuoted:
		if p.Dollar {
			return payloadSpan{}, false
		}
		return spanAt(text, int(p.Left.Offset())+1, p.Value)
	case *syntax.DblQuoted:
		if p.Dollar {
			return payloadSpan{}, false
		}
		v, ok := plainLiteralParts(p.Parts)
		if !ok {
			return payloadSpan{}, false
		}
		return spanAt(text, int(p.Left.Offset())+1, v)
	}
	return payloadSpan{}, false
}

// heredocPayloadSpan returns a heredoc body of plain literal text with no
// backslash (in an unquoted heredoc `\$` and `\\` are escapes).
func heredocPayloadSpan(w *syntax.Word, text string) (payloadSpan, bool) {
	if w == nil || len(w.Parts) == 0 {
		return payloadSpan{}, false
	}
	v, ok := plainLiteralParts(w.Parts)
	if !ok {
		return payloadSpan{}, false
	}
	return spanAt(text, int(w.Pos().Offset()), v)
}

// plainLiteralParts concatenates parts when every one is a Lit and the text
// holds no backslash.
func plainLiteralParts(parts []syntax.WordPart) (string, bool) {
	var b strings.Builder
	for _, part := range parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		b.WriteString(lit.Value)
	}
	v := b.String()
	if strings.Contains(v, `\`) {
		return "", false
	}
	return v, true
}

// spanAt checks that v is the text at start, so an edit inside the payload
// maps onto the outer text byte for byte.
func spanAt(text string, start int, v string) (payloadSpan, bool) {
	if v == "" || start < 0 || start+len(v) > len(text) || text[start:start+len(v)] != v {
		return payloadSpan{}, false
	}
	return payloadSpan{value: v, start: start}, true
}

// wholeQuotedLiteral reports the text of a word that is one quoted span of
// plain literal characters.
func wholeQuotedLiteral(w *syntax.Word) (string, bool) {
	if w == nil || len(w.Parts) != 1 {
		return "", false
	}
	var lit string
	switch p := w.Parts[0].(type) {
	case *syntax.SglQuoted:
		if p.Dollar {
			return "", false
		}
		lit = p.Value
	case *syntax.DblQuoted:
		if p.Dollar {
			return "", false
		}
		var b strings.Builder
		for _, part := range p.Parts {
			l, ok := part.(*syntax.Lit)
			if !ok {
				return "", false
			}
			b.WriteString(l.Value)
		}
		lit = b.String()
	default:
		return "", false
	}
	if lit == "" || strings.ContainsAny(lit, " \t\r\n\\$`'\"") {
		return "", false
	}
	return lit, true
}
