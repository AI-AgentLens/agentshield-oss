package pathnorm

import "strings"

// decodeDollarDoubleQuotedSpans finds every $"..." (locale-translated
// string) span in s — honoring backslash escapes within the span so an
// escaped quote (\") doesn't terminate it early — and replaces each with its
// literal content. See StripShellQuotes's doc comment for why the literal
// fallback (never a catalog lookup) is the correct runtime value here.
//
// Only \" \\ \$ and \` are unescaped within the span, matching bash's own
// double-quote escape rules — an unrecognized backslash sequence is left
// exactly as written, the same conservative posture as DecodeANSICEscapes.
func decodeDollarDoubleQuotedSpans(s string) (string, bool) {
	if !strings.Contains(s, `$"`) {
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	changed := false
	n := len(s)
	i := 0
	for i < n {
		if s[i] == '$' && i+1 < n && s[i+1] == '"' {
			j := i + 2
			for j < n {
				if s[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if s[j] == '"' {
					break
				}
				j++
			}
			if j < n && s[j] == '"' {
				b.WriteString(unescapeDblQuoteBody(s[i+2 : j]))
				i = j + 1
				changed = true
				continue
			}
			// Unterminated $"... — no closing quote; fall through and copy
			// the "$" literally rather than guess at a boundary.
		}
		b.WriteByte(s[i])
		i++
	}

	if !changed {
		return s, false
	}
	return b.String(), true
}

// unescapeDblQuoteBody un-escapes the four backslash sequences that are
// special inside real double-quoting (\" \\ \$ \`) — everything else is
// copied through untouched, since bash leaves those backslashes literal too.
func unescapeDblQuoteBody(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	n := len(s)
	for i := 0; i < n; i++ {
		if s[i] == '\\' && i+1 < n {
			switch s[i+1] {
			case '"', '\\', '$', '`':
				b.WriteByte(s[i+1])
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// FoldObfuscatingBackslashes removes a backslash immediately preceding an
// ASCII alphanumeric character or one of a small set of syntactically-inert
// punctuation characters, leaving every other backslash — and everything
// else — exactly as written. Reports whether anything changed.
//
// The gate (issue #3208, extended by #3209): a backslash escaping a
// character with no special meaning to the shell is not escaping — it is
// obfuscation. Outside quotes, a shell removes ANY non-quoted backslash and
// keeps the next character literally, so folding is always semantically
// correct. But alphanumerics plus this punctuation set are the only classes
// where that fold is also safe to apply to a RECONSTRUCTED match candidate
// that may be re-tokenized downstream: folding `\*` -> `*`, `\;` -> `;`,
// `\ ` -> ` `, `\$` -> `$`, or `\\` -> `\` would change how the reconstructed
// text splits into words or expands on a second pass, while none of
// alphanumerics, `-`, `/`, `.`, `:`, `,`, `_`, `+`, or `@` ever carries that
// syntactic weight in any shell grammar — none is a word separator,
// operator, quote, or expansion marker. Deliberately still excluded, because
// each IS load-bearing: whitespace, `| & ; ( ) < > " ' “ \ $ * ? [ ] { } # ~
// = ^ !`. So this function — unlike StripShellQuotes's unconditional strip,
// which is only ever applied to already-isolated name-like tokens (an
// executable name, a subcommand, a flag) — is safe to run on a whole
// reconstructed command.
func FoldObfuscatingBackslashes(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	n := len(s)
	for i := 0; i < n; i++ {
		if s[i] == '\\' && i+1 < n && isFoldableEscapeTarget(s[i+1]) {
			b.WriteByte(s[i+1])
			i++
			changed = true
			continue
		}
		b.WriteByte(s[i])
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func isASCIIAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// isFoldableEscapeTarget reports whether c is safe to un-escape under
// FoldObfuscatingBackslashes: an ASCII alphanumeric, or one of the
// syntactically-inert punctuation characters `- / . : , _ + @` (#3209).
func isFoldableEscapeTarget(c byte) bool {
	if isASCIIAlnum(c) {
		return true
	}
	switch c {
	case '-', '/', '.', ':', ',', '_', '+', '@':
		return true
	}
	return false
}

// FoldObfuscatingBackslashesUnquoted is FoldObfuscatingBackslashes restricted
// to escapes that sit in UNQUOTED context, tracked by a lexical scan rather
// than an AST walk.
//
// It exists for one caller: shellparse.DequoteCommand's parse-failure retry
// (#3211). Everywhere else the tree is available and the fold can be applied
// per-Lit, where quoting has already been resolved. On a command that does not
// parse there is no tree, so the quote state has to be recovered by hand — and
// getting it wrong is not cosmetic. A backslash before an alphanumeric is
// literal inside BOTH quote forms:
//
//	bash -c "printf 'a\nb'"     -> a\nb   (single: everything literal)
//	bash -c 'printf "a\nb"'     -> a\nb   (double: \ is special only before
//	                                       $ ` " \ and newline)
//
// so folding one would rewrite the command into something the shell never
// would, and the result is fed to command_regex as an extra match candidate.
// A wrong candidate cannot create a bypass — candidates only ever ADD matches
// — but it can create a false BLOCK, which is the failure mode users switch
// the tool off over.
//
// The scan therefore folds only while unquoted, and consumes both bytes of any
// escape it does not fold, so `\'` and `\"` cannot flip the quote state.
// Reports whether anything changed.
func FoldObfuscatingBackslashesUnquoted(s string) (string, bool) {
	if !strings.Contains(s, `\`) {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false

	const (
		unquoted = iota
		inSingle
		inDouble
	)
	state := unquoted

	for i := 0; i < len(s); i++ {
		c := s[i]
		switch state {
		case inSingle:
			// Nothing is special inside single quotes, not even a backslash.
			if c == '\'' {
				state = unquoted
			}
			b.WriteByte(c)
		case inDouble:
			// Backslash is special here only before $ ` " \ and newline. It is
			// never folded: `"a\nb"` is literally a-backslash-n-b to bash.
			// Both bytes are still consumed so an escaped quote does not close
			// the span.
			if c == '\\' && i+1 < len(s) {
				b.WriteByte(c)
				b.WriteByte(s[i+1])
				i++
				continue
			}
			if c == '"' {
				state = unquoted
			}
			b.WriteByte(c)
		default:
			if c == '\\' && i+1 < len(s) {
				if isFoldableEscapeTarget(s[i+1]) {
					b.WriteByte(s[i+1])
					i++
					changed = true
					continue
				}
				// Not foldable — emit both bytes verbatim. Critically this
				// covers `\'` and `\"`, where dropping through to the quote
				// handling below would open a span that the shell never opened.
				b.WriteByte(c)
				b.WriteByte(s[i+1])
				i++
				continue
			}
			switch c {
			case '\'':
				state = inSingle
			case '"':
				state = inDouble
			}
			b.WriteByte(c)
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}
