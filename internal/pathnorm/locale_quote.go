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
// each IS load-bearing: whitespace, `| & ; ( ) < > " ' `` \ $ * ? [ ] { } # ~
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
