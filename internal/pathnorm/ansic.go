package pathnorm

import "strings"

// DecodeANSICEscapes decodes bash ANSI-C quoting ($'...') escape sequences
// within body — the raw text between the $' and closing ' delimiters, exactly
// what mvdan.cc/sh's syntax.SglQuoted.Value holds for a Dollar-true node — into
// the actual bytes/runes bash produces at runtime. Reports whether anything
// was decoded; when false, body is returned unchanged.
//
// $'...' is a STATIC encoding, unlike $VAR/$(...): its content never depends
// on runtime state, so it is always safe to resolve, unlike genuine dynamic
// expansion. Every existing quote-normalization layer (pathnorm.StripShellQuotes,
// shellparse's DequoteCommand) treated any "$" as an unresolvable dynamic
// marker and left $'...' completely untouched — meaning an attacker could hide
// an executable name or protected path behind $'\x72\x6d' ("rm") or split
// escapes across adjacent $'...' fragments ($'\x72'$'\x6d') to defeat every
// structural/regex/glob-based rule keyed on the literal text, even though the
// existing ts-block-ansic-{hex,octal,unicode}-escape regex rules already prove
// this exact encoding is a recognized evasion class — those rules only catch
// 2+ escapes within a SINGLE quoted span, so splitting into single-escape
// fragments (still decodable, just not by that heuristic) slips through.
//
// Recognized escapes (bash `help printf` / ANSI-C quoting semantics):
//
//	\a \b \e \E \f \n \r \t \v \\ \' \" \?   — single-character escapes
//	\xHH        — 1-2 hex digits, one byte
//	\NNN        — 1-3 octal digits (first digit 0-7), one byte
//	\uHHHH      — 1-4 hex digits, one Unicode code point (UTF-8 encoded)
//	\UHHHHHHHH  — 1-8 hex digits, one Unicode code point (UTF-8 encoded)
//	\cX         — control character (Ctrl-X)
//
// Any other backslash sequence is left exactly as written (backslash and
// character both retained) — bash's own behavior for an unrecognized escape,
// and a conservative choice here: an unrecognized sequence never disappears,
// it just stays unresolved, so this function can only ever reveal MORE text,
// never hide any.
//
// An escape that decodes to byte 0 is written as a NUL byte, here and only
// here. bash ends the body at that escape instead (see ANSICNULIndex); that
// reading is evaluated separately, never in place of this one (#4540).
func DecodeANSICEscapes(body string) (string, bool) {
	out, changed, _ := decodeANSIC(body, false)
	return out, changed
}

// ANSICNULIndex returns the byte offset in body (the text between $' and the
// closing quote) of the first escape that bash decodes to byte 0, or -1.
//
// bash assembles the decoded $'...' text as a C string, so the body ENDS at
// that escape: r$'\0'm runs rm, and $'rm\0zz' runs rm (#4540). Text after the
// closing quote is not affected. Verified on bash 3.2.57 and 5.3.9 with
// printf and od, every spelling that yields byte 0:
//
//	\0 \00 \000   octal, and \400, which bash keeps to its low 8 bits
//	\x0 \x00      hex (\x0b is one escape, 0x0b, not \x0 then b)
//	\u0 \u0000    \U0 \U00000000 (bash 4.2+; bash 3.2 leaves \u literal)
//	\cX           when X&0x1f is 0: \c@, \c`, \c and a space, and the bytes
//	              0x80, 0xA0, 0xC0, 0xE0. bash computes \cX as X&0x1f, which
//	              DecodeANSICEscapes's XOR does not reproduce for these.
//
// zsh does not end the body: it keeps the NUL inside the string. An external
// command still sees the word cut at the NUL (argv is a C string), but zsh's
// own eval, trap, alias and source see the text after it and run it. So
// neither reading is the truth on its own, and the caller evaluates both.
func ANSICNULIndex(body string) int {
	_, _, at := decodeANSIC(body, true)
	return at
}

// decodeANSIC is DecodeANSICEscapes's loop. With stopAtNUL it stops at the
// first escape bash decodes to byte 0 and returns that escape's offset last;
// otherwise the offset is -1 and the rest is exactly DecodeANSICEscapes's.
func decodeANSIC(body string, stopAtNUL bool) (string, bool, int) {
	if !strings.Contains(body, `\`) {
		return body, false, -1
	}

	var b strings.Builder
	b.Grow(len(body))
	changed := false
	n := len(body)
	i := 0
	for i < n {
		c := body[i]
		if c != '\\' || i+1 >= n {
			b.WriteByte(c)
			i++
			continue
		}

		next := body[i+1]
		switch next {
		case 'a':
			b.WriteByte(0x07)
			i += 2
			changed = true
		case 'b':
			b.WriteByte(0x08)
			i += 2
			changed = true
		case 'e', 'E':
			b.WriteByte(0x1b)
			i += 2
			changed = true
		case 'f':
			b.WriteByte(0x0c)
			i += 2
			changed = true
		case 'n':
			b.WriteByte(0x0a)
			i += 2
			changed = true
		case 'r':
			b.WriteByte(0x0d)
			i += 2
			changed = true
		case 't':
			b.WriteByte(0x09)
			i += 2
			changed = true
		case 'v':
			b.WriteByte(0x0b)
			i += 2
			changed = true
		case '\\':
			b.WriteByte('\\')
			i += 2
			changed = true
		case '\'':
			b.WriteByte('\'')
			i += 2
			changed = true
		case '"':
			b.WriteByte('"')
			i += 2
			changed = true
		case '?':
			b.WriteByte('?')
			i += 2
			changed = true
		case 'x':
			if v, consumed, ok := readHexDigits(body[i+2:], 2); ok {
				if stopAtNUL && v == 0 {
					return b.String(), true, i
				}
				b.WriteByte(byte(v))
				i += 2 + consumed
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		case 'u':
			if v, consumed, ok := readHexDigits(body[i+2:], 4); ok {
				if stopAtNUL && v == 0 {
					return b.String(), true, i
				}
				b.WriteRune(rune(v))
				i += 2 + consumed
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		case 'U':
			if v, consumed, ok := readHexDigits(body[i+2:], 8); ok {
				if stopAtNUL && v == 0 {
					return b.String(), true, i
				}
				b.WriteRune(rune(v))
				i += 2 + consumed
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		case 'c':
			if i+2 < n {
				ctrl := body[i+2]
				if stopAtNUL && ctrl&0x1f == 0 {
					return b.String(), true, i
				}
				if ctrl >= 'a' && ctrl <= 'z' {
					ctrl -= 'a' - 'A'
				}
				// bash masks (X & 0x1f) for every X; only \c? is the DEL
				// special case. XOR 0x40 agrees on letters and @[\]^_ but
				// turns \c* (newline) and \c) (tab) into letters (#4543).
				if ctrl == '?' {
					b.WriteByte(0x7f)
				} else {
					b.WriteByte(ctrl & 0x1f)
				}
				i += 3
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		default:
			if next >= '0' && next <= '7' {
				if v, consumed, ok := readOctalDigits(body[i+1:], 3); ok {
					if stopAtNUL && byte(v) == 0 {
						return b.String(), true, i
					}
					b.WriteByte(byte(v))
					i += 1 + consumed
					changed = true
					continue
				}
			}
			// Unrecognized escape — retain both the backslash and the
			// character, exactly as bash leaves it undefined/untouched.
			b.WriteByte(c)
			i++
		}
	}

	if !changed {
		return body, false, -1
	}
	return b.String(), true, -1
}

// decodeDollarQuotedSpans finds every $'...' span in s — honoring backslash
// escapes within the span so an escaped quote (\') doesn't terminate it early
// — and replaces each with its decoded literal content. Used by
// StripShellQuotes to resolve ANSI-C quoting on the raw printed-text surface
// (as opposed to dequoteWordInPlace, which works directly on the AST node and
// so never needs to re-scan for the span boundaries).
func decodeDollarQuotedSpans(s string) (string, bool) {
	if !strings.Contains(s, "$'") {
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	changed := false
	n := len(s)
	i := 0
	for i < n {
		// An unterminated $'... (no closing quote) is not a span: the "$" is
		// copied literally rather than guessing at a boundary.
		if j := dollarQuotedSpanEnd(s, i); j >= 0 {
			decoded, _ := DecodeANSICEscapes(s[i+2 : j])
			b.WriteString(decoded)
			i = j + 1
			changed = true
			continue
		}
		b.WriteByte(s[i])
		i++
	}

	if !changed {
		return s, false
	}
	return b.String(), true
}

// dollarQuotedSpanEnd returns the offset of the quote that closes the $'...'
// span starting at s[i], or -1 when s[i:] does not start one or it is never
// closed. A backslash escapes the next byte, so \' does not close the span.
func dollarQuotedSpanEnd(s string, i int) int {
	n := len(s)
	if i+1 >= n || s[i] != '$' || s[i+1] != '\'' {
		return -1
	}
	for j := i + 2; j < n; j++ {
		if s[j] == '\\' && j+1 < n {
			j++
			continue
		}
		if s[j] == '\'' {
			return j
		}
	}
	return -1
}

// CutDollarQuotedSpansAtNUL is the text-only form of
// shellparse.ANSICNULReading, for a command the parser rejects (an
// unterminated heredoc, a quoted reserved word): every $'...' span found by
// StripShellQuotes's boundary rule has its body cut at the first escape bash
// decodes to byte 0 (ANSICNULIndex). Returns "" when nothing is cut.
//
// Without quote context a $' inside single or double quotes is cut too. That
// only touches the stricter-only second reading (policy.Engine.
// EvaluateANSICNUL), never the as-written text.
func CutDollarQuotedSpansAtNUL(s string) string {
	if !strings.Contains(s, "$'") {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	cut := false
	for i := 0; i < len(s); {
		j := dollarQuotedSpanEnd(s, i)
		if j < 0 {
			b.WriteByte(s[i])
			i++
			continue
		}
		if at := ANSICNULIndex(s[i+2 : j]); at >= 0 {
			b.WriteString(s[i : i+2+at])
			b.WriteByte('\'')
			cut = true
		} else {
			b.WriteString(s[i : j+1])
		}
		i = j + 1
	}
	if !cut {
		return ""
	}
	return b.String()
}

func readHexDigits(s string, maxDigits int) (value int, consumed int, ok bool) {
	n := 0
	for n < maxDigits && n < len(s) && isHexDigit(s[n]) {
		n++
	}
	if n == 0 {
		return 0, 0, false
	}
	v := 0
	for k := 0; k < n; k++ {
		v = v*16 + hexDigitValue(s[k])
	}
	return v, n, true
}

func readOctalDigits(s string, maxDigits int) (value int, consumed int, ok bool) {
	n := 0
	for n < maxDigits && n < len(s) && s[n] >= '0' && s[n] <= '7' {
		n++
	}
	if n == 0 {
		return 0, 0, false
	}
	v := 0
	for k := 0; k < n; k++ {
		v = v*8 + int(s[k]-'0')
	}
	return v, n, true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func hexDigitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	default: // 'A'-'F'
		return int(c-'A') + 10
	}
}
