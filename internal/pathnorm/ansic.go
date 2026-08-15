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
func DecodeANSICEscapes(body string) (string, bool) {
	if !strings.Contains(body, `\`) {
		return body, false
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
				b.WriteByte(byte(v))
				i += 2 + consumed
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		case 'u':
			if v, consumed, ok := readHexDigits(body[i+2:], 4); ok {
				b.WriteRune(rune(v))
				i += 2 + consumed
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		case 'U':
			if v, consumed, ok := readHexDigits(body[i+2:], 8); ok {
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
				if ctrl >= 'a' && ctrl <= 'z' {
					ctrl -= 'a' - 'A'
				}
				b.WriteByte(ctrl ^ 0x40)
				i += 3
				changed = true
			} else {
				b.WriteByte(c)
				i++
			}
		default:
			if next >= '0' && next <= '7' {
				if v, consumed, ok := readOctalDigits(body[i+1:], 3); ok {
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
		return body, false
	}
	return b.String(), true
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
		if s[i] == '$' && i+1 < n && s[i+1] == '\'' {
			j := i + 2
			for j < n {
				if s[j] == '\\' && j+1 < n {
					j += 2
					continue
				}
				if s[j] == '\'' {
					break
				}
				j++
			}
			if j < n && s[j] == '\'' {
				decoded, _ := DecodeANSICEscapes(s[i+2 : j])
				b.WriteString(decoded)
				i = j + 1
				changed = true
				continue
			}
			// Unterminated $'... — no closing quote; fall through and copy
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
