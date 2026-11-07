package unicode

import (
	"strings"
	"unicode"
)

// RecoverConsumerProse adds the reading produced by clients that discard
// private-use/unassigned characters and normalize compatibility forms. It is
// deliberately separate from RecoverRenderedText: identifiers and policy globs
// must keep their existing semantics. Callers must retain the raw reading and
// every existing recovery as well; this form may only add pattern matches.
// This is a focused ASCII compatibility fold, not full NFKC.
func RecoverConsumerProse(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 || isConsumerASCIISeparator(s[i]) {
			original := s
			for {
				next := recoverConsumerPass(s)
				next, _ = RecoverRenderedText(next)
				if next == s {
					return next, next != original
				}
				s = next
			}
		}
	}
	return s, false
}

func isConsumerASCIISeparator(b byte) bool {
	return b <= 0x08 || b == 0x0b || (b >= 0x0e && b <= 0x1f) || b == 0x7f
}

func isConsumerDeleted(r rune) bool {
	return r == unicode.ReplacementChar || unicode.In(r, unicode.Cf, unicode.Co, unicode.Cn)
}

func recoverConsumerPass(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r < 0x80:
			if isConsumerASCIISeparator(byte(r)) {
				b.WriteByte(' ')
			} else {
				b.WriteByte(byte(r))
			}
		case isConsumerDeleted(r):
			// Go's JSON decoder represents lone surrogates with U+FFFD.
		case r >= 0xff01 && r <= 0xff5e:
			b.WriteRune(r - 0xfee0)
		default:
			if folded, ok := consumerASCIIFold[r]; ok {
				b.WriteString(folded)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// StripConsumerIgnorables supplies an additional schema-property name reading.
// It only deletes the client's Cf/Co/Cn/U+FFFD set, leaving identifier folds
// and policy matching unchanged. Raw names must always be matched first.
func StripConsumerIgnorables(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			var b strings.Builder
			b.Grow(len(s))
			for _, r := range s {
				if !isConsumerDeleted(r) {
					b.WriteRune(r)
				}
			}
			stripped := b.String()
			return stripped, stripped != s
		}
	}
	return s, false
}

// ASCII-yielding NFKC decompositions from Small Form Variants, Roman numerals,
// Latin ligatures, superscripts, subscripts and modifier letters. Non-ASCII
// decompositions (for example the small ideographic comma) are left alone.
var consumerASCIIFold = map[rune]string{
	0x00aa: "a",    // FEMININE ORDINAL INDICATOR
	0x00b2: "2",    // SUPERSCRIPT TWO
	0x00b3: "3",    // SUPERSCRIPT THREE
	0x00b9: "1",    // SUPERSCRIPT ONE
	0x00ba: "o",    // MASCULINE ORDINAL INDICATOR
	0x02b0: "h",    // MODIFIER LETTER SMALL H
	0x02b2: "j",    // MODIFIER LETTER SMALL J
	0x02b3: "r",    // MODIFIER LETTER SMALL R
	0x02b7: "w",    // MODIFIER LETTER SMALL W
	0x02b8: "y",    // MODIFIER LETTER SMALL Y
	0x02e1: "l",    // MODIFIER LETTER SMALL L
	0x02e2: "s",    // MODIFIER LETTER SMALL S
	0x02e3: "x",    // MODIFIER LETTER SMALL X
	0x1d2c: "A",    // MODIFIER LETTER CAPITAL A
	0x1d2e: "B",    // MODIFIER LETTER CAPITAL B
	0x1d30: "D",    // MODIFIER LETTER CAPITAL D
	0x1d31: "E",    // MODIFIER LETTER CAPITAL E
	0x1d33: "G",    // MODIFIER LETTER CAPITAL G
	0x1d34: "H",    // MODIFIER LETTER CAPITAL H
	0x1d35: "I",    // MODIFIER LETTER CAPITAL I
	0x1d36: "J",    // MODIFIER LETTER CAPITAL J
	0x1d37: "K",    // MODIFIER LETTER CAPITAL K
	0x1d38: "L",    // MODIFIER LETTER CAPITAL L
	0x1d39: "M",    // MODIFIER LETTER CAPITAL M
	0x1d3a: "N",    // MODIFIER LETTER CAPITAL N
	0x1d3c: "O",    // MODIFIER LETTER CAPITAL O
	0x1d3e: "P",    // MODIFIER LETTER CAPITAL P
	0x1d3f: "R",    // MODIFIER LETTER CAPITAL R
	0x1d40: "T",    // MODIFIER LETTER CAPITAL T
	0x1d41: "U",    // MODIFIER LETTER CAPITAL U
	0x1d42: "W",    // MODIFIER LETTER CAPITAL W
	0x1d43: "a",    // MODIFIER LETTER SMALL A
	0x1d47: "b",    // MODIFIER LETTER SMALL B
	0x1d48: "d",    // MODIFIER LETTER SMALL D
	0x1d49: "e",    // MODIFIER LETTER SMALL E
	0x1d4d: "g",    // MODIFIER LETTER SMALL G
	0x1d4f: "k",    // MODIFIER LETTER SMALL K
	0x1d50: "m",    // MODIFIER LETTER SMALL M
	0x1d52: "o",    // MODIFIER LETTER SMALL O
	0x1d56: "p",    // MODIFIER LETTER SMALL P
	0x1d57: "t",    // MODIFIER LETTER SMALL T
	0x1d58: "u",    // MODIFIER LETTER SMALL U
	0x1d5b: "v",    // MODIFIER LETTER SMALL V
	0x1d62: "i",    // LATIN SUBSCRIPT SMALL LETTER I
	0x1d63: "r",    // LATIN SUBSCRIPT SMALL LETTER R
	0x1d64: "u",    // LATIN SUBSCRIPT SMALL LETTER U
	0x1d65: "v",    // LATIN SUBSCRIPT SMALL LETTER V
	0x1d9c: "c",    // MODIFIER LETTER SMALL C
	0x1da0: "f",    // MODIFIER LETTER SMALL F
	0x1dbb: "z",    // MODIFIER LETTER SMALL Z
	0x2070: "0",    // SUPERSCRIPT ZERO
	0x2071: "i",    // SUPERSCRIPT LATIN SMALL LETTER I
	0x2074: "4",    // SUPERSCRIPT FOUR
	0x2075: "5",    // SUPERSCRIPT FIVE
	0x2076: "6",    // SUPERSCRIPT SIX
	0x2077: "7",    // SUPERSCRIPT SEVEN
	0x2078: "8",    // SUPERSCRIPT EIGHT
	0x2079: "9",    // SUPERSCRIPT NINE
	0x207a: "+",    // SUPERSCRIPT PLUS SIGN
	0x207c: "=",    // SUPERSCRIPT EQUALS SIGN
	0x207d: "(",    // SUPERSCRIPT LEFT PARENTHESIS
	0x207e: ")",    // SUPERSCRIPT RIGHT PARENTHESIS
	0x207f: "n",    // SUPERSCRIPT LATIN SMALL LETTER N
	0x2080: "0",    // SUBSCRIPT ZERO
	0x2081: "1",    // SUBSCRIPT ONE
	0x2082: "2",    // SUBSCRIPT TWO
	0x2083: "3",    // SUBSCRIPT THREE
	0x2084: "4",    // SUBSCRIPT FOUR
	0x2085: "5",    // SUBSCRIPT FIVE
	0x2086: "6",    // SUBSCRIPT SIX
	0x2087: "7",    // SUBSCRIPT SEVEN
	0x2088: "8",    // SUBSCRIPT EIGHT
	0x2089: "9",    // SUBSCRIPT NINE
	0x208a: "+",    // SUBSCRIPT PLUS SIGN
	0x208c: "=",    // SUBSCRIPT EQUALS SIGN
	0x208d: "(",    // SUBSCRIPT LEFT PARENTHESIS
	0x208e: ")",    // SUBSCRIPT RIGHT PARENTHESIS
	0x2090: "a",    // LATIN SUBSCRIPT SMALL LETTER A
	0x2091: "e",    // LATIN SUBSCRIPT SMALL LETTER E
	0x2092: "o",    // LATIN SUBSCRIPT SMALL LETTER O
	0x2093: "x",    // LATIN SUBSCRIPT SMALL LETTER X
	0x2095: "h",    // LATIN SUBSCRIPT SMALL LETTER H
	0x2096: "k",    // LATIN SUBSCRIPT SMALL LETTER K
	0x2097: "l",    // LATIN SUBSCRIPT SMALL LETTER L
	0x2098: "m",    // LATIN SUBSCRIPT SMALL LETTER M
	0x2099: "n",    // LATIN SUBSCRIPT SMALL LETTER N
	0x209a: "p",    // LATIN SUBSCRIPT SMALL LETTER P
	0x209b: "s",    // LATIN SUBSCRIPT SMALL LETTER S
	0x209c: "t",    // LATIN SUBSCRIPT SMALL LETTER T
	0x2160: "I",    // ROMAN NUMERAL ONE
	0x2161: "II",   // ROMAN NUMERAL TWO
	0x2162: "III",  // ROMAN NUMERAL THREE
	0x2163: "IV",   // ROMAN NUMERAL FOUR
	0x2164: "V",    // ROMAN NUMERAL FIVE
	0x2165: "VI",   // ROMAN NUMERAL SIX
	0x2166: "VII",  // ROMAN NUMERAL SEVEN
	0x2167: "VIII", // ROMAN NUMERAL EIGHT
	0x2168: "IX",   // ROMAN NUMERAL NINE
	0x2169: "X",    // ROMAN NUMERAL TEN
	0x216a: "XI",   // ROMAN NUMERAL ELEVEN
	0x216b: "XII",  // ROMAN NUMERAL TWELVE
	0x216c: "L",    // ROMAN NUMERAL FIFTY
	0x216d: "C",    // ROMAN NUMERAL ONE HUNDRED
	0x216e: "D",    // ROMAN NUMERAL FIVE HUNDRED
	0x216f: "M",    // ROMAN NUMERAL ONE THOUSAND
	0x2170: "i",    // SMALL ROMAN NUMERAL ONE
	0x2171: "ii",   // SMALL ROMAN NUMERAL TWO
	0x2172: "iii",  // SMALL ROMAN NUMERAL THREE
	0x2173: "iv",   // SMALL ROMAN NUMERAL FOUR
	0x2174: "v",    // SMALL ROMAN NUMERAL FIVE
	0x2175: "vi",   // SMALL ROMAN NUMERAL SIX
	0x2176: "vii",  // SMALL ROMAN NUMERAL SEVEN
	0x2177: "viii", // SMALL ROMAN NUMERAL EIGHT
	0x2178: "ix",   // SMALL ROMAN NUMERAL NINE
	0x2179: "x",    // SMALL ROMAN NUMERAL TEN
	0x217a: "xi",   // SMALL ROMAN NUMERAL ELEVEN
	0x217b: "xii",  // SMALL ROMAN NUMERAL TWELVE
	0x217c: "l",    // SMALL ROMAN NUMERAL FIFTY
	0x217d: "c",    // SMALL ROMAN NUMERAL ONE HUNDRED
	0x217e: "d",    // SMALL ROMAN NUMERAL FIVE HUNDRED
	0x217f: "m",    // SMALL ROMAN NUMERAL ONE THOUSAND
	0xfb00: "ff",   // LATIN SMALL LIGATURE FF
	0xfb01: "fi",   // LATIN SMALL LIGATURE FI
	0xfb02: "fl",   // LATIN SMALL LIGATURE FL
	0xfb03: "ffi",  // LATIN SMALL LIGATURE FFI
	0xfb04: "ffl",  // LATIN SMALL LIGATURE FFL
	0xfb05: "st",   // LATIN SMALL LIGATURE LONG S T
	0xfb06: "st",   // LATIN SMALL LIGATURE ST
	0xfe50: ",",    // SMALL COMMA
	0xfe52: ".",    // SMALL FULL STOP
	0xfe54: ";",    // SMALL SEMICOLON
	0xfe55: ":",    // SMALL COLON
	0xfe56: "?",    // SMALL QUESTION MARK
	0xfe57: "!",    // SMALL EXCLAMATION MARK
	0xfe59: "(",    // SMALL LEFT PARENTHESIS
	0xfe5a: ")",    // SMALL RIGHT PARENTHESIS
	0xfe5b: "{",    // SMALL LEFT CURLY BRACKET
	0xfe5c: "}",    // SMALL RIGHT CURLY BRACKET
	0xfe5f: "#",    // SMALL NUMBER SIGN
	0xfe60: "&",    // SMALL AMPERSAND
	0xfe61: "*",    // SMALL ASTERISK
	0xfe62: "+",    // SMALL PLUS SIGN
	0xfe63: "-",    // SMALL HYPHEN-MINUS
	0xfe64: "<",    // SMALL LESS-THAN SIGN
	0xfe65: ">",    // SMALL GREATER-THAN SIGN
	0xfe66: "=",    // SMALL EQUALS SIGN
	0xfe68: "\\",   // SMALL REVERSE SOLIDUS
	0xfe69: "$",    // SMALL DOLLAR SIGN
	0xfe6a: "%",    // SMALL PERCENT SIGN
	0xfe6b: "@",    // SMALL COMMERCIAL AT
}
