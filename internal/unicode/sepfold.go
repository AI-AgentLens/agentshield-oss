package unicode

import "strings"

// FoldUnicodeSeparators folds Unicode characters that render as whitespace — but
// that Go's RE2 `\s` class does NOT match — down to an ASCII space, and reports
// whether any fold occurred.
//
// Motivation: Go's regexp is RE2, where the Perl class `\s` is ASCII-only and
// expands to exactly `[\t\n\f\r ]`. The inter-word poison patterns in the MCP
// scanners are spelled with `\s+` (293 `\s`-quantifier sites across 13 non-test
// scanner files at the time of writing, 158 of them in description_scanner.go),
// so replacing the ASCII spaces of an injection phrase with U+00A0 NO-BREAK
// SPACE — or any of the other Unicode space characters below — makes the phrase
// match nothing. Writing the directive as
// D = "<ignore-verb> all <previous-noun> <instructions-noun>":
//
//	D spelled with ASCII spaces  -> hidden_instructions
//	D spelled with U+00A0        -> no findings at all
//
// Measured the same way for an exfiltration directive and a stealth
// ("do not tell the user") directive: one finding each in ASCII, zero under the
// substitution.
//
// The substitution is free for the attacker on every axis that matters. The two
// strings render identically in a host's tool listing, an LLM tokenizer reads
// the NBSP form as ordinary word-separated English, and NBSP is a printable
// character that survives JSON transport, copy-paste, and log review.
//
// # Why this class fell between two existing defences
//
// The scanner already covers the two neighbouring classes, which is precisely
// why this one is easy to miss:
//
//   - ASCII separators (space, tab, dot, hyphen) — matched by `\s`, and the
//     letter-spacing form ("i g n o r e") is caught by detectSeparatorObfuscation.
//   - Zero-width characters (U+200B/200C/200D, U+2060, U+FEFF, U+2061–U+2064)
//     and bidi overrides — caught by detectInvisibleControls.
//
// The characters folded here are neither: they occupy visible horizontal space
// (so they are not "invisible") and they are not ASCII (so `\s` misses them).
// They are the only whitespace class that satisfies both halves.
//
// # What is deliberately NOT folded, and why
//
// Zero-width characters are excluded on purpose, and not only because
// detectInvisibleControls already reports them. Folding them to a SPACE would be
// semantically wrong in the direction that matters: U+200B is inserted INSIDE a
// word ("ig<ZWSP>nore") to split it, so folding it to a space yields "ig nore",
// which still matches nothing. The correct fold for a zero-width character is to
// the empty string — a different transform, with a different false-positive
// profile (it silently welds together words that a benign document separated),
// which is why it belongs in its own pass rather than being smuggled in here.
//
// U+180E MONGOLIAN VOWEL SEPARATOR is included: it was General_Category Zs
// through Unicode 6.2 and is still rendered as a space by a great deal of
// software, so an attacker can reach for it exactly like the others.
//
// # False-positive safety
//
// The fold itself is not a verdict, and callers must not treat it as one.
// Unicode spaces are entirely legitimate in prose: French typography puts a
// U+202F NARROW NO-BREAK SPACE before `: ; ! ?`, figures are grouped with U+2007
// FIGURE SPACE, and NBSP arrives by the thousand from any copy-paste out of a
// rendered web page. The intended use — mirroring FoldCompatibilityHomoglyphs —
// is "fold, re-run the plaintext matchers, and report ONLY matches that fire on
// the folded form and not on the raw form". A benign description containing an
// NBSP folds to benign prose that matches no injection pattern, so it produces
// no finding; the finding only exists when folding a separator is what turned
// the text into a known-malicious directive, which is not something benign
// typography does.
func FoldUnicodeSeparators(s string) (folded string, changed bool) {
	// Fast path: every character folded here is non-ASCII, so an all-ASCII input
	// cannot contain one. This keeps the common case a single linear scan with
	// no allocation.
	allASCII := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			allASCII = false
			break
		}
	}
	if allASCII {
		return s, false
	}

	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isFoldableSeparator(r) {
			b.WriteByte(' ')
			changed = true
			continue
		}
		b.WriteRune(r)
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

// isFoldableSeparator reports whether r is a Unicode whitespace/separator
// character that renders as visible horizontal or vertical space but is not in
// RE2's ASCII-only `\s` class.
//
// The list is the union of Unicode General_Category Zs (Space_Separator), Zl
// (Line_Separator) and Zp (Paragraph_Separator), plus U+0085 NEL and U+180E,
// MINUS the ASCII space that `\s` already matches. It is written as an explicit
// switch rather than a unicode.IsSpace call because unicode.IsSpace also returns
// true for the ASCII characters `\t\n\v\f\r `, and folding those would make the
// `changed` gate fire on ordinary multi-line prose — turning a precisely scoped
// evasion detector into a matcher that runs on every description.
func isFoldableSeparator(r rune) bool {
	switch r {
	case '', // NEXT LINE (NEL)
		' ', // NO-BREAK SPACE
		' ', // OGHAM SPACE MARK
		'᠎', // MONGOLIAN VOWEL SEPARATOR (Zs through Unicode 6.2)
		' ', // LINE SEPARATOR
		' ', // PARAGRAPH SEPARATOR
		' ', // NARROW NO-BREAK SPACE
		' ', // MEDIUM MATHEMATICAL SPACE
		'　': // IDEOGRAPHIC SPACE
		return true
	}
	// U+2000–U+200A: EN QUAD, EM QUAD, EN SPACE, EM SPACE, THREE-PER-EM SPACE,
	// FOUR-PER-EM SPACE, SIX-PER-EM SPACE, FIGURE SPACE, PUNCTUATION SPACE,
	// THIN SPACE, HAIR SPACE. Note the range stops at U+200A: U+200B ZERO WIDTH
	// SPACE is deliberately the first codepoint excluded (see the doc comment).
	return r >= ' ' && r <= ' '
}
