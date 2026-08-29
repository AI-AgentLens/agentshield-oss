package unicode

import (
	"strings"
	"unicode"
)

// RecoverRenderedText returns the text a human actually reads on screen, and
// reports whether recovering it changed anything.
//
// It is the composition of every codepoint-level disguise this package folds
// individually — invisible formatters, Unicode separators, compatibility
// homoglyphs and Cyrillic/Greek confusables — applied in a single pass. The
// caller's contract is the one every fold in this package shares: fold, re-run
// the plaintext matchers, and report ONLY findings that fire on the recovered
// form and not on the raw form.
//
// # Why a composed recovery, and not another fold
//
// The shipped defences are organised one-axis-per-pass, and an attacker is not
// obliged to pick one axis. Measured against the MCP description scanner (28
// signals) and the tool-response scanner on 2026-08-19, spelling one override
// directive eight different ways:
//
//	spelling                        description surface   response surface
//	ASCII                           hidden_instructions   1 finding
//	U+00A0 separators               separator_evasion     1 finding
//	fullwidth letters               separator_evasion     0
//	Cyrillic confusables x6         mixed_script          0
//	U+00AD soft hyphen in words     0                     0
//	NBSP + soft hyphen              0                     0
//	fullwidth + soft hyphen         0                     0
//	all four axes at once           0                     0
//
// Two distinct failures are visible there. The first is a missing character
// class: U+00AD renders as nothing, is not in RE2's ASCII-only `\s`, and is not
// in the hand-written zero-width list, so it defeats both surfaces on its own.
// The second is compositional: fullwidth alone and Cyrillic alone are each
// caught, yet combining them with a soft hyphen is clean — because each pass
// folds its own axis and then matches, so a residue from any other axis leaves
// the pattern unmatched. Adding a fifth single-axis pass would not fix that.
// Recovering all axes at once does, and it covers the axes' 2^n combinations
// for free.
//
// # The completeness argument for the invisible set
//
// isZeroWidth is a hand-maintained eight-entry switch, which is the shape this
// codebase has repeatedly found drifting (see proseDetectorsForFold in
// internal/mcp/description_scanner.go). An exhaustive sweep of the 181
// codepoints that render as nothing-or-blank found 67 that defeated BOTH MCP
// surfaces and 84 that defeated the response surface — including U+061C ARABIC
// LETTER MARK, the direct sibling of U+200E/U+200F which the list does carry,
// and U+2061-U+2064, which internal/guardian already treats as steganography on
// the shell surface. So the set here is derived from Unicode's own General
// Category rather than enumerated by hand: every Cf is a format character that
// renders as nothing, by definition, and the category cannot silently omit a
// codepoint added in a later Unicode revision.
//
// # Advance width decides remove-vs-space
//
// The recovery is trying to reproduce what a human sees, so a character is
// removed when it occupies no horizontal space and folded to an ASCII space
// when it occupies one cell. That is why the Hangul JAMO fillers (U+115F,
// U+1160 — zero-width in every shaping engine) are removed while HANGUL FILLER
// (U+3164), its halfwidth form (U+FFA0) and BRAILLE PATTERN BLANK (U+2800) fold
// to a space: all three render as one blank cell and are the classic
// blank-that-is-a-letter used for identifier spoofing.
//
// # False-positive safety
//
// This recovery is deliberately more aggressive than any single shipped fold —
// notably it folds Cyrillic and Greek to Latin with no "is this text mostly
// Latin?" guard. That is safe only because of the folded-but-not-raw contract,
// and it is what makes the recovery correct where a ratio guard is not:
// internal/mcp's mixed-script check exempts text below 80% ASCII letters so it
// does not fire on Russian prose, which means an attacker who substitutes MORE
// confusables buys MORE exemption — measured, a directive with 8 of 10 letter
// classes substituted scans completely clean while the same directive with 7
// substituted is caught. A presence-of-confusables signal needs that guard; a
// fold-and-rematch signal does not, because the finding requires the recovered
// text to match a specific malicious English directive. Ordinary Russian prose
// does not recover into an override directive; only a letter-for-letter
// homoglyph transliteration of one does, and that is the attack.
func RecoverRenderedText(s string) (recovered string, changed bool) {
	// Fast path: every character this function touches is non-ASCII, so an
	// all-ASCII input is already its own rendering.
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return recoverRenderedSlow(s)
		}
	}
	return s, false
}

func recoverRenderedSlow(s string) (string, bool) {
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	for _, r := range s {
		if r < 0x80 {
			b.WriteRune(r)
			continue
		}
		// Separators first: U+180E is both a format character and a historical
		// Zs, and FoldUnicodeSeparators' reading of it as a space is the one
		// this package already ships.
		if isFoldableSeparator(r) || isBlankAdvanceWidth(r) {
			b.WriteByte(' ')
			changed = true
			continue
		}
		if isZeroAdvanceWidth(r) {
			changed = true
			continue
		}
		if folded, ok := foldCompatRune(r); ok && folded != r {
			b.WriteRune(folded)
			changed = true
			continue
		}
		if folded, ok := foldConfusableRune(r); ok {
			b.WriteRune(folded)
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

// isZeroAdvanceWidth reports whether r renders in no horizontal space at all,
// so that deleting it reproduces what the reader sees.
//
// The bulk of the set is General_Category Cf (Format), taken as a category
// rather than a list precisely so it cannot drift; the named exceptions below
// are the non-Cf characters that also render at zero width.
func isZeroAdvanceWidth(r rune) bool {
	if unicode.In(r, unicode.Cf) {
		// U+180E is handled as a separator (see recoverRenderedSlow).
		return r != '\u180e'
	}
	switch r {
	case '\u034f', // COMBINING GRAPHEME JOINER — invisible, purely a collation hint
		'\u17b4', // KHMER VOWEL INHERENT AQ — invisible in modern shaping
		'\u17b5', // KHMER VOWEL INHERENT AA — invisible in modern shaping
		'\u180b', // MONGOLIAN FREE VARIATION SELECTOR ONE
		'\u180c', // MONGOLIAN FREE VARIATION SELECTOR TWO
		'\u180d', // MONGOLIAN FREE VARIATION SELECTOR THREE
		'\u115f', // HANGUL CHOSEONG FILLER — zero-width in every shaping engine
		'\u1160': // HANGUL JUNGSEONG FILLER — likewise
		return true
	}
	// Variation selectors: U+FE00-FE0F and the Variation Selectors Supplement.
	// A run of these is already a BLOCK-severity finding in Scan; removing them
	// here additionally recovers the text when a SINGLE selector — below that
	// run threshold, and therefore deliberately not a finding on its own — has
	// been spliced between letters to break a keyword match.
	if r >= '\ufe00' && r <= '\ufe0f' {
		return true
	}
	return r >= 0xE0100 && r <= 0xE01EF
}

// isBlankAdvanceWidth reports whether r renders as one blank cell without being
// a Unicode space separator. These are the "blank that is a letter or symbol"
// characters — the ones that pass an is-this-a-space check, an is-this-invisible
// check, and RE2's `\s` alike, which is what makes them useful for identifier
// spoofing and for standing in as a word separator.
func isBlankAdvanceWidth(r rune) bool {
	switch r {
	case '\u3164', // HANGUL FILLER — General_Category Lo: a *letter* that renders blank
		'\uffa0', // HALFWIDTH HANGUL FILLER
		'\u2800': // BRAILLE PATTERN BLANK — General_Category So, renders blank
		return true
	}
	return false
}

// StripInvisibleFormatters removes every zero-advance-width character from s.
//
// Exposed separately from RecoverRenderedText because "what did the attacker
// hide between these letters" is a question worth asking on its own — a caller
// that wants to report the invisible splice without also folding scripts and
// homoglyphs uses this.
func StripInvisibleFormatters(s string) (stripped string, changed bool) {
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
		if r >= 0x80 && isZeroAdvanceWidth(r) {
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

// FoldConfusables folds Cyrillic and Greek homoglyphs of Latin letters down to
// the Latin letter they impersonate, and reports whether any fold occurred.
//
// It reuses the same cyrillicHomoglyphs / greekHomoglyphs tables that
// checkHomoglyph reports on, so the two can never disagree about what a
// confusable is: one adds a character to the tables and both the presence
// signal and the fold learn it at once.
func FoldConfusables(s string) (folded string, changed bool) {
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
		if latin, ok := foldConfusableRune(r); ok {
			b.WriteRune(latin)
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

func foldConfusableRune(r rune) (rune, bool) {
	if r < 0x80 {
		return r, false
	}
	if unicode.Is(unicode.Cyrillic, r) {
		if latin, ok := cyrillicHomoglyphs[r]; ok {
			return latin, true
		}
		return r, false
	}
	if unicode.Is(unicode.Greek, r) {
		if latin, ok := greekHomoglyphs[r]; ok {
			return latin, true
		}
	}
	return r, false
}
