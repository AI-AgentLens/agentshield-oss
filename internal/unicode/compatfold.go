package unicode

import "strings"

// FoldCompatibilityHomoglyphs folds the Unicode "compatibility homoglyph"
// blocks down to their ASCII Latin letter / digit equivalents and reports
// whether any fold occurred.
//
// Motivation: the mixed-script detector (Scan / checkHomoglyph) only handles
// Cyrillic and Greek confusables. A separate, equally effective evasion spells
// an injection phrase using characters that are *visually* Latin and that NFKC
// normalization folds to ASCII, but that live in entirely different code
// blocks and so slip past both the ASCII keyword matchers and the
// Cyrillic/Greek homoglyph check:
//
//   - Mathematical Alphanumeric Symbols (U+1D400–U+1D7FF): bold, italic,
//     script, fraktur, double-struck, sans-serif, and monospace letters and
//     digits. "𝐢𝐠𝐧𝐨𝐫𝐞 𝐚𝐥𝐥 𝐩𝐫𝐞𝐯𝐢𝐨𝐮𝐬 𝐢𝐧𝐬𝐭𝐫𝐮𝐜𝐭𝐢𝐨𝐧𝐬" reads as plain English to an
//     LLM tokenizer but matches no ASCII regex.
//   - Halfwidth and Fullwidth Forms (U+FF01–U+FF5E): "ｉｇｎｏｒｅ".
//   - Enclosed Alphanumerics (U+2460–U+24FF): circled letters "ⓘⓖⓝⓞⓡⓔ".
//   - Letterlike Symbols (U+2100–U+214F): the glyphs that occupy the
//     "holes" reserved in the Mathematical block (ℎ, ℊ, ℴ, ℬ, ℋ, …).
//
// This is a focused fold, NOT a full NFKC implementation — it deliberately
// covers only the blocks that fold to ASCII A–Z/a–z/0–9, which are the blocks
// usable for spelling an English injection phrase. CJK compatibility ideographs,
// ligatures, and other NFKC decompositions are out of scope.
//
// The caller decides what to do with the folded text. The intended use is
// "fold, then re-run plaintext matchers, and flag only matches that fire on the
// folded form but not the raw form" — that keeps false positives at zero
// because a benign description that merely *contains* a fullwidth glyph (e.g.
// a stylized "ＡＰＩ") folds to harmless text that matches no injection pattern.
func FoldCompatibilityHomoglyphs(s string) (folded string, changed bool) {
	// Fast path: ASCII-only input cannot contain any compatibility homoglyph.
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
		if folded, ok := foldCompatRune(r); ok {
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

// foldCompatRune maps a single rune from a compatibility-homoglyph block to its
// ASCII equivalent. Returns (asciiRune, true) on a fold, or (r, false) when the
// rune is not a recognised compatibility homoglyph.
func foldCompatRune(r rune) (rune, bool) {
	switch {
	// Halfwidth and Fullwidth Forms.
	case r >= 0xFF21 && r <= 0xFF3A: // Ａ–Ｚ
		return 'A' + (r - 0xFF21), true
	case r >= 0xFF41 && r <= 0xFF5A: // ａ–ｚ
		return 'a' + (r - 0xFF41), true
	case r >= 0xFF10 && r <= 0xFF19: // ０–９
		return '0' + (r - 0xFF10), true

	// Enclosed Alphanumerics — circled letters.
	case r >= 0x24B6 && r <= 0x24CF: // Ⓐ–Ⓩ
		return 'A' + (r - 0x24B6), true
	case r >= 0x24D0 && r <= 0x24E9: // ⓐ–ⓩ
		return 'a' + (r - 0x24D0), true

	// Mathematical Alphanumeric Symbols — 13 Latin alphabets of 52 letters each
	// (26 uppercase then 26 lowercase), laid out contiguously and in order, so a
	// single modulo recovers the position regardless of which style it is. The
	// few reserved "holes" map to the same letter their position implies (and an
	// attacker can only render the hole glyph from the Letterlike block below),
	// so folding them here is harmless.
	case r >= 0x1D400 && r <= 0x1D6A3:
		pos := int(r-0x1D400) % 52
		if pos < 26 {
			return rune('A' + pos), true
		}
		return rune('a' + (pos - 26)), true

	// Mathematical digit styles: bold, double-struck, sans-serif, sans-serif
	// bold, monospace — five contiguous runs of ten, U+1D7CE–U+1D7FF.
	case r >= 0x1D7CE && r <= 0x1D7FF:
		return rune('0' + (int(r-0x1D7CE) % 10)), true
	}

	// Letterlike Symbols — the glyphs Unicode reserves the Mathematical-block
	// holes for. These are exactly the characters an attacker must use to spell
	// the hole positions (e.g. the math-script small "g", "o" and math-italic
	// "h"), so they are required for the fold to be complete on real attacks.
	if l, ok := letterlikeFold[r]; ok {
		return l, true
	}
	return r, false
}

// letterlikeFold maps the letter-bearing characters of the Letterlike Symbols
// block (U+2100–U+214F) to their ASCII equivalents. Only letters are listed;
// symbols such as ™, ℠, № have no ASCII letter form and are intentionally absent.
var letterlikeFold = map[rune]rune{
	0x2102: 'C', // ℂ DOUBLE-STRUCK CAPITAL C
	0x210A: 'g', // ℊ SCRIPT SMALL G
	0x210B: 'H', // ℋ SCRIPT CAPITAL H
	0x210C: 'H', // ℌ BLACK-LETTER CAPITAL H
	0x210D: 'H', // ℍ DOUBLE-STRUCK CAPITAL H
	0x210E: 'h', // ℎ PLANCK CONSTANT (math-italic small h)
	0x2110: 'I', // ℐ SCRIPT CAPITAL I
	0x2111: 'I', // ℑ BLACK-LETTER CAPITAL I
	0x2112: 'L', // ℒ SCRIPT CAPITAL L
	0x2113: 'l', // ℓ SCRIPT SMALL L
	0x2115: 'N', // ℕ DOUBLE-STRUCK CAPITAL N
	0x2119: 'P', // ℙ DOUBLE-STRUCK CAPITAL P
	0x211A: 'Q', // ℚ DOUBLE-STRUCK CAPITAL Q
	0x211B: 'R', // ℛ SCRIPT CAPITAL R
	0x211C: 'R', // ℜ BLACK-LETTER CAPITAL R
	0x211D: 'R', // ℝ DOUBLE-STRUCK CAPITAL R
	0x2124: 'Z', // ℤ DOUBLE-STRUCK CAPITAL Z
	0x2128: 'Z', // ℨ BLACK-LETTER CAPITAL Z
	0x212C: 'B', // ℬ SCRIPT CAPITAL B
	0x212D: 'C', // ℭ BLACK-LETTER CAPITAL C
	0x212F: 'e', // ℯ SCRIPT SMALL E
	0x2130: 'E', // ℰ SCRIPT CAPITAL E
	0x2131: 'F', // ℱ SCRIPT CAPITAL F
	0x2133: 'M', // ℳ SCRIPT CAPITAL M
	0x2134: 'o', // ℴ SCRIPT SMALL O
}
