package unicode

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Threat represents a detected Unicode smuggling threat.
type Threat struct {
	Category    string // e.g. "zero-width", "bidi-override", "homoglyph", "control-char", "tag-char"
	Description string
	Position    int    // byte offset in the input
	Codepoint   string // e.g. "U+200B"
	Severity    string // "block" or "audit"
}

// ScanResult holds the output of a Unicode scan.
type ScanResult struct {
	Clean   bool     // true if no threats found
	Threats []Threat
	// Sanitized is the input with dangerous characters removed/replaced.
	Sanitized string
	// RawHex is a hex dump of non-ASCII bytes for forensic logging.
	RawHex string
}

// variationSelectorRunThreshold is the minimum number of consecutive variation
// selectors that constitutes a covert steganographic channel rather than a
// legitimate glyph variant. Legitimate text applies at most ONE variation
// selector to a base character (VS16 emoji presentation, a single CJK IVS, a
// single Mongolian FVS); it never chains them. Butler's "emoji smuggling"
// technique (2024) encodes one hidden byte per selector, so any real payload is
// a long run. A threshold of 3 is immune to every legitimate single/double use
// while still catching the smallest meaningful hidden message.
const variationSelectorRunThreshold = 3

// Scan inspects a command string for Unicode smuggling indicators.
func Scan(input string) ScanResult {
	result := ScanResult{Clean: true}
	var sanitized strings.Builder
	var hexParts []string

	hostRanges := findURLHostRanges(input)

	// Variation-selector run accumulator. Variation selectors (U+FE00–FE0F,
	// the Variation Selectors Supplement U+E0100–E01EF, and the Mongolian Free
	// Variation Selectors U+180B–180D) render invisibly and carry no semantic
	// content of their own, so a run of them is a covert channel: each selector
	// encodes a byte an LLM can be instructed to decode, while the host displays
	// only the single base glyph. A run is collected as a unit and flushed when a
	// non-selector rune (or end of input) is reached.
	vsRunCount := 0
	vsRunStart := 0
	var vsRunFirst rune
	var vsRunBuf strings.Builder
	flushVSRun := func() {
		if vsRunCount == 0 {
			return
		}
		if vsRunCount >= variationSelectorRunThreshold {
			result.Clean = false
			result.Threats = append(result.Threats, Threat{
				Category: "variation-selector",
				Description: fmt.Sprintf(
					"Run of %d consecutive variation selectors (first %s) — covert steganographic channel; each selector encodes a hidden byte the model can decode while the text renders as a single visible glyph",
					vsRunCount, fmt.Sprintf("U+%04X", vsRunFirst),
				),
				Position:  vsRunStart,
				Codepoint: fmt.Sprintf("U+%04X", vsRunFirst),
				Severity:  "block",
			})
			// Dangerous run is stripped from the sanitized output.
		} else {
			// Sub-threshold run is a legitimate glyph variant — preserve it.
			sanitized.WriteString(vsRunBuf.String())
		}
		vsRunCount = 0
		vsRunBuf.Reset()
	}

	i := 0
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])

		// Accumulate variation-selector runs before any other classification so
		// the run is judged as a whole rather than character-by-character.
		if isVariationSelector(r) {
			if vsRunCount == 0 {
				vsRunStart = i
				vsRunFirst = r
			}
			vsRunCount++
			vsRunBuf.WriteRune(r)
			hexParts = append(hexParts, fmt.Sprintf("U+%04X", r))
			i += size
			continue
		}
		// Any non-selector rune terminates a pending run.
		flushVSRun()

		if r == utf8.RuneError && size == 1 {
			result.Clean = false
			result.Threats = append(result.Threats, Threat{
				Category:    "invalid-utf8",
				Description: "Invalid UTF-8 byte sequence",
				Position:    i,
				Codepoint:   fmt.Sprintf("0x%02X", input[i]),
				Severity:    "block",
			})
			hexParts = append(hexParts, fmt.Sprintf("%02X", input[i]))
			i++
			continue
		}

		if threat, found := classifyRune(r, i); found {
			// Homoglyph inside a URL host is unambiguously an IDN impersonation
			// attack — escalate from audit to block. Homoglyphs in benign
			// contexts (commit messages, comments, JSON values) stay at audit.
			if (threat.Category == "homoglyph-cyrillic" || threat.Category == "homoglyph-greek") && positionInRanges(i, hostRanges) {
				threat.Severity = "block"
				threat.Description = "URL host contains " + threat.Description + " — IDN homoglyph attack against the network endpoint"
			}
			result.Clean = false
			result.Threats = append(result.Threats, threat)
			// Don't include dangerous chars in sanitized output
			hexParts = append(hexParts, fmt.Sprintf("U+%04X", r))
			i += size
			continue
		}

		// Track non-ASCII for forensic logging
		if r > 127 {
			hexParts = append(hexParts, fmt.Sprintf("U+%04X", r))
		}

		sanitized.WriteRune(r)
		i += size
	}
	// Flush a variation-selector run that extends to the end of the input.
	flushVSRun()

	result.Sanitized = sanitized.String()
	if len(hexParts) > 0 {
		result.RawHex = strings.Join(hexParts, " ")
	}
	return result
}

// findURLHostRanges returns byte ranges in input that lie inside the host
// portion of any http://, https://, ftp://, ssh://, git:// or similar URL.
// The host extends from the byte after `://` up to (but not including) the
// next `/`, whitespace, quote, or terminator. Used by Scan to escalate
// homoglyph severity when the homoglyph targets a network endpoint.
func findURLHostRanges(input string) [][2]int {
	var ranges [][2]int
	idx := 0
	for {
		rel := strings.Index(input[idx:], "://")
		if rel < 0 {
			break
		}
		start := idx + rel + 3
		end := start
		for end < len(input) {
			b := input[end]
			if b == '/' || b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '"' || b == '\'' || b == '`' || b == ')' || b == ';' || b == '|' || b == '&' || b == '?' || b == '#' {
				break
			}
			end++
		}
		if end > start {
			ranges = append(ranges, [2]int{start, end})
		}
		idx = end
	}
	return ranges
}

func positionInRanges(pos int, ranges [][2]int) bool {
	for _, r := range ranges {
		if pos >= r[0] && pos < r[1] {
			return true
		}
	}
	return false
}

func classifyRune(r rune, pos int) (Threat, bool) {
	cp := fmt.Sprintf("U+%04X", r)

	// Zero-width characters — invisible, used to bypass text matching
	if isZeroWidth(r) {
		return Threat{
			Category:    "zero-width",
			Description: fmt.Sprintf("Zero-width character %s can hide content from display", cp),
			Position:    pos,
			Codepoint:   cp,
			Severity:    "block",
		}, true
	}

	// Bidirectional override characters — make displayed text differ from logical text
	if isBidiOverride(r) {
		return Threat{
			Category:    "bidi-override",
			Description: fmt.Sprintf("Bidirectional override %s can make displayed text differ from executed text", cp),
			Position:    pos,
			Codepoint:   cp,
			Severity:    "block",
		}, true
	}

	// Unicode tag characters (U+E0001–U+E007F) — hidden metadata smuggling
	if isTagCharacter(r) {
		return Threat{
			Category:    "tag-char",
			Description: fmt.Sprintf("Unicode tag character %s can smuggle hidden instructions", cp),
			Position:    pos,
			Codepoint:   cp,
			Severity:    "block",
		}, true
	}

	// Control characters (excluding tab, newline, carriage return)
	if isUnsafeControl(r) {
		return Threat{
			Category:    "control-char",
			Description: fmt.Sprintf("Control character %s should not appear in commands", cp),
			Position:    pos,
			Codepoint:   cp,
			Severity:    "block",
		}, true
	}

	// Homoglyph detection — Cyrillic/Greek letters that look like Latin
	if cat, desc := checkHomoglyph(r); cat != "" {
		return Threat{
			Category:    cat,
			Description: desc,
			Position:    pos,
			Codepoint:   cp,
			Severity:    "audit",
		}, true
	}

	return Threat{}, false
}

func isZeroWidth(r rune) bool {
	switch r {
	case '\u200B', // ZERO WIDTH SPACE
		'\u200C', // ZERO WIDTH NON-JOINER
		'\u200D', // ZERO WIDTH JOINER
		'\uFEFF', // ZERO WIDTH NO-BREAK SPACE (BOM)
		'\u2060', // WORD JOINER
		'\u180E', // MONGOLIAN VOWEL SEPARATOR
		'\u200E', // LEFT-TO-RIGHT MARK
		'\u200F': // RIGHT-TO-LEFT MARK
		return true
	}
	return false
}

func isBidiOverride(r rune) bool {
	switch r {
	case '\u202A', // LEFT-TO-RIGHT EMBEDDING
		'\u202B', // RIGHT-TO-LEFT EMBEDDING
		'\u202C', // POP DIRECTIONAL FORMATTING
		'\u202D', // LEFT-TO-RIGHT OVERRIDE
		'\u202E', // RIGHT-TO-LEFT OVERRIDE
		'\u2066', // LEFT-TO-RIGHT ISOLATE
		'\u2067', // RIGHT-TO-LEFT ISOLATE
		'\u2068', // FIRST STRONG ISOLATE
		'\u2069': // POP DIRECTIONAL ISOLATE
		return true
	}
	return false
}

func isTagCharacter(r rune) bool {
	return r >= 0xE0001 && r <= 0xE007F
}

// isVariationSelector reports whether r is a Unicode variation selector. These
// are zero-advance-width format characters that select a glyph variant of the
// preceding base character. They carry no standalone meaning, so chaining many
// of them (see variationSelectorRunThreshold) is never legitimate — it is the
// "emoji smuggling" steganographic channel that hides bytes from human display
// while remaining tokenizable by an LLM.
//
//   - U+FE00–U+FE0F   Variation Selectors (VS1–VS16; VS16 is emoji presentation)
//   - U+E0100–U+E01EF Variation Selectors Supplement (VS17–VS256; CJK IVD)
//   - U+180B–U+180D   Mongolian Free Variation Selectors (FVS1–FVS3)
//
// U+180E (Mongolian Vowel Separator) is intentionally excluded here — it is
// already classified as zero-width.
func isVariationSelector(r rune) bool {
	switch {
	case r >= 0xFE00 && r <= 0xFE0F:
		return true
	case r >= 0xE0100 && r <= 0xE01EF:
		return true
	case r >= 0x180B && r <= 0x180D:
		return true
	}
	return false
}

func isUnsafeControl(r rune) bool {
	// Allow tab (0x09), newline (0x0A), carriage return (0x0D)
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	// C0 control characters
	if r >= 0x00 && r <= 0x1F {
		return true
	}
	// DEL
	if r == 0x7F {
		return true
	}
	// C1 control characters
	if r >= 0x80 && r <= 0x9F {
		return true
	}
	return false
}

// checkHomoglyph detects characters from non-Latin scripts that visually
// resemble Latin letters — a technique used in IDN homograph attacks
// and code confusion attacks.
func checkHomoglyph(r rune) (category string, description string) {
	cp := fmt.Sprintf("U+%04X", r)

	// Cyrillic homoglyphs of Latin letters
	if unicode.Is(unicode.Cyrillic, r) {
		if confusable, ok := cyrillicHomoglyphs[r]; ok {
			return "homoglyph-cyrillic",
				fmt.Sprintf("Cyrillic %s looks like Latin '%c' — possible homoglyph attack", cp, confusable)
		}
	}

	// Greek homoglyphs
	if unicode.Is(unicode.Greek, r) {
		if confusable, ok := greekHomoglyphs[r]; ok {
			return "homoglyph-greek",
				fmt.Sprintf("Greek %s looks like Latin '%c' — possible homoglyph attack", cp, confusable)
		}
	}

	// Compatibility homoglyphs — Fullwidth Latin (Ａ–Ｚ), Mathematical Alphanumeric
	// Symbols (𝐀, 𝗌), Enclosed Alphanumerics (Ⓐ), and Letterlike Symbols (ℋ) that
	// NFKC folds to an ASCII A–Z/a–z/0–9. They live in non-Latin code blocks yet
	// read as Latin to a human (fullwidth/enclosed) or to an LLM tokenizer (math
	// styles), so in an ASCII identifier — a tool, server, or prompt name — they
	// are pure impersonation. This category is consumed only by the name-surface
	// scanners (tool names must be ASCII identifiers); the description-prose
	// scanners filter by category, so a stylized glyph in legitimate i18n prose
	// (fullwidth digits, a math formula) never produces a finding here. Genuine
	// non-Latin scripts (CJK, Arabic) and accented Latin do not fold and stay clean.
	if folded, ok := foldCompatRune(r); ok && folded != r {
		return "homoglyph-compat",
			fmt.Sprintf("%s folds to ASCII '%c' — compatibility homoglyph (fullwidth/mathematical/enclosed/letterlike) impersonating a Latin character", cp, folded)
	}

	return "", ""
}

// Cyrillic characters that are visually confusable with Latin characters
var cyrillicHomoglyphs = map[rune]rune{
	'а': 'a', // CYRILLIC SMALL LETTER A
	'А': 'A', // CYRILLIC CAPITAL LETTER A
	'В': 'B', // CYRILLIC CAPITAL LETTER VE
	'с': 'c', // CYRILLIC SMALL LETTER ES
	'С': 'C', // CYRILLIC CAPITAL LETTER ES
	'е': 'e', // CYRILLIC SMALL LETTER IE
	'Е': 'E', // CYRILLIC CAPITAL LETTER IE
	'Н': 'H', // CYRILLIC CAPITAL LETTER EN
	'і': 'i', // CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I
	'І': 'I', // CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I
	'К': 'K', // CYRILLIC CAPITAL LETTER KA
	'М': 'M', // CYRILLIC CAPITAL LETTER EM
	'о': 'o', // CYRILLIC SMALL LETTER O
	'О': 'O', // CYRILLIC CAPITAL LETTER O
	'р': 'p', // CYRILLIC SMALL LETTER ER
	'Р': 'P', // CYRILLIC CAPITAL LETTER ER
	'Т': 'T', // CYRILLIC CAPITAL LETTER TE
	'х': 'x', // CYRILLIC SMALL LETTER HA
	'Х': 'X', // CYRILLIC CAPITAL LETTER HA
	'у': 'y', // CYRILLIC SMALL LETTER U
	'У': 'Y', // CYRILLIC CAPITAL LETTER U
}

// Greek characters that are visually confusable with Latin characters
var greekHomoglyphs = map[rune]rune{
	'Α': 'A', // GREEK CAPITAL LETTER ALPHA
	'Β': 'B', // GREEK CAPITAL LETTER BETA
	'Ε': 'E', // GREEK CAPITAL LETTER EPSILON
	'Η': 'H', // GREEK CAPITAL LETTER ETA
	'Ι': 'I', // GREEK CAPITAL LETTER IOTA
	'Κ': 'K', // GREEK CAPITAL LETTER KAPPA
	'Μ': 'M', // GREEK CAPITAL LETTER MU
	'Ν': 'N', // GREEK CAPITAL LETTER NU
	'Ο': 'O', // GREEK CAPITAL LETTER OMICRON
	'ο': 'o', // GREEK SMALL LETTER OMICRON
	'Ρ': 'P', // GREEK CAPITAL LETTER RHO
	'Τ': 'T', // GREEK CAPITAL LETTER TAU
	'Χ': 'X', // GREEK CAPITAL LETTER CHI
	'Υ': 'Y', // GREEK CAPITAL LETTER UPSILON
	'Ζ': 'Z', // GREEK CAPITAL LETTER ZETA
}
