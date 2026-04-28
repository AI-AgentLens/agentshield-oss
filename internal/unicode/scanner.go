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

// Scan inspects a command string for Unicode smuggling indicators.
func Scan(input string) ScanResult {
	result := ScanResult{Clean: true}
	var sanitized strings.Builder
	var hexParts []string

	i := 0
	for i < len(input) {
		r, size := utf8.DecodeRuneInString(input[i:])

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

	result.Sanitized = sanitized.String()
	if len(hexParts) > 0 {
		result.RawHex = strings.Join(hexParts, " ")
	}
	return result
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
