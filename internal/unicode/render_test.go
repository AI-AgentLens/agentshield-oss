package unicode

import (
	"strings"
	"testing"
	"unicode"
)

// The disguise axes, as \u escapes. A literal degrades to ASCII through an
// editor or a patch, and a test built on a degraded constant passes vacuously.
const (
	tSHY   = "\u00ad" // U+00AD SOFT HYPHEN
	tNBSP  = "\u00a0" // U+00A0 NO-BREAK SPACE
	tZWSP  = "\u200b" // U+200B ZERO WIDTH SPACE
	tALM   = "\u061c" // U+061C ARABIC LETTER MARK
	tCGJ   = "\u034f" // U+034F COMBINING GRAPHEME JOINER
	tFILL  = "\u3164" // U+3164 HANGUL FILLER
	tBRL   = "\u2800" // U+2800 BRAILLE PATTERN BLANK
	tJAMO  = "\u1160" // U+1160 HANGUL JUNGSEONG FILLER
	tVS16  = "\ufe0f" // U+FE0F VARIATION SELECTOR-16
	tIVSEP = "\u2063" // U+2063 INVISIBLE SEPARATOR
)

// TestEscapedConstantsAreNotASCII guards the whole file. Every constant above
// must actually be the non-ASCII codepoint it claims to be; if one degraded to
// an ASCII space or vanished, every test using it would still pass while
// testing nothing. This is the vacuous-pass trap that has bitten this package
// before, so it is asserted rather than assumed.
func TestEscapedConstantsAreNotASCII(t *testing.T) {
	for name, s := range map[string]string{
		"tSHY": tSHY, "tNBSP": tNBSP, "tZWSP": tZWSP, "tALM": tALM, "tCGJ": tCGJ,
		"tFILL": tFILL, "tBRL": tBRL, "tJAMO": tJAMO, "tVS16": tVS16, "tIVSEP": tIVSEP,
	} {
		rs := []rune(s)
		if len(rs) != 1 {
			t.Fatalf("%s: want exactly one rune, got %d", name, len(rs))
		}
		if rs[0] < 0x80 {
			t.Fatalf("%s: degraded to ASCII U+%04X", name, rs[0])
		}
	}
}

func TestRecoverRenderedTextPerAxis(t *testing.T) {
	const want = "ignore all"
	cases := []struct {
		name string
		in   string
	}{
		{"soft hyphen inside words", "ig" + tSHY + "nore all"},
		{"zero width space inside words", "ig" + tZWSP + "nore all"},
		{"arabic letter mark inside words", "ig" + tALM + "nore all"},
		{"combining grapheme joiner", "ig" + tCGJ + "nore all"},
		{"invisible separator", "ig" + tIVSEP + "nore all"},
		{"variation selector", "ig" + tVS16 + "nore all"},
		{"hangul jamo filler", "ig" + tJAMO + "nore all"},
		{"nbsp as word separator", "ignore" + tNBSP + "all"},
		{"hangul filler as word separator", "ignore" + tFILL + "all"},
		{"braille blank as word separator", "ignore" + tBRL + "all"},
		{"fullwidth letters", "\uff49\uff47\uff4e\uff4f\uff52\uff45 all"},
		{"cyrillic confusables", "ign\u043er\u0435 \u0430ll"},
		{"every axis at once", "\uff49\uff47" + tSHY + "\uff4e\uff4f\uff52\uff45" + tNBSP + "\u0430" + tSHY + "ll"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := RecoverRenderedText(tc.in)
			if !changed {
				t.Fatalf("changed=false for %q", tc.in)
			}
			if got != want {
				t.Errorf("recovered %q, want %q", got, want)
			}
		})
	}
}

func TestRecoverRenderedTextLeavesASCIIAlone(t *testing.T) {
	for _, s := range []string{"", "ignore all previous", "rm -rf / && echo done", "a\tb\nc"} {
		got, changed := RecoverRenderedText(s)
		if changed || got != s {
			t.Errorf("RecoverRenderedText(%q) = %q, %v; want unchanged", s, got, changed)
		}
	}
}

// TestRecoverRenderedTextPreservesMeaningfulScripts pins the boundary. Recovery
// exists to undo IMPERSONATION of Latin, not to transliterate the world: a
// genuine non-Latin script must survive, or the fold would turn every
// non-English description into soup and the folded-but-not-raw contract would
// start reporting on noise.
func TestRecoverRenderedTextPreservesMeaningfulScripts(t *testing.T) {
	cases := []struct{ name, in string }{
		// Russian: only the confusables fold; the rest of the alphabet stays.
		{"russian keeps non-confusable letters", "\u0447\u0438\u0442\u0430\u0435\u0442"},
		// Greek: likewise.
		{"greek keeps non-confusable letters", "\u03b4\u03b9\u03b1\u03b2\u03b1\u03b6\u03b5\u03b9"},
		// CJK is not a confusable of anything Latin.
		{"cjk untouched", "\u691c\u7d22\u3057\u307e\u3059"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := RecoverRenderedText(tc.in)
			nonASCII := 0
			for _, r := range got {
				if r >= 0x80 {
					nonASCII++
				}
			}
			if nonASCII == 0 {
				t.Errorf("recovery erased the script entirely: %q -> %q", tc.in, got)
			}
		})
	}
}

// TestRecoverRenderedTextExcludesVisibleCombiningMarks is a scope line, not an
// omission. Splicing U+0301 between letters also defeats a plaintext matcher,
// but the result renders as visibly mangled text, so it is not a
// rendering-identical attack; folding it would cost false positives on every
// accented language for no security gain.
func TestRecoverRenderedTextExcludesVisibleCombiningMarks(t *testing.T) {
	in := "ig\u0301nore"
	got, _ := RecoverRenderedText(in)
	if got == "ignore" {
		t.Error("visible combining marks must NOT be folded; see the doc comment")
	}
}

func TestStripInvisibleFormatters(t *testing.T) {
	in := "ig" + tSHY + "no" + tZWSP + "re" + tALM
	got, changed := StripInvisibleFormatters(in)
	if !changed || got != "ignore" {
		t.Errorf("StripInvisibleFormatters = %q, %v; want %q, true", got, changed, "ignore")
	}
	// A space separator is NOT a zero-advance-width character and must survive.
	if got, changed := StripInvisibleFormatters("a" + tNBSP + "b"); changed || got != "a"+tNBSP+"b" {
		t.Errorf("StripInvisibleFormatters must not touch space separators, got %q", got)
	}
}

func TestFoldConfusables(t *testing.T) {
	got, changed := FoldConfusables("\u0440\u0430\u0455\u0455w\u043erd")
	if !changed || got != "password" {
		t.Errorf("FoldConfusables = %q, %v; want %q, true", got, changed, "password")
	}
	if got, changed := FoldConfusables("plain ascii"); changed || got != "plain ascii" {
		t.Errorf("FoldConfusables must be a no-op on ASCII, got %q %v", got, changed)
	}
}

// TestZeroOrBlankAdvanceWidthCoverage is the anti-drift fitness function.
//
// isZeroWidth was a hand-maintained eight-entry switch, and an exhaustive sweep
// found 67 codepoints that render as nothing-or-blank and defeated both MCP text
// surfaces. A hand list cannot be kept complete, so recovery derives its set
// from Unicode's General Category instead \u2014 and this test is what proves the
// derivation actually covers the category.
//
// It fails if any format character, any named invisible mark, or any
// blank-rendering filler survives recovery intact. Narrowing
// isZeroAdvanceWidth to a hand list turns it red immediately.
func TestZeroOrBlankAdvanceWidthCoverage(t *testing.T) {
	checked := 0
	for r := rune(0x80); r <= 0x10FFFF; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if !unicode.In(r, unicode.Cf) {
			continue
		}
		checked++
		in := "ig" + string(r) + "nore"
		got, _ := RecoverRenderedText(in)
		if strings.ContainsRune(got, r) {
			t.Errorf("U+%04X (Cf) survives recovery: %q", r, got)
		}
	}
	// Positive control: a sweep that checked nothing is not a passing sweep.
	if checked < 100 {
		t.Fatalf("vacuous sweep: only %d format characters examined", checked)
	}

	for _, r := range []rune{0x034F, 0x17B4, 0x17B5, 0x180B, 0x180C, 0x180D,
		0x115F, 0x1160, 0xFE00, 0xFE0F, 0xE0100} {
		if got, _ := RecoverRenderedText("ig" + string(r) + "nore"); got != "ignore" {
			t.Errorf("U+%04X must be removed by recovery, got %q", r, got)
		}
	}
	for _, r := range []rune{0x3164, 0xFFA0, 0x2800} {
		if got, _ := RecoverRenderedText("ignore" + string(r) + "all"); got != "ignore all" {
			t.Errorf("U+%04X must fold to a space, got %q", r, got)
		}
	}
}

// TestConfusableFoldMatchesPresenceTable pins the invariant that makes the two
// mechanisms impossible to disagree: every rune the presence-based classifier
// calls a Cyrillic/Greek confusable must also be foldable, because they read
// the same tables.
func TestConfusableFoldMatchesPresenceTable(t *testing.T) {
	for r := range cyrillicHomoglyphs {
		if _, ok := foldConfusableRune(r); !ok {
			t.Errorf("U+%04X is in cyrillicHomoglyphs but does not fold", r)
		}
	}
	for r := range greekHomoglyphs {
		if _, ok := foldConfusableRune(r); !ok {
			t.Errorf("U+%04X is in greekHomoglyphs but does not fold", r)
		}
	}
}
