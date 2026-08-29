package unicode

import (
	"regexp"
	"strings"
	"testing"
)

// TestRE2WhitespaceClassIsASCIIOnly is the premise the whole detector rests on.
// If a future Go release widened `\s` to Unicode, FoldUnicodeSeparators would be
// dead weight rather than a control, and nothing else in the tree would notice.
// Pin it here so the assumption fails loudly instead of silently.
func TestRE2WhitespaceClassIsASCIIOnly(t *testing.T) {
	re := regexp.MustCompile(`a\s+b`)
	if !re.MatchString("a b") {
		t.Fatal("premise broken: RE2 \\s must match the ASCII space")
	}
	for _, r := range []rune{' ', ' ', '　', ' ', ' '} {
		if re.MatchString("a" + string(r) + "b") {
			t.Fatalf("premise broken: RE2 \\s now matches U+%04X — "+
				"FoldUnicodeSeparators may be redundant, re-evaluate the detector", r)
		}
	}
}

func TestFoldUnicodeSeparators_FoldsEveryTargetedRune(t *testing.T) {
	targets := []struct {
		name string
		r    rune
	}{
		{"U+0085 NEL", ''},
		{"U+00A0 NO-BREAK SPACE", ' '},
		{"U+1680 OGHAM SPACE MARK", ' '},
		{"U+180E MONGOLIAN VOWEL SEPARATOR", '᠎'},
		{"U+2000 EN QUAD", ' '},
		{"U+2001 EM QUAD", ' '},
		{"U+2002 EN SPACE", ' '},
		{"U+2003 EM SPACE", ' '},
		{"U+2004 THREE-PER-EM", ' '},
		{"U+2005 FOUR-PER-EM", ' '},
		{"U+2006 SIX-PER-EM", ' '},
		{"U+2007 FIGURE SPACE", ' '},
		{"U+2008 PUNCTUATION SPACE", ' '},
		{"U+2009 THIN SPACE", ' '},
		{"U+200A HAIR SPACE", ' '},
		{"U+2028 LINE SEPARATOR", ' '},
		{"U+2029 PARAGRAPH SEPARATOR", ' '},
		{"U+202F NARROW NO-BREAK SPACE", ' '},
		{"U+205F MEDIUM MATHEMATICAL SPACE", ' '},
		{"U+3000 IDEOGRAPHIC SPACE", '　'},
	}
	for _, tc := range targets {
		t.Run(tc.name, func(t *testing.T) {
			in := "alpha" + string(tc.r) + "beta"
			got, changed := FoldUnicodeSeparators(in)
			if !changed {
				t.Fatalf("expected changed=true for U+%04X", tc.r)
			}
			if got != "alpha beta" {
				t.Fatalf("U+%04X: got %q, want %q", tc.r, got, "alpha beta")
			}
		})
	}
}

// The zero-width class is deliberately NOT folded — it is caught by the
// invisible-control detector, and folding it to a SPACE would be the wrong
// transform (it splits words rather than separating them). This test is the
// boundary marker: U+200A folds, U+200B does not.
func TestFoldUnicodeSeparators_ExcludesZeroWidthAndASCII(t *testing.T) {
	excluded := []struct {
		name string
		r    rune
	}{
		{"U+200B ZERO WIDTH SPACE", '\u200b'},
		{"U+200C ZERO WIDTH NON-JOINER", '\u200c'},
		{"U+200D ZERO WIDTH JOINER", '\u200d'},
		{"U+200E LEFT-TO-RIGHT MARK", '\u200e'},
		{"U+200F RIGHT-TO-LEFT MARK", '\u200f'},
		{"U+202E RIGHT-TO-LEFT OVERRIDE", '\u202e'},
		{"U+2060 WORD JOINER", '\u2060'},
		{"U+FEFF BOM", '\ufeff'},
		{"ASCII tab", '\t'},
		{"ASCII newline", '\n'},
		{"ASCII carriage return", '\r'},
		{"ASCII vertical tab", '\v'},
		{"ASCII form feed", '\f'},
		{"ASCII space", ' '},
	}
	for _, tc := range excluded {
		t.Run(tc.name, func(t *testing.T) {
			in := "alpha" + string(tc.r) + "beta"
			got, changed := FoldUnicodeSeparators(in)
			if changed {
				t.Fatalf("U+%04X must NOT fold (got %q) — see the doc comment for why", tc.r, got)
			}
			if got != in {
				t.Fatalf("unchanged input must be returned verbatim: got %q", got)
			}
		})
	}
}

func TestFoldUnicodeSeparators_ASCIIFastPath(t *testing.T) {
	in := "read the file and return its contents\tquickly\n"
	got, changed := FoldUnicodeSeparators(in)
	if changed {
		t.Fatal("pure-ASCII input must report changed=false")
	}
	if got != in {
		t.Fatalf("pure-ASCII input must be returned verbatim: got %q", got)
	}
}

// Non-ASCII text that contains no separator must not report a change — the
// `changed` flag is the gate the detector uses to scope itself, so a false
// positive here would run the whole re-match pass on every non-English
// description.
func TestFoldUnicodeSeparators_NonASCIINonSeparatorUnchanged(t *testing.T) {
	for _, in := range []string{
		"Lit le fichier et renvoie son contenu",           // accented Latin
		"ファイルを読み取って内容を返します",                            // Japanese, no U+3000
		"Читает файл и возвращает содержимое",             // Cyrillic
		"Reads a file — returns its contents (≤ 1 MiB) ✓", // punctuation/symbols
	} {
		got, changed := FoldUnicodeSeparators(in)
		if changed {
			t.Fatalf("no separator present but changed=true for %q -> %q", in, got)
		}
	}
}

func TestFoldUnicodeSeparators_MixedAndRepeated(t *testing.T) {
	in := "a b c　d ready"
	got, changed := FoldUnicodeSeparators(in)
	if !changed {
		t.Fatal("expected changed=true")
	}
	if got != "a b c d ready" {
		t.Fatalf("got %q, want %q", got, "a b c d ready")
	}
	if strings.ContainsRune(got, ' ') {
		t.Fatal("fold left a NBSP behind")
	}
}

func TestFoldUnicodeSeparators_Empty(t *testing.T) {
	got, changed := FoldUnicodeSeparators("")
	if changed || got != "" {
		t.Fatalf("empty input: got (%q, %v)", got, changed)
	}
}
