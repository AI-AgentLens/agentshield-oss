package mcp

import (
	"strings"
	"testing"
)

// nonTextOverrideWords builds the override-directive words nonTextInjectionRe
// matches (`\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b`), from
// fragments so no contiguous injection phrase appears in this source file.
// fieldVal is lowercased before matching, so case is not load-bearing here.
func nonTextOverrideWords() []string {
	return []string{"ig" + "nore", "previous", "instructions"}
}

func nonTextPhrase(sep string, parts ...string) string { return strings.Join(parts, sep) }

func scanNonTextName(name string) NonTextContentScanResult {
	items := []ContentItem{{Type: "resource_link", URI: "https://docs.example/report.pdf", Name: name}}
	return ScanNonTextContentBlocks(items)
}

func scanNonTextDescription(desc string) NonTextContentScanResult {
	items := []ContentItem{{Type: "resource", Description: desc, Resource: &ResourceContentItem{URI: "https://docs.example/report.pdf"}}}
	return ScanNonTextContentBlocks(items)
}

// TestNonTextContentSeparatorFold_TP_NameFieldNBSPRecovered: a resource_link
// block's `name` is shown to the user in a consent dialog AND to the LLM
// during tool-result listing — the dual-surface property that makes this
// scanner exist, since text scanners never see non-text content blocks at
// all. Before this pass, an override directive separated by U+00A0 fired in
// ASCII and matched nothing here, so the one check this field gets was
// bypassed by a single non-ASCII byte.
func TestNonTextContentSeparatorFold_TP_NameFieldNBSPRecovered(t *testing.T) {
	const nbsp = " "

	ascii := scanNonTextName(nonTextPhrase(" ", nonTextOverrideWords()...))
	if !ascii.Blocked {
		t.Fatalf("VACUOUS: ASCII override-directive control did not fire: %+v", ascii.Findings)
	}

	var raw NonTextContentScanResult
	scanNonTextInjectionField(&raw, 0, "resource_link", "name", nonTextPhrase(nbsp, nonTextOverrideWords()...))
	if len(raw.Findings) != 0 {
		t.Fatalf("raw scan unexpectedly matched NBSP-separated override directive: %+v", raw.Findings)
	}

	folded := scanNonTextName(nonTextPhrase(nbsp, nonTextOverrideWords()...))
	if !folded.Blocked {
		t.Fatal("NBSP-separated override directive in resource_link name was not detected — the fold did not recover it")
	}
}

// TestNonTextContentSeparatorFold_TP_DescriptionFieldNBSPRecovered proves the
// fold covers both scanned fields, not just `name`.
func TestNonTextContentSeparatorFold_TP_DescriptionFieldNBSPRecovered(t *testing.T) {
	const nbsp = " "

	ascii := scanNonTextDescription(nonTextPhrase(" ", nonTextOverrideWords()...))
	if !ascii.Blocked {
		t.Fatalf("VACUOUS: ASCII override-directive control did not fire on description: %+v", ascii.Findings)
	}

	folded := scanNonTextDescription(nonTextPhrase(nbsp, nonTextOverrideWords()...))
	if !folded.Blocked {
		t.Fatal("NBSP-separated override directive in resource description was not detected")
	}
}

// TestNonTextContentSeparatorFold_AttributionAndSubtraction mirrors
// TestResponseSeparatorFold_AttributionAndSubtraction: ASCII findings never
// carry the fold-attribution suffix, NBSP findings always do.
func TestNonTextContentSeparatorFold_AttributionAndSubtraction(t *testing.T) {
	const nbsp = " "

	ascii := scanNonTextName(nonTextPhrase(" ", nonTextOverrideWords()...))
	for _, f := range ascii.Findings {
		if strings.Contains(f.Detail, "recovered by folding") {
			t.Fatalf("ASCII text produced a fold-attributed finding: %s", f.Detail)
		}
	}

	folded := scanNonTextName(nonTextPhrase(nbsp, nonTextOverrideWords()...))
	var attributed bool
	for _, f := range folded.Findings {
		if strings.Contains(f.Detail, "recovered by folding") {
			attributed = true
		}
	}
	if !attributed {
		t.Fatal("NBSP-recovered finding must be attributed to the separator fold")
	}
}

// ---------------------------------------------------------------------------
// True negatives — legitimate Unicode spacing in ordinary resource names and
// descriptions must not be turned into a finding by the fold.
// ---------------------------------------------------------------------------

func assertNonTextTN(t *testing.T, name, fieldVal string, useDescription bool) {
	t.Helper()

	ascii := fieldVal
	for _, sep := range []string{" ", "　", " ", " ", " ", " "} {
		ascii = strings.ReplaceAll(ascii, sep, " ")
	}
	scan := scanNonTextName
	if useDescription {
		scan = scanNonTextDescription
	}
	if res := scan(ascii); res.Blocked {
		t.Fatalf("%s: INVALID TRUE NEGATIVE — the ASCII-spaced rendering already blocks, "+
			"so it cannot demonstrate anything about the separator fold: %+v", name, res.Findings)
	}

	if res := scan(fieldVal); res.Blocked {
		t.Fatalf("%s: false positive on benign field value: %+v", name, res.Findings)
	}
}

// A Japanese report title in a resource_link name — U+3000 is the ordinary
// word separator in Japanese layout.
func TestNonTextContentSeparatorFold_TN_JapaneseReportName(t *testing.T) {
	const ideo = "　"
	assertNonTextTN(t, "japanese-report-name",
		"第3四半期"+ideo+"売上報告書"+ideo+"最終版", false)
}

// A French-localized description mentioning "précédent" (previous) in a
// benign context, with narrow no-break spaces before punctuation.
func TestNonTextContentSeparatorFold_TN_FrenchDescription(t *testing.T) {
	const narrow = " "
	assertNonTextTN(t, "french-description",
		"Rapport trimestriel"+narrow+": comparaison avec le trimestre précédent"+narrow+"!", true)
}

// Plain ASCII benign name — pins the `changed` fast path.
func TestNonTextContentSeparatorFold_TN_PlainASCII(t *testing.T) {
	text := "Q3 Sales Report Final"
	res := scanNonTextName(text)
	if res.Blocked {
		t.Fatalf("plain ASCII benign name flagged: %+v", res.Findings)
	}
	var probe NonTextContentScanResult
	scanNonTextInjectionFieldSeparatorFolded(&probe, 0, "resource_link", "name", text)
	if len(probe.Findings) != 0 {
		t.Fatalf("fold pass must no-op on pure ASCII, got %+v", probe.Findings)
	}
}
