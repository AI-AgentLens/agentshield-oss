package mcp

import (
	"strings"
	"testing"
)

// jwtLikeToken mirrors the token shape TestContentScan_BearerToken already
// uses — 20+ chars from bearerTokenRe's charset, no real secret material.
const jwtLikeToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"

func scanArg(argName, text string) ContentScanResult {
	return ScanToolCallContent("fetch", map[string]interface{}{argName: text})
}

func hasContentSignal(res ContentScanResult, sig ContentSignal) bool {
	for _, f := range res.Findings {
		if f.Signal == sig {
			return true
		}
	}
	return false
}

// TestContentSeparatorFold_TP_BearerTokenNBSPRecovered: bearerTokenRe
// requires `\s+` between "Bearer" and the token. Before this pass, an
// argument value carrying "Bearer" + U+00A0 + token rendered and tokenized
// identically to "Bearer <token>" while matching nothing — a scanner that
// exists specifically to catch credentials leaking through tool arguments
// missed the credential when its separator was one non-ASCII byte.
func TestContentSeparatorFold_TP_BearerTokenNBSPRecovered(t *testing.T) {
	const nbsp = " "

	ascii := scanArg("headers", "Authorization: Bearer "+jwtLikeToken)
	if !hasContentSignal(ascii, SignalBearerToken) {
		t.Fatalf("VACUOUS: ASCII bearer-token control did not fire: %+v", ascii.Findings)
	}

	var raw ContentScanResult
	scanArgumentValue(&raw, "headers", "Authorization: Bearer"+nbsp+jwtLikeToken)
	if hasContentSignal(raw, SignalBearerToken) {
		t.Fatalf("raw scan unexpectedly matched NBSP-separated bearer token: %+v", raw.Findings)
	}

	folded := scanArg("headers", "Authorization: Bearer"+nbsp+jwtLikeToken)
	if !hasContentSignal(folded, SignalBearerToken) {
		t.Fatal("NBSP-separated bearer token was not detected — the fold did not recover it")
	}
}

// TestContentSeparatorFold_AttributionAndSubtraction mirrors
// TestResponseSeparatorFold_AttributionAndSubtraction for the argument-value
// scanner: ASCII findings never carry the fold-attribution suffix, NBSP
// findings always do.
func TestContentSeparatorFold_AttributionAndSubtraction(t *testing.T) {
	const nbsp = " "

	ascii := scanArg("headers", "Authorization: Bearer "+jwtLikeToken)
	for _, f := range ascii.Findings {
		if strings.Contains(f.Detail, "recovered by folding") {
			t.Fatalf("ASCII text produced a fold-attributed finding: %s", f.Detail)
		}
	}

	folded := scanArg("headers", "Authorization: Bearer"+nbsp+jwtLikeToken)
	var attributed bool
	for _, f := range folded.Findings {
		if f.Signal == SignalBearerToken && strings.Contains(f.Detail, "recovered by folding") {
			attributed = true
		}
	}
	if !attributed {
		t.Fatal("NBSP-recovered bearer-token finding must be attributed to the separator fold")
	}
}

// ---------------------------------------------------------------------------
// True negatives — legitimate Unicode spacing in ordinary argument values.
// ---------------------------------------------------------------------------

func assertContentTN(t *testing.T, name, argName, text string) {
	t.Helper()

	ascii := text
	for _, sep := range []string{" ", "　", " ", " ", " ", " "} {
		ascii = strings.ReplaceAll(ascii, sep, " ")
	}
	if res := scanArg(argName, ascii); res.Blocked {
		t.Fatalf("%s: INVALID TRUE NEGATIVE — the ASCII-spaced rendering already flags, "+
			"so it cannot demonstrate anything about the separator fold: %+v", name, res.Findings)
	}

	if res := scanArg(argName, text); res.Blocked {
		t.Fatalf("%s: false positive on benign argument value: %+v", name, res.Findings)
	}
}

// A localized product description argument using French typographic spacing
// (U+202F before punctuation) — plausible in a "description" or "message"
// argument to a localization/content-management MCP tool.
func TestContentSeparatorFold_TN_FrenchProductDescription(t *testing.T) {
	const narrow = " "
	assertContentTN(t, "french-description", "description",
		"Nouveau"+narrow+": livraison gratuite dès 50"+narrow+"€ d'achat"+narrow+"!")
}

// Scraped HTML pasted into a "notes" argument — NBSP arrives by the hundred
// from any HTML-to-text conversion and must not be treated as a credential
// separator.
func TestContentSeparatorFold_TN_ScrapedHTMLNotes(t *testing.T) {
	const nbsp = " "
	assertContentTN(t, "scraped-html-notes", "notes",
		"Pricing"+nbsp+"— Starter plan: $10"+nbsp+"/ month, billed annually.")
}

// Plain ASCII benign argument — pins the `changed` fast path.
func TestContentSeparatorFold_TN_PlainASCII(t *testing.T) {
	text := "New York City"
	res := scanArg("location", text)
	if res.Blocked {
		t.Fatalf("plain ASCII benign argument flagged: %+v", res.Findings)
	}
	var probe ContentScanResult
	scanArgumentValueSeparatorFolded(&probe, "location", text)
	if len(probe.Findings) != 0 {
		t.Fatalf("fold pass must no-op on pure ASCII, got %+v", probe.Findings)
	}
}
