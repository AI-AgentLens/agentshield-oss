package mcp

import (
	"strings"
	"testing"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// Spelling-parity tests for looksLikeCode's `import` detector.
//
// # What this file asserts
//
// `import` is the one token in codePatterns that is also an ordinary English
// word, so the old unanchored `import\s+\w+` classified prose that merely
// MENTIONED an import as code-execute — "how to fix python import error"
// (MCP-TP-720), "The answer should explain import os as an example." An
// earlier attempt at a fix anchored the keyword to statement position with a
// single regex (`(?im)(^|;)[ \t]*import…`). Adversarial review showed that
// anchor was unsound in both directions — it lost `if True: import os`,
// CR-only line boundaries and `python3 -c "import os"` payloads, while still
// firing on "For example; import os is shown below." (`;` is punctuation as
// often as it is a statement separator, and a bare anchor cannot tell which).
//
// #3696 replaced the anchor with importInStatementPosition (semantic.go): a
// small tokenizer that recognizes comment lines, line boundaries (`\n`, `\r`,
// `\f`), the colon that closes a compound-statement header, and — the piece
// the anchor could not do — treats a semicolon as a statement separator only
// when the segment BEFORE it also looks like a code statement (an assignment
// or bare identifier), not merely present. That is what lets "x = 1; import
// socket" stay detected while "For example; import os is shown below." does
// not.
//
// Every row below now asserts the CORRECT verdict — code stays detected, prose
// is excluded — in both the ASCII spelling and every folded spelling from
// #3594, so the fold cannot reopen the gap the tokenizer just closed.

// proseMentioningImport is the reproduction case for #3696, assembled by
// concatenation so the whole sentence is not a single literal.
func proseMentioningImport() string {
	return "The answer should explain " + "import" + " os as an example."
}

// classifiesAsCode mirrors what classifyArgValues actually does: the wire form
// OR the folded form.
func classifiesAsCode(s string) bool {
	if looksLikeCode(s) {
		return true
	}
	folded, changed := pkgunicode.FoldUnicodeSeparators(s)
	return changed && looksLikeCode(folded)
}

func TestLooksLikeCode_ImportSpellingParity(t *testing.T) {
	imp := "import" + " os"

	cases := []struct {
		name      string
		value     string
		wantASCII bool
		note      string
	}{
		// --- executable positions. All must stay detected: the tokenizer must
		// not regress recall relative to the old unanchored regex. ---
		{name: "standalone", value: imp, wantASCII: true},
		{name: "colon suite", value: "if True: " + imp, wantASCII: true},
		{name: "CR-only line boundary", value: "x = 1\r" + imp, wantASCII: true},
		{name: "form-feed prefix", value: "\f" + imp, wantASCII: true},
		{name: "python3 -c payload", value: `python3 -c "` + imp + `"`, wantASCII: true},
		{name: "leading indentation", value: "    import sys", wantASCII: true},
		{name: "after a newline", value: "x = 1\nimport socket", wantASCII: true},
		{name: "after a semicolon", value: "x = 1; import socket", wantASCII: true},
		{name: "from-form", value: "from crewai import Crew", wantASCII: true},
		{name: "from-form, dotted package", value: "from google.cloud import scheduler_v1", wantASCII: true},

		// --- prose. #3696 fixed these: none of them are in statement
		// position, so none of them are code. ---
		{name: "prose mentioning import", value: proseMentioningImport(), wantASCII: false,
			note: "#3696 fixed — no statement position"},
		{name: "support question", value: "how to fix python import error", wantASCII: false,
			note: "#3696 fixed (MCP-TP-720) — no statement position"},
		{name: "prose semicolon", value: "For example; " + imp + " is shown below.", wantASCII: false,
			note: "#3696 fixed — the `;` is punctuation here, and \"For example\" is not a code-shaped prefix"},
		{name: "comment semicolon", value: "# disabled example; " + imp, wantASCII: false,
			note: "#3696 fixed — comment lines are excluded before the semicolon check runs"},

		// --- prose with no import at all: the control that keeps the rows
		// above from being vacuous. ---
		{name: "no import keyword", value: "The answer should explain modules as an example.", wantASCII: false},
	}

	seps := map[string]string{
		"U+00A0":            sepRune(0x00A0),
		"2x U+00A0":         sepRune(0x00A0) + sepRune(0x00A0),
		"U+2009 and U+200A": sepRune(0x2009) + sepRune(0x200A),
		"U+3000":            sepRune(0x3000),
	}

	sawPositive, sawNegative := 0, 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ascii := classifiesAsCode(tc.value)
			if ascii != tc.wantASCII {
				t.Fatalf("ASCII spelling of %q classified as code = %v, want %v (%s)",
					tc.value, ascii, tc.wantASCII, tc.note)
			}
			if ascii {
				sawPositive++
			} else {
				sawNegative++
			}

			for sepName, sep := range seps {
				respelled := strings.ReplaceAll(tc.value, " ", sep)
				if respelled == tc.value {
					continue // nothing to respell in this row
				}
				assertFoldable(t, sepName, sep)
				if got := classifiesAsCode(respelled); got != ascii {
					t.Errorf("%s spelling classified as code = %v, ASCII = %v (%q)",
						sepName, got, ascii, tc.value)
				}
			}
		})
	}

	// Vacuity guard: a parity table where every row is true (or every row is
	// false) would pass with the detector deleted.
	if sawPositive == 0 || sawNegative == 0 {
		t.Errorf("vacuous table: %d rows classified as code, %d did not — need both",
			sawPositive, sawNegative)
	}
}

// TestSemanticImportProse_SpellingParity is the same contract one layer up, at
// the shipped-rule level: the prose call must not BLOCK on
// mcp-sem-block-code-execute, in either spelling.
//
// Before #3696 both spellings crossed mcp-sem-block-code-execute's
// confidence_min of 0.7 — two code-ish argument names ("code", "expression")
// contributed 0.5, and the unanchored `import\s+\w+` on the value added the
// +0.2 that crossed the threshold. The tokenizer now scores the value's
// `import` at 0, so the call is left at 0.5 and the rule does not fire.
func TestSemanticImportProse_SpellingParity(t *testing.T) {
	ev := newTestMCPEvaluator(t)

	const toolName = "syntax_highlighter"
	const wantRule = "mcp-sem-block-code-execute"
	prose := proseMentioningImport()
	args := func(text string) map[string]interface{} {
		return map[string]interface{}{"code": "plain-text", "expression": text}
	}

	ascii := matchedSemanticIDs(t, ev, toolName, args(prose), "")
	if contains(ascii, wantRule) {
		t.Fatalf("#3696 regression: prose mentioning import matched %q (matched: %v)", wantRule, ascii)
	}

	for sepName, sep := range map[string]string{
		"U+00A0":    sepRune(0x00A0),
		"2x U+00A0": sepRune(0x00A0) + sepRune(0x00A0),
		"U+3000":    sepRune(0x3000),
	} {
		t.Run(sepName, func(t *testing.T) {
			assertFoldable(t, sepName, sep)
			respelled := strings.ReplaceAll(prose, " ", sep)
			if got := matchedSemanticIDs(t, ev, toolName, args(respelled), ""); !equalIDs(got, ascii) {
				t.Errorf("%s spelling matched %v, ASCII matched %v", sepName, got, ascii)
			}
		})
	}

	// Vacuity guard: a real import statement in the same argument must reach the
	// detector, in both spellings, or the parity rows above prove nothing.
	scores := make(map[MCPToolIntent]float64)
	classifyArgValues(map[string]interface{}{"expression": "import os"}, scores)
	if scores[IntentCodeExecute] == 0 {
		t.Fatalf("vacuous control: a real import statement scored code-execute at 0")
	}
	foldedScores := make(map[MCPToolIntent]float64)
	classifyArgValues(map[string]interface{}{"expression": "import" + sepRune(0x00A0) + "os"}, foldedScores)
	if foldedScores[IntentCodeExecute] != scores[IntentCodeExecute] {
		t.Errorf("U+00A0 import statement scored %.2f, ASCII scored %.2f",
			foldedScores[IntentCodeExecute], scores[IntentCodeExecute])
	}
}
