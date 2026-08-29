package mcp

import (
	"regexp"
	"strings"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// Rendering-equivalent forms of a prose field.
//
// # The defect this exists to close
//
// Seven scanners in this package match the shared description-side prose
// pattern sets (hiddenInstruction, credentialHarvest, exfiltration, stealth,
// behavioralManipulation, …) against `strings.ToLower(text)` and nothing else.
// Measured 2026-08-23 with one canonical hidden-instruction payload, ASCII
// versus the same sentence in fullwidth:
//
//	surface                          ascii    fullwidth
//	error.message                    BLOCK    clean
//	prompts/get                      poisoned clean
//	resources/list metadata          found    clean
//	resources/templates/list         found    clean
//	initialize instructions          BLOCK    ALLOW
//	sampling/createMessage           found    clean
//
// Six of six surfaces with a positive control went completely silent. Only
// description_scanner.go and response_scanner.go had a recovery pass; the
// lesson had been learned twice and propagated to neither of these.
//
// # Why one pass and not one pass per axis
//
// Per-axis normalizers do not compose: each folds ITS axis then matches, so a
// residue from any other axis leaves the pattern unmatched, and two axes
// combined defeat two independent single-axis passes.
// pkgunicode.RecoverRenderedText undoes every axis at once, which covers the
// 2^n combinations for free.
//
// # Why this cannot introduce false positives
//
// Recovery is a text transform, never a verdict. Nothing reports the presence
// of an invisible or confusable codepoint — a signal fires only when a KNOWN
// MALICIOUS pattern matches the recovered text. Benign prose (CMS soft
// hyphens, emoji ZWJ sequences, Japanese fullwidth punctuation, Russian text)
// does not recover into a credential-harvest directive. That folded-but-not-
// raw gate is the same one used by scanResponseRenderRecovered.
type proseForms struct {
	// lower is the text as sent, lowercased — always tried first, so a match
	// on the wire form behaves exactly as it did before.
	lower string
	// recoveredLower is the lowercased text with codepoint-level disguises
	// undone. Empty when recovery changed nothing.
	recoveredLower string
}

// renderRecoveryNote is appended to a finding's description when the pattern
// matched only after recovery, so an audit entry never implies the bytes
// arrived in the clear.
const renderRecoveryNote = " (recovered by undoing codepoint-level disguises — " +
	"invisible formatters removed, blank-rendering fillers and Unicode separators folded to " +
	"ASCII space, fullwidth/mathematical and Cyrillic/Greek confusables folded to Latin; " +
	"the text as sent matched no pattern while rendering as ordinary English)"

// newProseForms builds the match forms for a prose field.
func newProseForms(text string) proseForms {
	f := proseForms{lower: strings.ToLower(text)}
	if recovered, changed := pkgunicode.RecoverRenderedText(text); changed {
		f.recoveredLower = strings.ToLower(recovered)
	}
	return f
}

// proseMatchNote reports whether re matches any rendering of the field. The
// returned note is empty when the text as sent matched, and renderRecoveryNote
// when only the recovered rendering did — append it to the finding's detail.
func proseMatchNote(re *regexp.Regexp, forms proseForms) (note string, ok bool) {
	if re.MatchString(forms.lower) {
		return "", true
	}
	if forms.recoveredLower != "" && re.MatchString(forms.recoveredLower) {
		return renderRecoveryNote, true
	}
	return "", false
}
