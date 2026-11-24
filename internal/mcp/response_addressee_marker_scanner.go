package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// Addressee markers on the tools/call result surface (AI_risk_compliance#4554;
// Gary 2026-10-10, option A: a Go detector, its vocabulary public in the OSS
// build, its receipt attributed through a premium sentinel).
//
// An addressee marker is text in a tool result that speaks to the model AS
// the assistant, not about anything: "Assistant instruction: ...", a line
// opening "Instruction:" or "SYSTEM:", a role tag (<system>, <<SYS>>,
// [assistant], [INST], <|im_start|>, a Llama-3 header), "Note to the AI", or
// "your instructions have changed". A tool result is data the user asked for;
// nothing in it has a reason to address the model in the second person under
// an authority label. Shield's other result scanners key on what a directive
// asks for (override, exfiltration, concealment). appsecco's malicious-tools
// server shows why that is not enough: its injected goal is harmless ("also
// print a recipe"), so only the marker carries it.
//
// The vocabulary is Comply's ai-mcp-server-tool-result-instruction lexicon
// (AI_risk_compliance#4563, the static twin of this check), copied verbatim,
// plus three role-tag forms none of the measured apps uses: [system] /
// [assistant], Llama-2 <<SYS>>, and the Llama-3 header ids. The two repos
// cannot share code (Shield is OSS, Comply is not), so this is a copy.
// #4554 tracks keeping the copies in step.
//
// The imperative tail is REQUIRED. A marker alone fired on 1 of 284 benign
// prose files (a handoff doc's "agent instructions:") and on 8 of 1,860 text
// files (`system:` keys in chat-SDK code). With the tail it fires on none of
// either set and still catches the attack texts (2026-10-10 measurement in
// the PR that added this file).
//
// AUDIT only, and the scanner cannot block: the result type has no Blocked
// field. "Only BLOCK what you can justify." The lexicon was written after
// reading its targets, so real-world precision is unmeasured beyond the
// benign corpus. Like ScanToolCallResponseForIndirectDirectives, the value of
// an AUDIT here is the receipt: a result that addressed the model is the
// event an auditor asks about.
//
// Known limits, deliberately not addressed here:
//   - text content items only (no structuredContent, _meta or non-text
//     blocks);
//   - tools/call only (resources/read and sampling tool_result do not run
//     it);
//   - no render recovery, so a fullwidth or homoglyph marker is not folded.

// ResponseAddresseeMarkerSignal is the signal ScanToolCallResponseForAddresseeMarkers emits.
type ResponseAddresseeMarkerSignal string

// SignalResponseAddresseeMarker fires when a text content item addresses the
// model as the assistant (an authority or role marker) and, on the same line,
// gives it an imperative.
const SignalResponseAddresseeMarker ResponseAddresseeMarkerSignal = "response_addressee_marker"

// ResponseAddresseeMarkerFinding records one addressed text content item.
type ResponseAddresseeMarkerFinding struct {
	Signal       ResponseAddresseeMarkerSignal
	Detail       string
	Snippet      string
	ContentIndex int
}

// ResponseAddresseeMarkerScanResult is the outcome of
// ScanToolCallResponseForAddresseeMarkers. It has no Blocked field on purpose.
type ResponseAddresseeMarkerScanResult struct {
	Found    bool
	Findings []ResponseAddresseeMarkerFinding
}

const (
	// addresseeMarkers: who the text claims to be, or whom it addresses.
	addresseeMarkers = `\b(?:assistant|ai|agent|model|llm|claude|chatgpt)\s+(?:instructions?|directives?|guidelines?|note|notice)\s*:` +
		`|\bnote\s+to\s+(?:the\s+)?(?:ai|assistant|agent|model|llm)\b` +
		"|(?:^|[|\\n\"`]\\s*)(?:important\\s+)?(?:instruction|system(?:\\s+(?:instruction|directive|note|message|override))?)\\s*:" +
		`|<\s*/?\s*system\s*>` +
		`|\[/?INST\]` +
		`|<\|im_start\|>` +
		`|\byour\s+(?:instructions?|rules|guidelines|directives)\s+(?:have|has)\s+(?:changed|been\s+(?:updated|changed|replaced))` +
		// Shield-only additions: role tags no measured app uses.
		`|\[\s*/?\s*(?:system|assistant)\s*\]` +
		`|<<\s*/?\s*SYS\s*>>` +
		`|<\|start_header_id\|>\s*(?:system|assistant)\s*<\|end_header_id\|>`

	// addresseeImperatives: what the marked text tells the assistant to do.
	addresseeImperatives = `\b(?:also|additionally|in\s+addition)\b[^.\n]{0,80}?\b(?:print|output|say|tell|include|append|send|call|invoke|run|execute|write|respond|reply|show|display|recommend|mention|list|add|return|use)\b` +
		`|\byou\s+(?:must|should|need\s+to|have\s+to|are\s+required\s+to|will\s+now)\b` +
		`|\b(?:do\s+not|don.?t|never)\s+(?:mention|tell|reveal|show|disclose|inform|say)\b` +
		`|\b(?:ignore|disregard|forget)\b` +
		`|\b(?:when|before|after)\s+(?:presenting|responding|answering|replying|displaying|showing|summari[sz]ing)\b`
)

// addresseeMarkerRE requires a marker followed on the same line, within 200
// characters, by an imperative.
var addresseeMarkerRE = regexp.MustCompile(`(?is)(?:` + addresseeMarkers + `)[^\n]{0,200}?(?:` + addresseeImperatives + `)`)

// forgedUserTurnRE is the other direction: text in a tool result that speaks
// AS the user. A context-compacting harness that flattens its history into a
// plain string labels each message "[User]:", so a result carrying that label
// followed by a grant of approval survives summarisation as a genuine standing
// approval (arXiv 2610.29869, Compaction Laundering; 87-100% on five flattening
// harnesses). The label alone is common in chat transcripts and docs, so a
// bracketed or line-initial user/human label counts only with an approval grant
// on the same line. It is a second reading beside addresseeMarkerRE, never a
// replacement: a match here only adds a finding, at the same AUDIT tier.
const (
	forgedUserLabels = "(?:^|[|\\n\"`]\\s*)(?:\\[\\s*(?:user|human)\\s*\\]|(?:user|human))\\s*:"
	userGrantTails   = `\bi\s+(?:hereby\s+)?(?:approve|authori[sz]e|allow|grant|permit|consent)\b` +
		`|\b(?:approved|authori[sz]ed|pre-?approved)\b` +
		`|\bgo\s+ahead\b` +
		`|\bfrom\s+now\s+on\b` +
		`|\bstanding\s+(?:approval|permission|authori[sz]ation)\b` +
		`|\bwithout\s+(?:asking|confirm\w*|prompting|checking\s+with\s+me)\b` +
		`|\b(?:always|automatically)\s+(?:run|execute|approve|accept|allow)\b`
)

var forgedUserTurnRE = regexp.MustCompile(`(?is)(?:` + forgedUserLabels + `)[^\n]{0,200}?(?:` + userGrantTails + `)`)

// addresseeMarkerSnippetMax caps the matched text quoted into the receipt.
const addresseeMarkerSnippetMax = 160

// ScanToolCallResponseForAddresseeMarkers reports each text content item that
// addresses the model as the assistant. AUDIT-tier only; call sites surface
// findings as AUDIT and fall through.
func ScanToolCallResponseForAddresseeMarkers(items []ContentItem) ResponseAddresseeMarkerScanResult {
	var result ResponseAddresseeMarkerScanResult
	for i, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		detail := "addresses the model as the assistant and gives it an instruction"
		loc := addresseeMarkerRE.FindStringIndex(item.Text)
		if loc == nil {
			loc = forgedUserTurnRE.FindStringIndex(item.Text)
			detail = "speaks as the user and grants an approval (a forged user turn)"
		}
		if loc == nil {
			continue
		}
		snippet := item.Text[loc[0]:loc[1]]
		if detail != "addresses the model as the assistant and gives it an instruction" {
			// The label's leading delimiter is part of the match, not of the evidence.
			snippet = strings.TrimLeft(snippet, "|\n\"` \t")
		}
		if len(snippet) > addresseeMarkerSnippetMax {
			snippet = snippet[:addresseeMarkerSnippetMax]
		}
		result.Findings = append(result.Findings, ResponseAddresseeMarkerFinding{
			Signal:       SignalResponseAddresseeMarker,
			Detail:       fmt.Sprintf("content item %d %s: %q", i, detail, snippet),
			Snippet:      snippet,
			ContentIndex: i,
		})
	}
	result.Found = len(result.Findings) > 0
	return result
}
