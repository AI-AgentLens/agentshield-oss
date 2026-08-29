package mcp

import (
	"regexp"
	"strings"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// ResponseIndirectDirectiveSignal identifies one of five prose attack classes
// that ScanToolDescription already detects on tool descriptions but the
// ordinary response scanner (response_scanner.go) does not detect on tool
// responses: exfiltration directives, conditional (sleeper) triggers,
// approval-gate / consent-gate manipulation, reasoning / system-prompt
// exfiltration, and audit-log evasion.
//
// # Why these five were missing on the response surface (issue #3435)
//
// A tool description is authored by the server operator and reviewed once, at
// install time. A tool response is arbitrary fetched content — a web page, an
// issue body, an email — and response_scanner.go's own comment calls it
// "where indirect prompt injection actually lands." Measured 2026-08-19, one
// canonical directive per class, these five scanned completely clean on the
// response surface across every phrasing tried, while firing reliably on the
// description surface.
//
// # Why the description patterns cannot simply be re-run on responses
//
// Measured against seven realistic benign responses (a CVE advisory quoting
// an injection phrase, a GitHub issue discussing a false positive, an
// internal policy doc, an observability runbook, a code review of a
// date-gated feature flag, an LLM eval harness printing its test case, an
// agent debugging transcript), the description patterns flag 7 of 7. The
// narrower response pattern set already in response_scanner.go is a correct
// calibration, not an oversight.
//
// # The actual fix: a discourse-level guard, not another pattern list
//
// The distinction is not lexical, it is discourse-level: a description that
// says "do not tell the user" IS a directive; a response that says it is very
// often QUOTING or DISCUSSING one. Every match here must clear two gates:
//
//  1. isQuotedOrAttributed — the match must NOT sit inside a fenced code
//     block, inline code span, blockquote, dialogue-labelled line (User:/
//     Agent:/System:), an open quotation, or near an attribution cue (says,
//     according to, a CVE advisory, a test case, a changelog, ...).
//  2. hasAgentDirectedCue — the match must be addressed TO THE AGENT: a
//     second-person / self-referential cue (you, your, this tool, this call,
//     this action, this request) nearby, OR the match opens its own sentence
//     (bare imperative mood — "Disable the audit log before writing" has no
//     pronoun, but is a directive precisely because nothing else is the
//     subject).
//
// Both gates must pass. A third-person factual statement ("hotfixes are
// pre-approved") fails gate 2 (mid-sentence, no agent-directed cue) and is
// not reported. A quoted CVE payload or a labelled debug transcript line
// fails gate 1 and is not reported even though it may satisfy gate 2.
//
// # AUDIT-tier only, by design
//
// These signals never set Blocked. Even with both gates, position-and-cue
// heuristics carry more residual FP risk than the curated, lexically precise
// patterns already driving BLOCK decisions elsewhere in this package —
// see issue #3435's own recommendation. An AUDIT finding still reaches the
// attestation (the moat-relevant half of the issue: an approval-gate or
// audit-log-evasion directive arriving in tool output is exactly the event
// that should appear in a receipt, even when it is not worth blocking on),
// without the enforcement cost landing on ordinary tool output.
type ResponseIndirectDirectiveSignal string

const (
	// SignalResponseIndirectExfiltration fires when response content directs
	// the agent to transfer data to a sink (send/encode/embed/exfiltrate),
	// addressed to the agent rather than quoted or discussed.
	SignalResponseIndirectExfiltration ResponseIndirectDirectiveSignal = "response_indirect_exfiltration_directive"

	// SignalResponseIndirectConditionalTrigger fires when response content
	// contains a dormant directive gated on a runtime condition (a date, a
	// trigger phrase, a tool-presence check, a lifecycle event).
	SignalResponseIndirectConditionalTrigger ResponseIndirectDirectiveSignal = "response_indirect_conditional_trigger"

	// SignalResponseIndirectApprovalGate fires when response content targets
	// the host consent gate or human approver (auto-approve coercion, false
	// pre-authorisation claims, directives to skip confirmation).
	SignalResponseIndirectApprovalGate ResponseIndirectDirectiveSignal = "response_indirect_approval_gate_manipulation"

	// SignalResponseIndirectReasoningExfiltration fires when response content
	// directs the agent to transfer its own private reasoning (chain-of-
	// thought, system prompt, hidden instructions) into an argument, output,
	// or external sink.
	SignalResponseIndirectReasoningExfiltration ResponseIndirectDirectiveSignal = "response_indirect_reasoning_exfiltration"

	// SignalResponseIndirectAuditLogEvasion fires when response content
	// directs the agent to suppress, skip, or hide a call from the security/
	// audit/monitoring layer.
	SignalResponseIndirectAuditLogEvasion ResponseIndirectDirectiveSignal = "response_indirect_audit_log_evasion"
)

// ResponseIndirectDirectiveFinding records one detected indirect-directive
// signal in a tool response.
type ResponseIndirectDirectiveFinding struct {
	Signal  ResponseIndirectDirectiveSignal
	Detail  string
	Snippet string
}

// ResponseIndirectDirectiveScanResult is the outcome of
// ScanToolCallResponseForIndirectDirectives.
type ResponseIndirectDirectiveScanResult struct {
	Found    bool
	Findings []ResponseIndirectDirectiveFinding
}

// ScanToolCallResponseForIndirectDirectives inspects tool response text
// content for the five prose attack classes described above. AUDIT-tier only
// (does not set Blocked) — call sites should surface findings as AUDIT and
// fall through, mirroring ScanToolCallResponseForVerificationLoop and
// ScanToolCallResponseForTracebacks.
func ScanToolCallResponseForIndirectDirectives(items []ContentItem) ResponseIndirectDirectiveScanResult {
	var result ResponseIndirectDirectiveScanResult
	for _, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		scanIndirectDirectiveText(&result, item.Text)
		scanIndirectDirectiveRenderRecovered(&result, item.Text)
	}
	result.Found = len(result.Findings) > 0
	return result
}

// scanIndirectDirectiveRenderRecovered re-runs the five classes over text that
// has had codepoint-level disguises undone, appending only signals the raw pass
// did not already produce.
//
// Without it this entire scanner is defeated by one substitution. Measured
// 2026-08-23, one canonical directive per class, four spellings each:
//
//	class                     ascii  fullwidth  soft-hyphen  both
//	approval-gate               ✓        ✗           ✗         ✗
//	exfiltration                ✓        ✗           ✗         ✗
//	reasoning-exfiltration      ✓        ✗           ✗         ✗
//	audit-log-evasion           ✓        ✗           ✗         ✗
//	conditional-trigger         ✓        ✗           ✗         ✗
//
// 15 of 15 disguised spellings scanned clean, and ScanToolCallResponse caught
// none of them either — these five classes exist precisely because it does
// not. The response surface is the one place the payload is arbitrary fetched
// content, so the attacker chooses the encoding.
//
// The same shape as scanResponseRenderRecovered and
// scanContentAudienceRenderRecovered: recovery is a text transform and never a
// verdict, so only a directive that recovery made READABLE is reported. That
// folded-but-not-raw gate is what keeps it FP-free — benign prose does not
// recover into an approval-gate directive, and per-axis passes do not compose,
// which is why one recovery undoing every axis is the only shape that works.
//
// The discourse gates run against the RECOVERED text, deliberately: a fence,
// a blockquote marker or an attribution cue written in fullwidth is still a
// fence to a human reader, so quoting must be judged on what renders.
func scanIndirectDirectiveRenderRecovered(result *ResponseIndirectDirectiveScanResult, text string) {
	recovered, changed := pkgunicode.RecoverRenderedText(text)
	if !changed {
		return
	}

	seen := make(map[ResponseIndirectDirectiveSignal]bool, len(result.Findings))
	for _, f := range result.Findings {
		seen[f.Signal] = true
	}

	var recoveredResult ResponseIndirectDirectiveScanResult
	scanIndirectDirectiveText(&recoveredResult, recovered)

	for _, f := range recoveredResult.Findings {
		if seen[f.Signal] {
			continue
		}
		seen[f.Signal] = true
		f.Detail += " — recovered by undoing codepoint-level disguises (invisible formatters " +
			"such as U+00AD SOFT HYPHEN removed; blank-rendering fillers and Unicode separators " +
			"folded to ASCII space; fullwidth/mathematical and Cyrillic/Greek confusables folded " +
			"to Latin). The text as sent matched no pattern while rendering as ordinary English"
		result.Findings = append(result.Findings, f)
	}
}

func scanIndirectDirectiveText(result *ResponseIndirectDirectiveScanResult, text string) {
	lower := strings.ToLower(text)

	if loc, desc, ok := firstDirectedMatch(exfiltrationPatterns, text, lower); ok {
		result.Findings = append(result.Findings, ResponseIndirectDirectiveFinding{
			Signal: SignalResponseIndirectExfiltration,
			Detail: "tool response directs the agent to exfiltrate data (" + desc +
				"), addressed to the agent rather than quoted or discussed",
			Snippet: safeSnippet(text, loc, 80),
		})
	}

	if loc, desc, ok := firstDirectedMatch(conditionalTriggerPatterns, text, lower); ok {
		result.Findings = append(result.Findings, ResponseIndirectDirectiveFinding{
			Signal: SignalResponseIndirectConditionalTrigger,
			Detail: "tool response contains a dormant conditional-trigger directive (" + desc +
				"), addressed to the agent rather than quoted or discussed",
			Snippet: safeSnippet(text, loc, 80),
		})
	}

	if loc, desc, ok := firstDirectedMatch(approvalGateManipulationPatterns, text, lower); ok {
		result.Findings = append(result.Findings, ResponseIndirectDirectiveFinding{
			Signal: SignalResponseIndirectApprovalGate,
			Detail: "tool response targets the host consent gate / human approver (" + desc +
				"), addressed to the agent rather than quoted or discussed",
			Snippet: safeSnippet(text, loc, 80),
		})
	}

	if loc, ok := firstDirectedCooccurrence(agentPrivateReasoningRE, reasoningTransferVerbRE, 160, text, lower); ok {
		result.Findings = append(result.Findings, ResponseIndirectDirectiveFinding{
			Signal: SignalResponseIndirectReasoningExfiltration,
			Detail: "tool response directs the agent to transfer its own private reasoning " +
				"(chain-of-thought / system prompt / hidden reasoning) into a tool argument, " +
				"response, or external sink, addressed to the agent rather than quoted or discussed",
			Snippet: safeSnippet(text, loc, 100),
		})
	}

	if loc, ok := firstDirectedCooccurrence(auditSecurityNounRE, auditSuppressionVerbRE, 180, text, lower); ok {
		result.Findings = append(result.Findings, ResponseIndirectDirectiveFinding{
			Signal: SignalResponseIndirectAuditLogEvasion,
			Detail: "tool response directs the agent to suppress, skip, or hide a call from the " +
				"security/audit/monitoring layer, addressed to the agent rather than quoted or discussed",
			Snippet: safeSnippet(text, loc, 100),
		})
	}
}

// firstDirectedMatch returns the byte offset and description of the first
// match of patterns against lower whose location clears both the quotation/
// attribution gate and the agent-directed-cue gate. Patterns are tried in
// order; within a pattern, every match location is tried before moving to the
// next pattern, so an early pattern with only quoted/third-person occurrences
// does not shadow a later pattern with a genuine directive.
func firstDirectedMatch(patterns []signalPattern, text, lower string) (int, string, bool) {
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringIndex(lower, -1) {
			if !shouldFireDirective(text, lower, loc[0], loc[1]) {
				continue
			}
			return loc[0], p.description, true
		}
	}
	return 0, "", false
}

// firstDirectedCooccurrence mirrors the co-occurrence idiom already used by
// detectReasoningExfiltration and detectAuditLogEvasion (description_scanner.go):
// a nounRE match and a verbRE match within a sliding window of each other. It
// additionally requires the noun's match location to clear the quotation/
// attribution and agent-directed-cue gates before firing.
func firstDirectedCooccurrence(nounRE, verbRE *regexp.Regexp, window int, text, lower string) (int, bool) {
	for _, loc := range nounRE.FindAllStringIndex(lower, -1) {
		windowStart := loc[0] - window
		if windowStart < 0 {
			windowStart = 0
		}
		windowEnd := loc[1] + window
		if windowEnd > len(lower) {
			windowEnd = len(lower)
		}
		if !verbRE.MatchString(lower[windowStart:windowEnd]) {
			continue
		}
		if !shouldFireDirective(text, lower, loc[0], loc[1]) {
			continue
		}
		return loc[0], true
	}
	return 0, false
}

// shouldFireDirective is the combined discourse-level gate: a match fires
// only when it is NOT quoted/code-fenced/blockquoted/attributed AND IS
// addressed to the agent (second-person/self-referential cue, or bare
// imperative sentence start).
func shouldFireDirective(text, lower string, start, end int) bool {
	if isQuotedOrAttributed(text, lower, start, end) {
		return false
	}
	return hasAgentDirectedCue(text, lower, start, end)
}

// attributionCueRE matches phrasing that attributes the surrounding text to a
// third-party source (a report, an advisory, a changelog, a test case) rather
// than presenting it as a live directive to the agent.
var attributionCueRE = regexp.MustCompile(`(?i)\b(` +
	`says?|said|states?|stated|wrote|writes?|according\s+to|` +
	`describ(?:es|ed|ing)|discuss(?:es|ed|ing)?|mentions?|mentioned|` +
	`notes?|noted|claims?|claimed|argu(?:es|ed)|quoting|quotes?|quoted|` +
	`cites?|cited|titled|reads?:|reported?|document(?:s|ed)?|logged|` +
	`recorded|comment(?:s|ed)?|repl(?:y|ies|ied)|` +
	`test\s*case|changelog|runbook|` +
	`for\s+example|e\.g\.|for\s+instance|` +
	`cve-\d{4}-\d+|cve\s+advisory|vulnerability\s+report|advisory|` +
	`transcript|debug\s+log|policy\s+(?:doc(?:ument)?|states?)` +
	`)\b`)

// dialogueLabelRE matches a blockquote marker or a speaker-labelled line
// (User:, Agent:, Assistant:, System:, Attacker:, ...) at the start of a
// line — the shape of a quoted transcript or a moderated discussion thread.
var dialogueLabelRE = regexp.MustCompile(`(?im)^\s*(>|(user|agent|assistant|system|attacker|human|operator|reviewer|issue|comment)\s*:)`)

// agentDirectedCueRE matches a second-person or self-referential cue that
// marks a directive as addressed to the agent/tool/call, as opposed to a
// third-person description of some unrelated policy or system.
var agentDirectedCueRE = regexp.MustCompile(`(?i)\b(you|your|yourself|the\s+agent|the\s+assistant|the\s+model|this\s+tool|this\s+call|this\s+action|this\s+request|this\s+response|this\s+invocation|this\s+function)\b`)

// isQuotedOrAttributed reports whether the byte range [start,end) of text
// sits inside a fenced code block, an inline code span, a blockquote/
// dialogue-labelled line, an open quotation, or near an attribution cue.
func isQuotedOrAttributed(text, lower string, start, end int) bool {
	before := text[:start]

	// Fenced code block: an odd number of ``` markers before start means the
	// match sits inside an open fence.
	if strings.Count(before, "```")%2 == 1 {
		return true
	}

	lineStart := strings.LastIndexByte(before, '\n') + 1

	// Inline code span on the same line: an odd number of backticks since the
	// start of the line means the match sits inside an open span.
	if strings.Count(text[lineStart:start], "`")%2 == 1 {
		return true
	}

	lineEnd := len(text)
	if idx := strings.IndexByte(text[end:], '\n'); idx >= 0 {
		lineEnd = end + idx
	}
	if dialogueLabelRE.MatchString(text[lineStart:lineEnd]) {
		return true
	}

	// Quotation marks: an odd count of straight quotes, or more open than
	// close curly quotes, since the start of the paragraph means the match
	// sits inside an open quotation. Single quotes are deliberately excluded
	// — English contractions ("don't") would otherwise read as unmatched
	// quote characters on every other sentence.
	paraStart := 0
	if idx := strings.LastIndex(before, "\n\n"); idx >= 0 {
		paraStart = idx + 2
	}
	para := text[paraStart:start]
	if strings.Count(para, `"`)%2 == 1 {
		return true
	}
	if strings.Count(para, "“") > strings.Count(para, "”") {
		return true
	}

	windowStart := start - 100
	if windowStart < 0 {
		windowStart = 0
	}
	return attributionCueRE.MatchString(lower[windowStart:start])
}

// hasAgentDirectedCue reports whether the match at [start,end) is addressed
// to the agent: a second-person/self-referential cue within 80 bytes, or the
// match opening its own sentence (bare imperative mood — the classic
// injection shape has no subject because the sentence itself is the command).
func hasAgentDirectedCue(text, lower string, start, end int) bool {
	windowStart := start - 80
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + 80
	if windowEnd > len(lower) {
		windowEnd = len(lower)
	}
	if agentDirectedCueRE.MatchString(lower[windowStart:windowEnd]) {
		return true
	}
	return isImperativeSentenceStart(text, start)
}

// indirectDirectiveTaxonomyRef returns the taxonomy ref for a given signal.
// SignalResponseIndirectConditionalTrigger reuses the existing dedicated node
// created for the description-side signal (its name is not description-
// specific and precisely fits the response-side variant too). The other four
// description-side signals are themselves mapped to the generic
// tool-description-poisoning fallback node in mcp-sentinel.yaml (no dedicated
// node exists for them yet), so their response-side variants use the
// analogous generic response fallback instead of minting a new taxonomy node.
func indirectDirectiveTaxonomyRef(signal ResponseIndirectDirectiveSignal) string {
	if signal == SignalResponseIndirectConditionalTrigger {
		return "unauthorized-execution/agentic-attacks/conditional-trigger-prompt-injection"
	}
	return "unauthorized-execution/agentic-attacks/mcp-tool-response-poisoning"
}

// indirectDirectiveSentinelEngine returns the mcp-sentinel.yaml `engine` key
// that gives a signal's finding a stable rule ID, description, and
// remediation guidance via PolicyEvaluator.LookupSentinel.
func indirectDirectiveSentinelEngine(signal ResponseIndirectDirectiveSignal) string {
	switch signal {
	case SignalResponseIndirectExfiltration:
		return "mcp-response-indirect-exfiltration"
	case SignalResponseIndirectConditionalTrigger:
		return "mcp-response-indirect-conditional-trigger"
	case SignalResponseIndirectApprovalGate:
		return "mcp-response-indirect-approval-gate"
	case SignalResponseIndirectReasoningExfiltration:
		return "mcp-response-indirect-reasoning-exfiltration"
	case SignalResponseIndirectAuditLogEvasion:
		return "mcp-response-indirect-audit-log-evasion"
	default:
		return ""
	}
}

// isImperativeSentenceStart reports whether the byte at start opens its own
// sentence or line — i.e., nothing but whitespace separates it from the start
// of the text or a preceding sentence/line boundary.
func isImperativeSentenceStart(text string, start int) bool {
	i := start - 1
	for i >= 0 && (text[i] == ' ' || text[i] == '\t') {
		i--
	}
	if i < 0 {
		return true
	}
	switch text[i] {
	case '.', '!', '?', '\n', ':', ';', '-', '*':
		return true
	}
	return false
}
