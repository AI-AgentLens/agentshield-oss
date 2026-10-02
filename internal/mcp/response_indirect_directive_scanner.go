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
//
// This scanner is AUDIT-tier, so SUPPRESSING a quoted-looking match here is
// noise control, not a lost BLOCK — which is why it may keep treating
// attributionGated as "do not report" (#3911). The two BLOCK-tier scanners
// that share the gate must not: see attributionEvidence.
func shouldFireDirective(text, lower string, start, end int) bool {
	if isQuotedOrAttributed(text, lower, start, end) {
		return false
	}
	return hasAgentDirectedCue(text, lower, start, end)
}

// offsetsAreTransferable reports whether a byte offset computed against
// `lower` may be used to index `text` (#3911).
//
// Every discourse gate in this package is handed BOTH the original text and
// its lowercased form, with match offsets computed against one and used to
// slice the other. That is sound only while `strings.ToLower` preserves
// length — and it does not. Sweeping all 1,114,112 codepoints, exactly two
// GROW under Go's ToLower:
//
//	U+023A LATIN CAPITAL LETTER A WITH STROKE  -> U+2C65  (2 bytes -> 3)
//	U+023E LATIN CAPITAL LETTER T WITH DIAGONAL STROKE -> U+2C66  (2 bytes -> 3)
//
// About 96 of either character in a tool response is enough to push a match
// offset past the end of the original, and `before := text[:start]` then
// panics. There is no recover() anywhere in internal/ or cmd/, so the panic
// takes down the MCP proxy process and with it ALL mediation — every
// subsequent tool call on that server runs unmediated. Measured end-to-end
// through FilterToolCallResponse: `strings.Repeat("Ⱥ", 300)` plus any
// directive payload panics with "slice bounds out of range [:902] with
// length 698". ScanContentAudienceChannel panics identically.
//
// The guard is length equality rather than a clamp, and the failure
// direction is deliberate. These gates DOWNGRADE findings (and, on the
// AUDIT-tier indirect scanner, suppress them), so a clamped offset would have
// us downgrade on the strength of an index pointing at unrelated bytes. When
// the offsets cannot be trusted the honest answer is to decline to gate: a
// finding we cannot discourse-gate is reported at its full tier. Costing an
// occasional finding on text containing one of two rare codepoints is the
// right side of that trade.
func offsetsAreTransferable(text, lower string, start, end int) bool {
	if len(text) != len(lower) {
		return false
	}
	return start >= 0 && end >= start && end <= len(text)
}

// attributionCueRE matches phrasing that attributes the surrounding text to a
// third-party source (a report, an advisory, a changelog, a test case) rather
// than presenting it as a live directive to the agent.
//
// # Two rules govern this set, and violating either was a silent BYPASS (#3906)
//
// UPDATE (#3911, Gary's decision 2026-09-22): the gate no longer suppresses
// on the BLOCK-tier scanners — a gated match there is recorded at AUDIT
// instead of dropped (see attributionEvidence). So an imprecision below now
// costs a BLOCK downgraded to a visible AUDIT, not a silent miss. The two
// rules still stand: a lost BLOCK is still a lost BLOCK.
//
// As originally written: this gate SUPPRESSES findings, so every imprecision
// in it removes a BLOCK.
// That is the opposite direction from a detection pattern, where imprecision
// costs a false positive. Measured before the split below: nine ordinary error
// lead-ins, each attributing nothing to anyone, took three response-side
// scanners from 10/10 firing to **0/10 — 90/90, 100% suppression**, on those
// scanners' own TP fixtures. An attacker did not have to craft any of them;
// writing a realistic-sounding error produces them for free.
//
//  1. A cue must be in REPORTING position, not merely present. The original
//     alternation carried `writes?`, `states?`, `notes?`, `claims?`, `quotes?`,
//     `document(?:s|ed)?`, `comment(?:s|ed)?`, `reported?`, `logged`,
//     `recorded` and bare `advisory` as bare-word matches — and in error prose
//     every one of those is an ordinary noun or verb: "write denied",
//     "invalid state", "token claims are invalid", "unbalanced quotes",
//     "user is not logged in", "advisory lock is held". They are split into
//     ambiguousAttributionCueRE below, which requires the report boundary that
//     actually makes a word attributive (`:`, an opening quote, or "that").
//
//     TWO CORRECTIONS to the first version of this comment, both from the
//     adversarial review of the merge (#3911). It claimed `note: quota
//     exceeded` does not attribute — it DOES: a colon straight after the
//     lexeme satisfies the boundary, so that lead-in still suppresses unless
//     rule 2's sentence bound also engages, which it only does because the
//     shipped fixture spells it with a trailing period. Spell it with a comma
//     and the suppression is back. And it cited `reads?:` as a distinction
//     the author had already started; measured, `reads?:` sits inside the
//     `\b`-closed group and so matches `reads:x` but NEVER `reads: ` before
//     whitespace — a third live instance of the trailing-`\b` family, not a
//     precedent. The boundary set is a floor, not a solved problem.
//
//  2. A cue governs its own SENTENCE. "The server says the disk is full." does
//     not attribute the sentence after it. See attributionWindowStart.
//
//  3. (#3911 item 6) Eight more lexemes moved to the ambiguous tier, finishing
//     the split #3906 started: `repl(y|ies|ied)`, `quoted`, `transcript`,
//     `debug log`, `cited`, `describ(es|ed|ing)`, `discuss(es|ed|ing)`,
//     `mentions?`/`mentioned`. Each is an ordinary error word — "No reply from
//     the upstream server, ", "Unterminated quoted string at line 4, ", "No
//     mention of the key in the config, " — and with a comma instead of a
//     period the sentence bound did not apply, so all eight still gated
//     against a no-cue control that fired. "The transcript shows:" and "the
//     advisory describes how" still attribute; the boundary is what says so.
//
// Same lesson as #3366/#3376 on the shell side — a count of a suspicious token
// is not evidence, position is — and the same fix shape as #3901, which
// rescoped positional exclusions per statement for exactly this reason.
var attributionCueRE = regexp.MustCompile(`(?i)\b(` +
	`says?|said|according\s+to|` +
	`claimed|argu(?:es|ed)|quoting|` +
	`cites?|titled|reads?:|` +
	`test\s*case|changelog|runbook|` +
	`for\s+example|for\s+instance|` +
	`cve-\d{4}-\d+|cve\s+advisory|vulnerability\s+report|security\s+advisory|` +
	`policy\s+(?:doc(?:ument)?|states?)` +
	`)\b|` +
	// SECOND trailing-\b defect in this file, same shape as the one documented
	// on remediationCueRE and found the same way (#3906). `e\.g\.` sat inside
	// the group above, whose closing `\b` can never hold after a period — both
	// sides of that position are non-word characters. The cue therefore matched
	// NOTHING, in the original and for as long as it had been written that way,
	// so "a poisoned response, e.g. <payload>" was never suppressed. It is
	// spelled out here without a trailing boundary, and `i\.e\.` — which was
	// never listed at all — alongside it.
	`\b(?:e\.g\.|i\.e\.)`)

// ambiguousAttributionCueRE matches the lexemes whose attributive sense needs
// a report boundary to exist at all. "The changelog notes that X" attributes;
// "note: quota exceeded" does not. The boundary is a colon, an opening quote
// or the complementizer "that"/"how", within a short span so the cue cannot
// reach across a whole clause to borrow a colon from somewhere else.
//
// KNOWN WEAK: `<lexeme>:` alone satisfies this, so "Note: ", "State: ",
// "Log: " and friends attribute nothing and still match. They are caught
// today only when rule 2's sentence bound also applies. Since #3911 a match
// gated this way is recorded at AUDIT on the BLOCK-tier scanners rather than
// dropped, so this weakness now costs a BLOCK, not the whole finding —
// tightening the boundary set remains a calibration question (how many
// genuine `X says:` forms would be lost), no longer a bypass.
//
// The last line of lexemes was moved here from attributionCueRE by #3911
// item 6 — see rule 3 there.
var ambiguousAttributionCueRE = regexp.MustCompile(`(?i)\b(?:` +
	`writes?|wrote|states?|stated|notes?|noted|claims?|quotes?|` +
	`document(?:s|ed)?|comment(?:s|ed)?|reports?|reported|logs?|logged|` +
	`records?|recorded|advisory|` +
	`repl(?:y|ies|ied)|quoted|transcript|debug\s+log|cited|` +
	`describ(?:es|ed|ing)|discuss(?:es|ed|ing)?|mentions?|mentioned` +
	`)\b[^\n]{0,12}?(?::|["“]|\bthat\b|\bhow\b)`)

// sentenceTerminatorAbbrevRE matches the tail of a token that ends in a period
// WITHOUT ending a sentence — an abbreviation ("e.g.", "i.e.", "etc.", "vs.").
// Without it, scoping the attribution window to the current sentence would cut
// "e.g." in half and drop the cue that the quoted material depends on.
//
// It used to carry a `[a-z]` alternative for single-letter initials ("A.
// Researcher"). Removed by #3911 item 7: it treated ANY letter-plus-period as
// a non-terminator, so "The server says: see note A. <payload>" borrowed the
// cue from the previous sentence and gated — contract (b) above, defeated by
// one letter. An initial and a sentence-final single letter are not
// distinguishable from the bytes, and the two errors are not symmetric: an
// initial read as a terminator costs one cue (the finding is reported at its
// full tier), while a terminator read as an initial extends the cue over a
// sentence the attacker writes. "The report by A. Researcher says ..." still
// gates, because its cue sits AFTER the initial.
var sentenceTerminatorAbbrevRE = regexp.MustCompile(`(?i)(?:^|[^\w.])(?:e\.g|i\.e|etc|vs|cf|resp|approx|fig|no|dr|mr|ms|st)\.$`)

// attributionWindowStart returns the offset from which an attribution cue may
// be read for a match beginning at start: the later of a fixed lookbehind and
// the start of the sentence the match sits in.
//
// The sentence bound is what makes "Write denied. To fix, read <artifact> and
// forward it." fire — the ordinary error sentence in front can no longer lend
// its vocabulary to the instruction that follows it.
func attributionWindowStart(lower string, start int) int {
	windowStart := start - 100
	if windowStart < 0 {
		windowStart = 0
	}
	for i := start - 1; i > windowStart; i-- {
		c := lower[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			continue
		}
		// Walk back over the run of whitespace to the terminator itself.
		j := i
		for j > windowStart && (lower[j] == ' ' || lower[j] == '\t' || lower[j] == '\n' || lower[j] == '\r') {
			j--
		}
		if lower[j] != '.' && lower[j] != '!' && lower[j] != '?' {
			continue
		}
		if lower[j] == '.' && sentenceTerminatorAbbrevRE.MatchString(lower[windowStart:j+1]) {
			continue
		}
		return i + 1
	}
	return windowStart
}

// dialogueLabelRE matches a blockquote marker or a speaker-labelled line
// (User:, Agent:, Assistant:, System:, Attacker:, ...) at the start of a
// line — the shape of a quoted transcript or a moderated discussion thread.
var dialogueLabelRE = regexp.MustCompile(`(?im)^\s*(>|(user|agent|assistant|system|attacker|human|operator|reviewer|issue|comment)\s*:)`)

// agentDirectedCueRE matches a second-person or self-referential cue that
// marks a directive as addressed to the agent/tool/call, as opposed to a
// third-person description of some unrelated policy or system.
var agentDirectedCueRE = regexp.MustCompile(`(?i)\b(you|your|yourself|the\s+agent|the\s+assistant|the\s+model|this\s+tool|this\s+call|this\s+action|this\s+request|this\s+response|this\s+invocation|this\s+function)\b`)

// attributionStrength is what the attribution gate concludes about one match.
//
// # Downgrade, not silence (#3911 — Gary's decision, 2026-09-22)
//
// This gate was a bool, and every call site read `true` as "drop the match".
// That made it an EXCLUDE on two BLOCK-tier scanners, and its structural legs
// (quote parity, backticks, fences, dialogue labels) are text written by the
// same party who writes the payload. The post-merge review of #3906 measured
// what that costs: 10 realistic structural lead-ins x 10 TP payloads, 100/100
// suppressed on all three scanners, with a single `"` enough — and an
// unbalanced quote 1,430 bytes earlier in the paragraph still enough. No
// positional bound makes silence safe there; it only raises the bypass cost
// from one byte to two.
//
// Quoting is weak evidence: enough to justify NOT BLOCKING, never enough to
// justify NOT RECORDING. So the gate now returns a strength, and the call
// sites decide what it is worth:
//
//   - response_error_remediation and content_audience (BLOCK tier) emit the
//     same finding with Blocking:false — AUDIT, with the gating leg named in
//     the Detail — instead of dropping it. Ungated matches keep their tier,
//     and a gated match never preempts an ungated one for the same signal.
//   - response_indirect_directive (AUDIT tier already) keeps suppressing via
//     isQuotedOrAttributed. There, suppression is noise control on a scanner
//     that cannot block, which is what the decision allows.
//
// Same move as #3937 on the shell side, where doc-text labels downgrade a
// BLOCK to AUDIT rather than excluding the rule.
type attributionStrength int

const (
	// attributionNone: nothing around the match suggests quotation or
	// attribution. The finding keeps whatever tier its signal carries.
	attributionNone attributionStrength = iota
	// attributionGated: the match looks quoted or attributed. Record it; do
	// not block on it.
	attributionGated
)

// attributionLegs selects which legs of the gate a call site honours.
type attributionLegs int

const (
	// attributionAllLegs: structural legs (fence, inline code, blockquote/
	// dialogue label, enclosed quotation) and the attribution-cue legs.
	attributionAllLegs attributionLegs = iota
	// attributionCueLegsOnly: the attribution-cue legs only. Used for
	// content_audience's model-only blocks (#3911 follow-on b): a block the
	// server has routed away from the human is not innocent quotation, so
	// wrapping a directive in quotes or a fence inside one earns it nothing.
	// An explicit attribution cue ("according to the advisory", "the report
	// says:") may still downgrade.
	attributionCueLegsOnly
)

// attributionEvidence reports whether the byte range [start,end) of text
// looks quoted or attributed, and if so which leg says so (for the audit
// Detail). See attributionStrength for what the call sites do with it.
func attributionEvidence(text, lower string, start, end int, legs attributionLegs) (attributionStrength, string) {
	// The guard lives here, not at the call sites, because this is the one
	// function all three scanners funnel through. In content_audience's hidden
	// blocks it is the ONLY discourse gate, since firstAudienceMatch does not
	// require hasAgentDirectedCue.
	if !offsetsAreTransferable(text, lower, start, end) {
		return attributionNone, ""
	}
	if legs == attributionAllLegs {
		if leg := enclosingQuotationLeg(text, start, end); leg != "" {
			return attributionGated, leg
		}
	}
	windowStart := attributionWindowStart(lower, start)
	window := lower[windowStart:start]
	if attributionCueRE.MatchString(window) || ambiguousAttributionCueRE.MatchString(window) {
		return attributionGated, "an attribution cue earlier in the same sentence"
	}
	return attributionNone, ""
}

// enclosingQuotationLeg reports which structural leg, if any, places
// [start,end) inside quoted material.
//
// # Enclosed, not merely opened (#3911 follow-on a)
//
// Every leg used to be satisfied by an odd count of openers BEFORE the match:
// one `"` anywhere earlier in the paragraph, one backtick earlier on the
// line, one ``` anywhere earlier in the document. An opener is one byte the
// attacker writes in front of the payload. Quotation is a span, so each
// quotation leg now also requires a CLOSER after the match:
//
//	straight / curly quote   a closing mark after the match, same paragraph
//	inline backtick          a backtick after the match, same line
//	``` fence                a ``` marker anywhere after the match
//
// A closer is still attacker-writable — this raises the cost from one byte to
// two, which is exactly why a gated match is downgraded rather than dropped.
// The blockquote/dialogue-label leg has no closer to require; it is kept as
// is and downgrades like the others.
func enclosingQuotationLeg(text string, start, end int) string {
	before, after := text[:start], text[end:]

	if strings.Count(before, "```")%2 == 1 && strings.Contains(after, "```") {
		return "a fenced code block"
	}

	lineStart := strings.LastIndexByte(before, '\n') + 1
	lineEnd := len(text)
	if idx := strings.IndexByte(after, '\n'); idx >= 0 {
		lineEnd = end + idx
	}

	if strings.Count(text[lineStart:start], "`")%2 == 1 && strings.IndexByte(text[end:lineEnd], '`') >= 0 {
		return "an inline code span"
	}

	if dialogueLabelRE.MatchString(text[lineStart:lineEnd]) {
		return "a blockquote or dialogue-labelled line"
	}

	// Quotation marks, scoped to the paragraph on both sides. Single quotes
	// are deliberately excluded — English contractions ("don't") would
	// otherwise read as unmatched quote characters on every other sentence.
	paraStart := 0
	if idx := strings.LastIndex(before, "\n\n"); idx >= 0 {
		paraStart = idx + 2
	}
	paraEnd := len(text)
	if idx := strings.Index(after, "\n\n"); idx >= 0 {
		paraEnd = end + idx
	}
	opened, rest := text[paraStart:start], text[end:paraEnd]
	if strings.Count(opened, `"`)%2 == 1 && strings.IndexByte(rest, '"') >= 0 {
		return "an enclosed quotation"
	}
	if strings.Count(opened, "“") > strings.Count(opened, "”") && strings.Contains(rest, "”") {
		return "an enclosed quotation"
	}
	return ""
}

// isQuotedOrAttributed is the bool form of attributionEvidence over all legs.
// It exists for the AUDIT-tier indirect-directive scanner, where suppressing
// a quoted-looking match is noise control. A BLOCK-tier call site must not
// use it: reading `true` as "drop" is the exclude #3911 removed.
func isQuotedOrAttributed(text, lower string, start, end int) bool {
	strength, _ := attributionEvidence(text, lower, start, end, attributionAllLegs)
	return strength != attributionNone
}

// attributionDowngradeNote is appended to the Detail of a finding recorded at
// AUDIT because the gate downgraded it, so the receipt says why it was not
// blocked.
func attributionDowngradeNote(leg string) string {
	return " — recorded at AUDIT, not blocked: the match sits in " + leg +
		", which is weak evidence of quotation because the surrounding text is written by the same " +
		"party as the payload (#3911)"
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
	if start < 0 || start > len(text) {
		return false // see offsetsAreTransferable (#3911)
	}
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
