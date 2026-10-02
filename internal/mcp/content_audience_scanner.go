package mcp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// Content-block audience channel — MCP's own routing annotation as a covert
// instruction channel.
//
// # The surface
//
// Every MCP content block may carry an `annotations` object, and its
// `audience` field declares who the block is for: `["user"]`, `["assistant"]`,
// or both. The spec's stated purpose is presentation — a host uses it to
// decide what to render. So a block annotated `audience: ["assistant"]` is the
// server asking the host to route the content to the model while withholding
// it from the human.
//
// That is a human-oversight-evasion primitive hiding in plain sight, and it
// was invisible here twice over: ContentItem did not parse `annotations` at
// all (json.Unmarshal dropped it), and no scanner in this package read it.
//
// # Why the annotation is worth more than another pattern list
//
// response_indirect_directive_scanner.go documents the hard problem on this
// surface (issue #3435): a tool description that says "do not tell the user"
// IS a directive, while a tool response that says it is very often QUOTING
// one. Its solution admits a match only when it clears two discourse gates —
// isQuotedOrAttributed (not quoted/fenced/attributed) and hasAgentDirectedCue
// (second-person cue nearby, or bare imperative sentence start). The second
// gate is an approximation of "is this addressed to the agent", and because
// person and position are weak discriminators, everything it admits is
// deliberately AUDIT-tier rather than BLOCK.
//
// `audience: ["assistant"]` answers that same question directly, and the
// server answers it itself. Two consequences, and both are used below:
//
//  1. ESCALATION. A directive that already clears both discourse gates and
//     arrives in a model-only block is no longer resting on a weak proxy for
//     "addressed to the agent" — the routing annotation says so. The residual
//     FP risk that capped those findings at AUDIT is gone, so the same finding
//     is worth BLOCK here (SignalAudienceHiddenDirectiveEscalation).
//
//  2. ADMISSION. A directive that clears the quotation gate but FAILS the
//     agent-directed-cue gate — third-person, mid-sentence, no pronoun — is
//     silently dropped today. In a model-only block the addressee is supplied
//     structurally, so the cue is not needed and the match is admitted, at
//     AUDIT tier (SignalAudienceHiddenLatentDirective).
//
// Correction (#3911): in a model-only block the quotation gate is no longer
// the ordinary response surface's gate. Its structural legs (quotes,
// backticks, fences, blockquote/dialogue labels) do not apply — the server
// routed the block away from the human, so a fence inside it is not innocent
// quotation — and a match behind an attribution cue is recorded at AUDIT
// instead of dropped. See scanHiddenBlockText.
//
// Two further shapes exist only because the audience field exists:
// an instruction to conceal information from the human, delivered in a block
// the human is already not being shown (SignalAudienceHiddenUserConcealment);
// and a result that tells the human one thing and the model another
// (SignalAudiencePartitionedDivergence).
//
// # What is deliberately NOT flagged
//
// `audience: ["assistant"]` on its own is legitimate and common — raw JSON,
// logs, retrieved document bodies, anything a host would rather not paste into
// the transcript. Nothing here fires on the annotation alone. Every signal
// requires the annotation AND content that has no business being in a block
// the human cannot see.
//
// credentialHarvestPatterns is deliberately excluded from the directive-class
// sets. It is a REFERENCE detector calibrated for tool descriptions, where the
// string "~/.aws" is anomalous; in fetched response content a mention of
// "api key" or ".env" is ordinary prose and would fire constantly.
//
// # Known, accepted residual
//
// A policy document carried in a model-only block that states a third-person
// fact about approvals — "hotfixes are pre-approved under the emergency change
// policy" — produces a latent-directive AUDIT. That is the intended outcome
// rather than a false positive to tune away: an unreviewable block asserting
// that something is pre-authorised is the shape, and AUDIT is where a claim
// that weak belongs. It is called out here so the next reader does not
// "fix" it into a miss.
type ContentAudienceSignal string

const (
	// SignalAudienceHiddenUserConcealment fires when a model-only block
	// instructs the agent to withhold information from the user, operator, or
	// reviewer. The block is already hidden from the human by annotation and
	// its content asks for further concealment — there is no benign reading.
	SignalAudienceHiddenUserConcealment ContentAudienceSignal = "audience_hidden_user_concealment"

	// SignalAudienceHiddenDirectiveEscalation fires when a model-only block
	// carries a directive that clears BOTH discourse gates used on the
	// ordinary response surface. Same finding, escalated from AUDIT to BLOCK
	// because the routing annotation, not a pronoun-position heuristic,
	// establishes that the content is addressed to the agent.
	SignalAudienceHiddenDirectiveEscalation ContentAudienceSignal = "audience_hidden_directive_escalation"

	// SignalAudienceHiddenLatentDirective fires when a model-only block
	// carries a directive that clears the quotation/attribution gate but has
	// no second-person cue and does not open its own sentence — the class the
	// response surface drops today. AUDIT tier: the annotation supplies the
	// addressee, but a third-person statement is still a weaker signal than
	// an imperative one.
	SignalAudienceHiddenLatentDirective ContentAudienceSignal = "audience_hidden_latent_directive"

	// SignalAudiencePartitionedDivergence fires when one result tells the
	// human that nothing happened (or that the operation was blocked) in a
	// user-visible block, while a model-only block instructs the agent to
	// carry out a state-changing action. The human reviews the first half and
	// the model acts on the second.
	SignalAudiencePartitionedDivergence ContentAudienceSignal = "audience_partitioned_divergence"
)

// ContentAudienceFinding records one detection.
type ContentAudienceFinding struct {
	Signal       ContentAudienceSignal `json:"signal"`
	Detail       string                `json:"detail"`
	ContentIndex int                   `json:"content_index"`
	Snippet      string                `json:"snippet,omitempty"`
	// Blocking distinguishes the BLOCK-tier signals from the AUDIT-tier one so
	// the call site can act on a mixed-tier result without re-deriving the
	// mapping from the signal name. False on a BLOCK-tier signal when the
	// attribution gate downgraded it (AttributionGated).
	Blocking bool `json:"blocking"`
	// AttributionGated records that the match sat behind an explicit
	// attribution cue, so it was recorded at AUDIT instead of blocked (#3911).
	// Before #3911 such a match produced no finding at all.
	AttributionGated bool `json:"attribution_gated,omitempty"`
}

// ContentAudienceScanResult is the outcome of ScanContentAudienceChannel.
type ContentAudienceScanResult struct {
	// Blocked is true when at least one BLOCK-tier finding was produced.
	Blocked bool `json:"blocked"`
	// Found is true when any finding was produced, at any tier.
	Found    bool                     `json:"found"`
	Findings []ContentAudienceFinding `json:"findings,omitempty"`
}

// ScanContentAudienceChannel inspects a tool result's content blocks for abuse
// of the `annotations.audience` routing field. Blocks with no audience
// restriction are treated as visible to both parties and are not scanned here
// — the ordinary response scanners already cover them.
func ScanContentAudienceChannel(items []ContentItem) ContentAudienceScanResult {
	result := scanContentAudienceForm(items)
	scanContentAudienceRenderRecovered(&result, items, scanContentAudienceForm)
	return finalizeContentAudienceResult(result)
}

// ScanPromptsGetAudienceChannel is ScanContentAudienceChannel adapted for a
// prompts/get response. A PromptMessage's content block carries `annotations`
// in exactly the same place TextContent/EmbeddedResource does on the
// tools/call surface (see PromptMessageContent.Annotations) — arguably a
// higher-value surface for this channel than tool results, since prompt
// content is spliced into the agent's context wholesale rather than returned
// as one tool's output among many.
//
// Only "text" and "resource" blocks carry scannable text; "image" blocks are
// skipped, matching ScanPromptsGetResponse's own handling. A "resource"
// block's annotations live on the outer PromptMessageContent (the
// EmbeddedResource per spec), not on the nested ResourceContentItem — which
// has no `annotations` field at all, see its doc comment in types.go — so the
// conversion below reads Annotations from the message content, not the
// resource.
func ScanPromptsGetAudienceChannel(result *GetPromptResult) ContentAudienceScanResult {
	if result == nil {
		return ContentAudienceScanResult{}
	}
	items := make([]ContentItem, 0, len(result.Messages))
	for _, msg := range result.Messages {
		switch msg.Content.Type {
		case "text":
			if msg.Content.Text == "" {
				continue
			}
			items = append(items, ContentItem{Type: "text", Text: msg.Content.Text, Annotations: msg.Content.Annotations})
		case "resource":
			if msg.Content.Resource == nil || msg.Content.Resource.Text == "" {
				continue
			}
			items = append(items, ContentItem{Type: "text", Text: msg.Content.Resource.Text, Annotations: msg.Content.Annotations})
		}
	}
	return ScanContentAudienceChannel(items)
}

// ScanResourceListAudienceChannel is ScanContentAudienceChannel adapted for a
// resources/list response. Per spec, `Resource` (a resources/list entry)
// carries `annotations` directly on the entry — see ResourceEntry.Annotations
// in types.go — unlike TextResourceContents/BlobResourceContents (a
// resources/read `contents[]` item), which the spec gives no `annotations`
// field at all. The scanned text is the entry's Description: the field a host
// renders when a human is browsing what to read next, so an
// audience:["assistant"]-annotated description is content the server is
// routing to the model's decision-making while withholding it from the human
// doing the browsing.
//
// Deliberately does NOT run the partitioned-divergence check
// (SignalAudiencePartitionedDivergence). That signal compares a user-visible
// claim against a hidden directive WITHIN one coherent response — two halves
// of the same answer. resources/list entries are independent resources with
// unrelated descriptions; comparing entry N's visible text against entry M's
// hidden text would manufacture a pairing that was never a single response,
// producing findings with no coherent narrative to attach to an attestation.
func ScanResourceListAudienceChannel(entries []ResourceEntry) ContentAudienceScanResult {
	items := make([]ContentItem, 0, len(entries))
	for _, e := range entries {
		if e.Description == "" {
			continue
		}
		items = append(items, ContentItem{Type: "text", Text: e.Description, Annotations: e.Annotations})
	}
	result := scanHiddenBlocks(items)
	scanContentAudienceRenderRecovered(&result, items, scanHiddenBlocks)
	return finalizeContentAudienceResult(result)
}

func scanContentAudienceForm(items []ContentItem) ContentAudienceScanResult {
	result := scanHiddenBlocks(items)
	scanAudiencePartitionedDivergence(&result, items)
	return result
}

// scanHiddenBlocks runs the per-block directive scan (concealment,
// escalation, latent-directive) over every hidden-from-user text block, with
// no cross-block comparison. Split out from scanContentAudienceForm so the
// resources/list adapter can reuse it without the partitioned-divergence
// check, which does not transfer to that surface — see
// ScanResourceListAudienceChannel.
func scanHiddenBlocks(items []ContentItem) ContentAudienceScanResult {
	var result ContentAudienceScanResult
	for i, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		if !item.Annotations.HiddenFromUser() {
			continue
		}
		scanHiddenBlockText(&result, i, item.Text)
	}
	return result
}

// finalizeContentAudienceResult derives Blocked/Found from the accumulated
// findings. Shared by every surface adapter so the tier-derivation logic
// cannot drift between them.
//
// It also orders ungated findings ahead of attribution-gated ones (#3911),
// stably. Call sites read Findings[0] for the audit TaxonomyRef and the BLOCK
// reason; gated findings did not exist before #3911, so putting them last
// keeps both exactly what they were for any result that has an ungated
// finding.
func finalizeContentAudienceResult(result ContentAudienceScanResult) ContentAudienceScanResult {
	if len(result.Findings) > 0 {
		ordered := make([]ContentAudienceFinding, 0, len(result.Findings))
		for _, f := range result.Findings {
			if !f.AttributionGated {
				ordered = append(ordered, f)
			}
		}
		for _, f := range result.Findings {
			if f.AttributionGated {
				ordered = append(ordered, f)
			}
		}
		result.Findings = ordered
	}
	for _, f := range result.Findings {
		if f.Blocking {
			result.Blocked = true
			break
		}
	}
	result.Found = len(result.Findings) > 0
	return result
}

// scanContentAudienceRenderRecovered re-runs the whole scan over text that has
// had codepoint-level disguises undone, and appends only findings the raw pass
// did not already produce.
//
// Without it every signal in this file is defeated by one substitution.
// Measured on introduction: a fullwidth spelling of a concealment directive in
// a model-only block scored zero here AND zero on the ordinary response
// scanner, turning a BLOCK into silence. Soft hyphens and the two axes
// combined do the same — the "per-axis folds do not compose" result that
// produced unicode.RecoverRenderedText in the first place.
//
// This is the third place that lesson has had to be applied by hand
// (description_scanner.go, response_scanner.go, here). It is deliberately the
// same shape as scanResponseRenderRecovered so the three stay recognisable as
// one mitigation:
//
//   - Recovery is a text transform, never a verdict. An invisible character is
//     not reported; only a directive that recovery made readable is. That
//     folded-but-not-raw gate is what makes it structurally FP-free — benign
//     prose does not recover into an exfiltration directive.
//   - Snippets come from the recovered text, because a raw-offset snippet
//     renders as the visually identical string that did not match. The Detail
//     says so, so an audit entry never implies the bytes arrived in the clear.
//
// Note that ScanToolCallResponseForIndirectDirectives, which shares this
// file's pattern sets, has no recovery pass either — see issue #3485.
func scanContentAudienceRenderRecovered(result *ContentAudienceScanResult, items []ContentItem, scanFn func([]ContentItem) ContentAudienceScanResult) {
	recoveredItems, changed := recoverContentItemText(items)
	if !changed {
		return
	}

	// seen maps a finding key to whether the finding already held for it was
	// attribution-gated. A gated raw finding must not shadow an UNGATED
	// recovered one (#3911): before gated findings existed the raw pass
	// produced nothing for that key and the recovered BLOCK was appended, so
	// the gated one is dropped and the recovered one takes its place.
	seen := make(map[string]bool, len(result.Findings))
	for _, f := range result.Findings {
		seen[string(f.Signal)+"\x00"+strconv.Itoa(f.ContentIndex)] = f.AttributionGated
	}

	for _, f := range scanFn(recoveredItems).Findings {
		key := string(f.Signal) + "\x00" + strconv.Itoa(f.ContentIndex)
		if heldGated, held := seen[key]; held {
			if !heldGated || f.AttributionGated {
				continue
			}
			kept := result.Findings[:0]
			for _, g := range result.Findings {
				if string(g.Signal)+"\x00"+strconv.Itoa(g.ContentIndex) != key {
					kept = append(kept, g)
				}
			}
			result.Findings = kept
		}
		seen[key] = f.AttributionGated
		f.Detail += " — recovered by undoing codepoint-level disguises (invisible formatters " +
			"such as U+00AD SOFT HYPHEN removed; blank-rendering fillers and Unicode separators " +
			"folded to ASCII space; fullwidth/mathematical and Cyrillic/Greek confusables folded " +
			"to Latin). The text as sent matched no pattern while rendering as ordinary English"
		result.Findings = append(result.Findings, f)
	}
}

// recoverContentItemText returns a copy of items whose text blocks have had
// rendering-identical disguises undone, and whether anything changed. The
// annotations are carried over unchanged — the audience field is what decides
// admission, and it is structured JSON, not prose.
func recoverContentItemText(items []ContentItem) ([]ContentItem, bool) {
	var changed bool
	out := make([]ContentItem, len(items))
	copy(out, items)
	for i, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		recovered, itemChanged := pkgunicode.RecoverRenderedText(item.Text)
		if !itemChanged {
			continue
		}
		out[i].Text = recovered
		changed = true
	}
	return out, changed
}

// hiddenDirectiveClasses is the five-class directive pattern set shared with
// the ordinary response surface. Reusing the vars rather than copying them
// keeps the two surfaces from drifting apart, which is the failure mode that
// produced the description-vs-response gap in the first place.
var hiddenDirectiveClasses = []struct {
	patterns []signalPattern
	class    string
}{
	{exfiltrationPatterns, "exfiltration directive"},
	{conditionalTriggerPatterns, "conditional (sleeper) trigger"},
	{approvalGateManipulationPatterns, "approval-gate manipulation"},
}

// hiddenDirectiveCooccurrences is the co-occurrence half of the same five
// classes: an agent-private-state noun or security-log noun that must appear
// near a transfer or suppression verb.
var hiddenDirectiveCooccurrences = []struct {
	nounRE, verbRE *regexp.Regexp
	window         int
	class          string
}{
	{agentPrivateReasoningRE, reasoningTransferVerbRE, 160, "reasoning / system-prompt exfiltration"},
	{auditSecurityNounRE, auditSuppressionVerbRE, 180, "audit-log evasion"},
}

// scanHiddenBlockText produces at most one finding per model-only block.
//
// # The attribution gate downgrades here; it does not drop (#3911)
//
// Every match is judged by attributionEvidence with attributionCueLegsOnly.
// Two decisions from #3911, both Gary's (2026-09-22):
//
//   - A gated match is recorded at AUDIT (Blocking:false, AttributionGated),
//     not dropped. Before, one `"` in front of a concealment directive was the
//     only thing between it and a BLOCK — firstAudienceMatch does not require
//     hasAgentDirectedCue, so the quotation gate was the sole discourse gate.
//   - The STRUCTURAL legs (quotes, backticks, fences, blockquote/dialogue
//     labels) do not apply at all in a model-only block. A server that routes
//     a block away from the human has already said who it is for; wrapping a
//     directive in a fence there is not innocent quotation. An explicit
//     attribution cue may still downgrade.
//
// Order is what keeps ungated behaviour byte-identical to before: an ungated
// match wins exactly as it did (concealment first, then the directive
// classes in order) and a gated match only surfaces, as a fallback, when no
// ungated match exists anywhere in the block.
func scanHiddenBlockText(result *ContentAudienceScanResult, idx int, text string) {
	lower := strings.ToLower(text)
	var fallback *ContentAudienceFinding
	keep := func(f ContentAudienceFinding, m audienceMatch) bool {
		if m.strength == attributionNone {
			result.Findings = append(result.Findings, f)
			return true
		}
		if fallback == nil {
			f.Blocking = false
			f.AttributionGated = true
			f.Detail += attributionDowngradeNote(m.leg)
			fallback = &f
		}
		return false
	}

	// Concealment directive — BLOCK. Checked first: it is the signal specific
	// to this surface, so attributing the finding to it is more useful than
	// attributing it to a generic directive class it may also match.
	if m, ok := firstAudienceMatch(userConcealmentPatterns, text, lower); ok {
		f := ContentAudienceFinding{
			Signal: SignalAudienceHiddenUserConcealment,
			Detail: "content block annotated audience:[\"assistant\"] (withheld from the user) " +
				"instructs the agent to conceal information from the user or operator — " + m.desc,
			ContentIndex: idx,
			Snippet:      safeSnippet(text, m.loc, 100),
			Blocking:     true,
		}
		if keep(f, m) {
			return
		}
	}

	// Directive classes. A match that also clears the agent-directed-cue gate
	// escalates to BLOCK; one that does not is admitted at AUDIT.
	for _, cls := range hiddenDirectiveClasses {
		if m, ok := firstAudienceMatch(cls.patterns, text, lower); ok {
			if keep(directiveFinding(idx, text, m.loc, cls.class+" ("+m.desc+")", m.directed), m) {
				return
			}
		}
	}
	for _, co := range hiddenDirectiveCooccurrences {
		if m, ok := firstAudienceCooccurrence(co.nounRE, co.verbRE, co.window, text, lower); ok {
			if keep(directiveFinding(idx, text, m.loc, co.class, m.directed), m) {
				return
			}
		}
	}
	if fallback != nil {
		result.Findings = append(result.Findings, *fallback)
	}
}

func directiveFinding(idx int, text string, loc int, class string, directed bool) ContentAudienceFinding {
	if directed {
		return ContentAudienceFinding{
			Signal: SignalAudienceHiddenDirectiveEscalation,
			Detail: "content block annotated audience:[\"assistant\"] (withheld from the user) " +
				"carries an agent-directed " + class + ". On an unannotated block this is an AUDIT " +
				"finding because person and position are weak evidence of who is being addressed; " +
				"the audience annotation is the server's own statement that the addressee is the model",
			ContentIndex: idx,
			Snippet:      safeSnippet(text, loc, 100),
			Blocking:     true,
		}
	}
	return ContentAudienceFinding{
		Signal: SignalAudienceHiddenLatentDirective,
		Detail: "content block annotated audience:[\"assistant\"] (withheld from the user) " +
			"carries a " + class + " with no second-person cue and no imperative sentence start. " +
			"The ordinary response surface drops this class for want of an addressee; the audience " +
			"annotation supplies one",
		ContentIndex: idx,
		Snippet:      safeSnippet(text, loc, 100),
		Blocking:     false,
	}
}

// audienceMatch is one pattern match in a model-only block, with what the
// attribution gate made of it.
type audienceMatch struct {
	loc      int
	desc     string
	directed bool
	strength attributionStrength
	leg      string
}

// firstAudienceMatch returns the first match the attribution gate leaves
// ungated, or — only when there is none — the first gated one. Patterns are
// tried in order and every location of a pattern before the next, exactly as
// before #3911, so the ungated match returned is the one that was returned
// then. directed reports whether the match also clears the agent-directed-cue
// gate; unlike firstDirectedMatch that gate is not REQUIRED here — in a
// model-only block the audience annotation supplies the addressee the cue was
// standing in for.
func firstAudienceMatch(patterns []signalPattern, text, lower string) (audienceMatch, bool) {
	var gated audienceMatch
	haveGated := false
	for _, p := range patterns {
		for _, loc := range p.re.FindAllStringIndex(lower, -1) {
			strength, leg := attributionEvidence(text, lower, loc[0], loc[1], attributionCueLegsOnly)
			if strength == attributionNone {
				return audienceMatch{loc[0], p.description, hasAgentDirectedCue(text, lower, loc[0], loc[1]), strength, leg}, true
			}
			if !haveGated {
				gated = audienceMatch{loc[0], p.description, hasAgentDirectedCue(text, lower, loc[0], loc[1]), strength, leg}
				haveGated = true
			}
		}
	}
	return gated, haveGated
}

// firstAudienceCooccurrence is the co-occurrence equivalent of
// firstAudienceMatch.
func firstAudienceCooccurrence(nounRE, verbRE *regexp.Regexp, window int, text, lower string) (audienceMatch, bool) {
	var gated audienceMatch
	haveGated := false
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
		strength, leg := attributionEvidence(text, lower, loc[0], loc[1], attributionCueLegsOnly)
		if strength == attributionNone {
			return audienceMatch{loc[0], "", hasAgentDirectedCue(text, lower, loc[0], loc[1]), strength, leg}, true
		}
		if !haveGated {
			gated = audienceMatch{loc[0], "", hasAgentDirectedCue(text, lower, loc[0], loc[1]), strength, leg}
			haveGated = true
		}
	}
	return gated, haveGated
}

// userConcealmentPatterns match directives to withhold information from the
// human. Every alternative names the human (user / operator / reviewer) or a
// human-facing artefact (the summary, the report, the answer), so ordinary
// documentation prose — "do not commit node_modules", "never expose the port"
// — does not match.
var userConcealmentPatterns = []signalPattern{
	// The human is the DIRECT object: "do not tell the user", "never inform
	// the operator". Only tell-class verbs, so "never expose the port to the
	// user" is not in scope.
	{regexp.MustCompile(`(do\s+not|do\s*n['’]?t|don['’]?t|never|avoid)\s+(ever\s+)?(tell|telling|inform|informing|notify|notifying|alert|alerting)\s+(the\s+)?(user|human|operator|reviewer|approver)\b`),
		"directs the agent not to tell the user"},
	// The CONTENT is the direct object and the human is the recipient, with
	// the object restricted to a deictic reference back to this block. This
	// is what keeps ordinary documentation out: "never display raw stack
	// traces to the user" has a non-deictic object and does not match.
	{regexp.MustCompile(`(do\s+not|do\s*n['’]?t|don['’]?t|never|avoid)\s+(ever\s+)?(tell|inform|notify|alert|show|reveal|disclose|display|mention|surface|report|expose)\s+(this|that|it|these|those|any\s+of\s+this|the\s+(above|following|preceding|change|changes|edit|edits|step|steps))\s+(to\s+)?(the\s+)?(user|human|operator|reviewer|approver)\b`),
		"directs the agent not to show this content to the user"},
	{regexp.MustCompile(`without\s+(ever\s+)?(telling|informing|notifying|alerting|asking|consulting|involving|showing)\s+(the\s+)?(user|human|operator|reviewer|approver)\b`),
		"directs the agent to act without telling the user"},
	{regexp.MustCompile(`(hide|hiding|conceal|concealing|omit|omitting|suppress|suppressing|exclude|excluding|redact|redacting)\s+([\w'’]+\s+){0,4}?(from|out\s+of)\s+(the\s+|your\s+|any\s+)?(user|human|operator|reviewer|summary|summaries|report|final\s+(answer|response|output)|visible\s+output|transcript)\b`),
		"directs the agent to hide content from the user or the summary"},
	{regexp.MustCompile(`(do\s+not|do\s*n['’]?t|don['’]?t|never)\s+(include|mention|list|log|echo|repeat|quote|show)\s+(this|these|that|those|it|any\s+of\s+this)\s+(in|to)\s+(the|your)\s+(summary|response|output|report|answer|reply|message|explanation)\b`),
		"directs the agent to keep content out of its user-facing output"},
	{regexp.MustCompile(`keep\s+(this|these|that|it|the\s+following)\s+(step\s+|part\s+|detail\s+|change\s+)?(secret|hidden|private|confidential|to\s+yourself|between\s+us|off\s+the\s+record)\b`),
		"directs the agent to keep content secret"},
	{regexp.MustCompile(`(this|these|the\s+following)\s+(instruction|directive|message|note|section|block)s?\s+(is|are)\s+(not\s+)?(meant\s+)?(only\s+)?for\s+(you|the\s+(assistant|model|agent|ai))\b`),
		"declares the content is for the model only"},
}

// --- Partitioned divergence -------------------------------------------------

// benignOutcomeClaimRE matches a user-visible claim that nothing happened or
// that the operation did not go through. Deliberately narrow: "completed
// successfully" and bare "dry run" are excluded because they are ordinary tool
// output that coexists with real work. What is required is a claim of NO
// state change or of an operation that was stopped.
var benignOutcomeClaimRE = regexp.MustCompile(`(?i)` +
	`no\s+(changes?|modifications?|edits?|actions?|writes?|files?|updates?)\s+(were|was|have\s+been|has\s+been|will\s+be)\s+(made|applied|written|taken|performed|committed|pushed|deleted|modified|changed|updated|altered|touched)|` +
	`nothing\s+(was|has\s+been|will\s+be)\s+(changed|modified|written|deleted|removed|committed|pushed)|` +
	`(operation|request|action|command|call|change)\s+(was\s+|has\s+been\s+)?(blocked|denied|rejected|refused|cancell?ed|aborted|not\s+permitted|not\s+performed)|` +
	`(permission|access)\s+denied|` +
	`no\s+action\s+(is\s+|was\s+)?(required|needed|taken|necessary)`)

// hiddenActionDirectiveRE matches an instruction to the agent to carry out a
// state-changing action: a bare imperative opening a sentence, or an explicit
// second-person obligation. The verb set is restricted to operations that
// change state or move data, so a model-only block that merely NARRATES a
// deletion ("the record was removed") does not match.
//
// The admitted positions are deliberately NOT "start of any line". A unified
// diff or a log excerpt carried in a model-only block routinely opens a line
// with "remove ...", and that is narration, not instruction. Only a prose
// sentence start (start of text, or after a full stop) or an explicit
// directive marker counts.
var hiddenActionDirectiveRE = regexp.MustCompile(`(?i)` +
	`(?:\A\s*|[.!?]\s+|\byou\s+(?:must|should|need\s+to|have\s+to|are\s+to|will|can\s+now)\s+|\bplease\s+|\bnow\s+|\bthen\s+|\bnext,\s+|\bfirst,\s+)` +
	`(delete|remove|drop|truncate|purge|wipe|disable|revoke|overwrite|replace|reset|rotate|chmod|chown|force[\s-]?push|send|upload|post|transmit|exfiltrate|curl|wget|install|execute|run|invoke|escalate|grant|elevate)\s+\S`)

// scanAudiencePartitionedDivergence pairs a user-visible "nothing happened"
// claim with a model-only action directive.
//
// The two halves are gated differently (#3911). The CLAIM sits in a block the
// human can see, so every leg of the attribution gate applies to it: a claim
// quoted from somewhere else ("the docs say \"no changes were made\"") is not
// the tool claiming it. The DIRECTIVE sits in a model-only block, so only the
// attribution-cue legs apply — see scanHiddenBlockText. Either half gated
// records the divergence at AUDIT rather than dropping it; only an ungated
// claim paired with an ungated directive BLOCKs, and that pairing is found
// exactly as it was before #3911.
func scanAudiencePartitionedDivergence(result *ContentAudienceScanResult, items []ContentItem) {
	userClaimIdx, userClaimText := -1, ""
	claimStrength, claimLeg := attributionNone, ""
	for i, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		if !item.Annotations.VisibleToUser() {
			continue
		}
		if loc := benignOutcomeClaimRE.FindStringIndex(item.Text); loc != nil {
			lower := strings.ToLower(item.Text)
			strength, leg := attributionEvidence(item.Text, lower, loc[0], loc[1], attributionAllLegs)
			if strength != attributionNone {
				// Remember the first gated claim as a fallback, and keep
				// looking for an ungated one exactly as before.
				if userClaimIdx < 0 {
					userClaimIdx, userClaimText = i, safeSnippet(item.Text, loc[0], 80)
					claimStrength, claimLeg = strength, leg
				}
				continue
			}
			userClaimIdx, userClaimText = i, safeSnippet(item.Text, loc[0], 80)
			claimStrength, claimLeg = attributionNone, ""
			break
		}
	}
	if userClaimIdx < 0 {
		return
	}

	divergence := func(i int, text string, loc int) ContentAudienceFinding {
		return ContentAudienceFinding{
			Signal: SignalAudiencePartitionedDivergence,
			Detail: fmt.Sprintf(
				"tool result is partitioned by audience: the user-visible block at index %d claims no "+
					"state change or a stopped operation (%q), while the block at index %d — annotated "+
					"audience:[\"assistant\"] and withheld from the user — instructs the agent to carry "+
					"out a state-changing action. The human reviews one half and the model acts on the other",
				userClaimIdx, userClaimText, i),
			ContentIndex: i,
			Snippet:      safeSnippet(text, loc, 100),
			Blocking:     true,
		}
	}

	var fallback *ContentAudienceFinding
	fallbackLeg := ""
	fallbackUngated := false
	for i, item := range items {
		if item.Type != "text" || item.Text == "" || !item.Annotations.HiddenFromUser() {
			continue
		}
		loc := hiddenActionDirectiveRE.FindStringIndex(item.Text)
		if loc == nil {
			continue
		}
		lower := strings.ToLower(item.Text)
		strength, leg := attributionEvidence(item.Text, lower, loc[0], loc[1], attributionCueLegsOnly)
		if strength == attributionNone && claimStrength == attributionNone {
			result.Findings = append(result.Findings, divergence(i, item.Text, loc[0]))
			return
		}
		// Fallback preference: an ungated directive over a gated one.
		if fallback == nil || (strength == attributionNone && !fallbackUngated) {
			f := divergence(i, item.Text, loc[0])
			fallback = &f
			fallbackUngated = strength == attributionNone
			fallbackLeg = leg
			if claimStrength != attributionNone {
				fallbackLeg = claimLeg + " (the user-visible claim)"
			}
		}
	}
	if fallback != nil {
		fallback.Blocking = false
		fallback.AttributionGated = true
		fallback.Detail += attributionDowngradeNote(fallbackLeg)
		result.Findings = append(result.Findings, *fallback)
	}
}

// contentAudienceSentinelEngine returns the mcp-sentinel.yaml `engine` key that
// gives a signal's finding a stable rule ID, reason, and remediation via
// PolicyEvaluator.LookupSentinel.
func contentAudienceSentinelEngine(signal ContentAudienceSignal) string {
	switch signal {
	case SignalAudienceHiddenUserConcealment:
		return "mcp-audience-hidden-user-concealment"
	case SignalAudienceHiddenDirectiveEscalation:
		return "mcp-audience-hidden-directive-escalation"
	case SignalAudienceHiddenLatentDirective:
		return "mcp-audience-hidden-latent-directive"
	case SignalAudiencePartitionedDivergence:
		return "mcp-audience-partitioned-divergence"
	default:
		return ""
	}
}

// promptsAudienceSentinelEngine is contentAudienceSentinelEngine's prompts/get
// counterpart — same signals, "-prompts"-suffixed engine keys so the finding
// resolves to the mcp-prompt-template-injection taxonomy node instead of
// mcp-tool-response-poisoning. See the "prompts/get surface" sentinel block in
// mcp-sentinel.yaml for why these need to be separate entries rather than
// reusing the tools/call ones.
func promptsAudienceSentinelEngine(signal ContentAudienceSignal) string {
	switch signal {
	case SignalAudienceHiddenUserConcealment:
		return "mcp-audience-hidden-user-concealment-prompts"
	case SignalAudienceHiddenDirectiveEscalation:
		return "mcp-audience-hidden-directive-escalation-prompts"
	case SignalAudienceHiddenLatentDirective:
		return "mcp-audience-hidden-latent-directive-prompts"
	case SignalAudiencePartitionedDivergence:
		return "mcp-audience-partitioned-divergence-prompts"
	default:
		return ""
	}
}
