package mcp

import "regexp"

// ResponseOverrideDirectiveSignal identifies a match of the widened
// earlier-instructions override vocabulary (overrideEarlierInstructionsRE:
// four verbs, five adjectives, five instruction nouns) in a tool response,
// tiered by whether anything around it says the directive is addressed to
// the agent.
//
// # Why this is a separate scanner and not a row (#4060, Codex pass 1 on #4073)
//
// responseInjectionPatterns is BLOCK by construction: ScanToolCallResponse
// sets Poisoned on any finding and the handler replaces the whole result.
// The one-verb row it has always carried (ignorePreviousInstructionsRE) is
// narrow enough to live there. The widened vocabulary is not: "rules",
// "messages", "prompts" and "directives" are ordinary data nouns, and the
// four verbs are ordinary data verbs. Placed in that set, the shared value
// blocked all five of these on a first pass:
//
//	Fixed a bug that caused the firewall to <verb> previous rules
//	The mail client can <verb> previous messages after thirty days
//	The installer will <verb> earlier prompts when running unattended
//	The parser must not <verb> earlier directives in the configuration file
//	Alice wrote: Please <verb> the earlier instructions for assembling the desk.
//
// A changelog line is a valid use of that exact shape, so a BLOCK on it is
// indefensible ("only BLOCK what you can justify"). The alternative —
// keeping the widened row at BLOCK and adding those five sentences as TNs —
// was rejected: it removes five examples, not the class.
//
// # The tiering
//
//   - Bare match (no agent-directed cue within 80 bytes): AUDIT. The receipt
//     survives — an override phrase arriving in tool output is worth a line
//     in the attestation — and nothing is blocked on prose.
//   - Directed match (a cue within 80 bytes): BLOCK. The cue set is the one
//     the sibling directive rows anchor on — second-person address, an
//     imperative marker (please / from now on / right now), or a reference to
//     the system's or the assistant's own instructions — NOT the bare
//     imperative-sentence-start leg hasAgentDirectedCue also accepts, because
//     a changelog bullet opens its own line too. Bare "now" is likewise
//     excluded: it is a tense adverb in release notes ("the client now
//     discards previous messages") far more often than a command.
//   - Directed but quoted or attributed: recorded at AUDIT with the gating
//     leg named, never dropped (#3911). "Alice wrote: Please ..." is reported
//     speech, and the attribution gate is what turns its "please" back into a
//     receipt instead of a block.
//
// The scanner skips any span ignorePreviousInstructionsRE already covers:
// that row blocks it in ScanToolCallResponse, and a second entry for the
// same bytes would only clutter the receipt.
//
// It also skips a match whose noun runs straight on into an ASCII letter
// ("rulesets" is not an instruction noun). The boundary lives here and not in
// the shared regex: only a following letter disqualifies, so "_" (Markdown
// emphasis), digits, punctuation and end-of-text still match, and the sampling
// path keeps main's exact pattern (Opus pass 2 on #4073, option 1).
//
// Sampling is untouched. toolLoopOverridePatterns shares the regex and keeps
// BLOCK for bare prose on the tool_result path (#4058) — a pre-existing FP
// class there, and aligning it is a NARROWING decision left open.
type ResponseOverrideDirectiveSignal string

const (
	// SignalResponseOverrideDirectiveBare: the widened override vocabulary
	// matched with no agent-directed cue in reach. AUDIT tier.
	SignalResponseOverrideDirectiveBare ResponseOverrideDirectiveSignal = "response_override_directive_bare"

	// SignalResponseOverrideDirectiveDirected: the widened override vocabulary
	// matched with a corroborating agent-directed cue within 80 bytes. BLOCK
	// tier, unless the attribution gate downgraded the finding.
	SignalResponseOverrideDirectiveDirected ResponseOverrideDirectiveSignal = "response_override_directive_directed"
)

// ResponseOverrideDirectiveFinding records one detection.
type ResponseOverrideDirectiveFinding struct {
	Signal  ResponseOverrideDirectiveSignal `json:"signal"`
	Detail  string                          `json:"detail"`
	Snippet string                          `json:"snippet,omitempty"`
	// ContentIndex is the index of the content block the match came from.
	ContentIndex int `json:"content_index"`
	// Blocking is whether THIS finding blocks: the signal's tier, unless the
	// attribution gate downgraded it.
	Blocking bool `json:"blocking"`
	// AttributionGated records that a directed match looked quoted or
	// attributed, so it was recorded at AUDIT instead of blocked (#3911).
	AttributionGated bool `json:"attribution_gated,omitempty"`
}

// ResponseOverrideDirectiveScanResult is the aggregate result.
type ResponseOverrideDirectiveScanResult struct {
	Blocked  bool                               `json:"blocked"`
	Found    bool                               `json:"found"`
	Findings []ResponseOverrideDirectiveFinding `json:"findings,omitempty"`
}

// overrideDirectedCueRE is the corroborating context that promotes a widened
// override match to BLOCK. Three families, each anchored the way the sibling
// BLOCK rows in responseActionPatterns / responseBehavioralPatterns anchor
// ("you must", "please now", "from now on you"):
//
//   - second-person address: you / your / yourself
//   - an imperative marker: please, from now on, right now
//   - an instruction object that belongs to the system or the assistant:
//     "system prompt", "developer instructions", "the assistant", "this agent"
//
// Evaluated over lowercased text; the window is 80 bytes either side of the
// match, the same reach hasAgentDirectedCue uses.
var overrideDirectedCueRE = regexp.MustCompile(`\b(?:` +
	`you|your|yourself|` +
	`please|from\s+now\s+on|right\s+now|` +
	`(?:system|developer|operator)\s+(?:prompts?|instructions?|messages?|rules?|directives?)|` +
	`(?:the|this)\s+(?:assistant|agent|model|ai|llm|chatbot)` +
	`)\b`)

// overrideDirectedCueWindow is the reach, in bytes on either side of the
// match, within which a cue corroborates it.
const overrideDirectedCueWindow = 80

// overrideDirectedCue returns the cue that corroborates the match at
// [start,end) of lower, if any.
func overrideDirectedCue(lower string, start, end int) (string, bool) {
	windowStart := start - overrideDirectedCueWindow
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := end + overrideDirectedCueWindow
	if windowEnd > len(lower) {
		windowEnd = len(lower)
	}
	cue := overrideDirectedCueRE.FindString(lower[windowStart:windowEnd])
	return cue, cue != ""
}

// ScanToolCallResponseForOverrideDirective inspects text content items for
// the widened earlier-instructions override vocabulary and tiers each match
// as described on ResponseOverrideDirectiveSignal. Call sites surface AUDIT
// findings and fall through, and replace the response when Blocked — the
// same contract as ScanToolResultErrorRemediation.
func ScanToolCallResponseForOverrideDirective(items []ContentItem) ResponseOverrideDirectiveScanResult {
	var result ResponseOverrideDirectiveScanResult

	// Same bookkeeping as ScanToolResultErrorRemediation (#3911): the first
	// ungated match of each signal is kept; a gated match surfaces only for a
	// signal that never matched ungated, so a quoted occurrence early in the
	// text cannot downgrade a bare one later on.
	var ungated, gated []ResponseOverrideDirectiveFinding
	seenUngated := map[ResponseOverrideDirectiveSignal]bool{}
	seenGated := map[ResponseOverrideDirectiveSignal]bool{}

	add := func(f ResponseOverrideDirectiveFinding, strength attributionStrength, leg string) {
		if strength == attributionNone {
			if seenUngated[f.Signal] {
				return
			}
			seenUngated[f.Signal] = true
			ungated = append(ungated, f)
			return
		}
		if seenUngated[f.Signal] || seenGated[f.Signal] {
			return
		}
		seenGated[f.Signal] = true
		f.Blocking = false
		f.AttributionGated = true
		f.Detail += attributionDowngradeNote(leg)
		gated = append(gated, f)
	}

	for i, item := range items {
		if item.Type != "" && item.Type != "text" {
			continue
		}
		if item.Text == "" {
			continue
		}
		forms := newProseForms(item.Text)
		// A block the server hid from the human gets the cue legs only, as
		// the other discourse-gated scanners do: quotation marks the user
		// never sees are not innocent quotation.
		legs := attributionAllLegs
		if item.Annotations.HiddenFromUser() {
			legs = attributionCueLegsOnly
		}

		for _, form := range []struct {
			text string
			note string
		}{{forms.lower, ""}, {forms.recoveredLower, renderRecoveryNote}} {
			if form.text == "" {
				continue
			}
			for _, loc := range overrideEarlierInstructionsRE.FindAllStringIndex(form.text, -1) {
				if overrideNounRunsOn(form.text, loc[1]) {
					continue // "rulesets": the noun is the start of a longer word
				}
				span := form.text[loc[0]:loc[1]]
				if ignorePreviousInstructionsRE.MatchString(span) {
					continue // the one-verb BLOCK row in responseInjectionPatterns owns this span
				}
				cue, directed := overrideDirectedCue(form.text, loc[0], loc[1])
				if !directed {
					add(ResponseOverrideDirectiveFinding{
						Signal: SignalResponseOverrideDirectiveBare,
						Detail: "earlier-instructions override vocabulary in tool output (" + span +
							") with no agent-directed cue within 80 bytes — recorded at AUDIT, not blocked: " +
							"the instruction nouns and verbs have ordinary data meanings in changelogs, " +
							"mail and installer text" + form.note,
						Snippet:      safeSnippet(form.text, loc[0], 80),
						ContentIndex: i,
						Blocking:     false,
					}, attributionNone, "")
					continue
				}
				strength, leg := attributionEvidence(form.text, form.text, loc[0], loc[1], legs)
				add(ResponseOverrideDirectiveFinding{
					Signal: SignalResponseOverrideDirectiveDirected,
					Detail: "earlier-instructions override directive in tool output (" + span +
						") corroborated by an agent-directed cue (" + cue + ") within 80 bytes" + form.note,
					Snippet:      safeSnippet(form.text, loc[0], 80),
					ContentIndex: i,
					Blocking:     true,
				}, strength, leg)
			}
		}
	}

	result.Findings = ungated
	for _, f := range gated {
		if !seenUngated[f.Signal] {
			result.Findings = append(result.Findings, f)
		}
	}
	for _, f := range result.Findings {
		if f.Blocking {
			result.Blocked = true
		}
	}
	result.Found = len(result.Findings) > 0
	return result
}

// overrideNounRunsOn reports whether the override match ending at end is
// followed by an ASCII letter, i.e. its instruction noun is only the prefix of
// a longer word ("rulesets", "messageboard"). Anything else after the noun —
// "_", a digit, punctuation, whitespace, a non-ASCII byte or end-of-text —
// leaves the match standing.
func overrideNounRunsOn(text string, end int) bool {
	if end >= len(text) {
		return false
	}
	c := text[end]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// overrideDirectiveSentinelEngine returns the mcp-sentinel.yaml `engine` key
// for a signal. No sentinel entry exists yet for either key; the handler's
// LookupSentinel is nil-safe and sentinelTaxonomyRef falls back to the
// generic response-poisoning node until one is added (a pack decision).
func overrideDirectiveSentinelEngine(signal ResponseOverrideDirectiveSignal) string {
	switch signal {
	case SignalResponseOverrideDirectiveBare:
		return "mcp-response-override-directive-bare"
	case SignalResponseOverrideDirectiveDirected:
		return "mcp-response-override-directive-directed"
	default:
		return ""
	}
}
