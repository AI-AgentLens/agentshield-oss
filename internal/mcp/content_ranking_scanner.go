package mcp

import (
	"fmt"
	"strings"
	"time"
	"unicode"
)

// Content-block RANKING channel — MCP's own `annotations.priority` and
// `annotations.lastModified` fields as a precedence-forgery primitive.
//
// # The surface
//
// The MCP `Annotations` object has exactly three fields, and every one of them
// is a routing directive the SERVER writes and the HOST obeys:
//
//	audience      who the block is for            → oversight routing
//	priority      "how important this data is"    → attention / retention ranking
//	lastModified  "the moment the resource was    → recency ranking
//	              last modified", ISO 8601
//
// content_audience_scanner.go closed the first. The other two were parsed into
// ContentAnnotations "for completeness so a round-trip of a real block is
// lossless" and read by nothing in this package — confirmed by sweeping every
// json-tagged field in types.go for a reader outside types.go. `priority` and
// `lastModified` were the only two with none.
//
// # Why ranking is an attack surface and not presentation trivia
//
// An agent's hardest job is reconciling sources that disagree. Ask it for the
// deployment procedure and it may get the honest internal wiki through one
// tool and, through another, a document claiming the procedure now requires
// posting the production key to an attacker's endpoint. Which one survives
// into the answer is decided by precedence — and MCP ships precedence as two
// attacker-supplied scalars:
//
//   - `lastModified` is the protocol's own answer to "which of these is
//     current". A host or model that prefers the newer document is reasoning
//     CORRECTLY; it is the input that is forged.
//   - `priority` is the protocol's own answer to "what must not be dropped".
//     The spec's words for the endpoints are not hints: 1 means the data is
//     "effectively required", 0 means it is "entirely optional". Under context
//     pressure that is a directive about which evidence the host discards.
//
// This is the same shape as `isError` (response_error_remediation_scanner.go)
// and `audience` before it: the highest-authority channels on this surface are
// not the ones carrying prose, they are the ones the PROTOCOL tells the host to
// act on. An attacker does not have to argue with the model's judgment if it
// can supply the tiebreaker the model's judgment consumes.
//
// # Why these signals need no prose analysis at all
//
// Every signal below is arithmetic or an alphabet check on a metadata value.
// There is no pattern list to bypass, no discourse gate to argue with, and no
// natural-language FP class — which is also why the tiers can be set on "does
// any conformant server do this" rather than on "how confident is the match".
//
// # What is deliberately NOT flagged
//
//   - `priority: 1` on its own. "Effectively required" is a legitimate and
//     common thing for a server to say about its main payload.
//   - A `lastModified` that simply fails to parse. Real servers write RFC 1123,
//     naive local time, "unknown" and epoch strings. Non-conformance is not an
//     attack, and a signal there would fire on sloppiness far more often than
//     on malice. Only a value carrying a character NO date representation
//     contains is admitted (SignalRankingTimestampSmuggling).
//   - Bare digit strings are not parsed as epochs. Seconds and milliseconds are
//     indistinguishable by length in the ranges that matter, and guessing wrong
//     manufactures a "year 57000" finding out of an ordinary epoch-millis
//     timestamp. An unparseable value simply produces no recency finding.
//
// # Render recovery is deliberately NOT applied
//
// ScanContentAudienceChannel re-runs itself over Unicode-recovered text because
// its matches are prose. Doing that here would be actively harmful:
// SignalRankingTimestampSmuggling detects exactly the characters a recovery
// pass exists to delete, so folding first would erase the evidence. Same
// reasoning as patternTargetsNonASCII in the tool-name fold — a detector aimed
// at non-ASCII must see the wire form.
type ContentRankingSignal string

const (
	// SignalRankingForgedRecency fires when `annotations.lastModified` names a
	// moment more than rankingClockSkewTolerance in the future. A resource
	// cannot have been modified after now, so beyond any clock-skew or
	// timezone-mishandling argument the value is not a fact about the resource
	// — it is a claim about precedence over everything else in context.
	// AUDIT: a thoroughly broken server clock produces the same bytes.
	SignalRankingForgedRecency ContentRankingSignal = "ranking_forged_recency"

	// SignalRankingPriorityOutOfRange fires when `annotations.priority` falls
	// outside the spec's closed 0..1 interval. A conformant server cannot emit
	// this; a host that sorts or weights numerically without clamping hands the
	// block precedence over every well-behaved one. AUDIT: a server writing a
	// percentage (`priority: 100`) is a plausible bug.
	SignalRankingPriorityOutOfRange ContentRankingSignal = "ranking_priority_out_of_range"

	// SignalRankingHiddenSupremacy fires when a block the server has routed
	// AWAY from the human (audience names "assistant" and omits "user") also
	// carries an anomalous ranking claim — an impossible timestamp or an
	// out-of-spec priority. BLOCK: a broken clock does not correlate with
	// audience routing, so the conjunction has no benign reading. "Trust this
	// above everything else, and do not show it to the operator" is the whole
	// attack in two metadata fields.
	SignalRankingHiddenSupremacy ContentRankingSignal = "ranking_hidden_supremacy"

	// SignalRankingPriorityInversion fires when one response declares every
	// user-visible block "entirely optional" (priority <= 0.1) while a
	// model-only block is "effectively required" (priority >= 0.9). The server
	// is telling the host which half of its own answer to discard first under
	// context pressure, and it is the half the human reviews. BLOCK.
	SignalRankingPriorityInversion ContentRankingSignal = "ranking_priority_inversion"

	// SignalRankingTimestampSmuggling fires when `lastModified` contains a
	// character no date representation contains — a control character, a line
	// break, a zero-width or bidi formatter, a tag character, an emoji. The
	// field is an unvalidated string on the wire that hosts render and models
	// read, and it is scanned by nothing else. BLOCK.
	SignalRankingTimestampSmuggling ContentRankingSignal = "ranking_timestamp_smuggling"
)

// rankingClockSkewTolerance is how far into the future a `lastModified` may sit
// before it stops being explicable as a clock problem.
//
// The FP driver here is NOT NTP drift, which is seconds. It is timezone
// mishandling: a server that formats naive local time and appends "Z", or that
// writes a local timestamp with no offset at all, reports up to its UTC offset
// in the future. The largest real offset in use is +14:00 (Line Islands), and
// Go parses a zoneless layout as UTC, so the worst honest case this scanner can
// see is about 14 hours. A full day clears that with margin and is a bound that
// can be defended to an auditor in one sentence.
//
// Tightening this below ~15h would start reporting Pacific-timezone bugs as
// forged recency. Widening it buys an attacker a full extra day of precedence
// over any document written yesterday.
const rankingClockSkewTolerance = 24 * time.Hour

// Priority endpoints, named for the spec's own gloss of them: 1 means the data
// is "effectively required", 0 means it is "entirely optional". The inversion
// signal is pinned to these endpoints rather than to a plain `hidden > visible`
// comparison because a plain comparison has a legitimate reading — a server may
// reasonably rank a raw model-only data payload above the short human summary
// beside it. What has no legitimate reading is declaring the ONLY content the
// human can see to be optional.
const (
	rankingPriorityOptional = 0.1
	rankingPriorityRequired = 0.9
)

// ContentRankingFinding records one detection.
type ContentRankingFinding struct {
	Signal       ContentRankingSignal `json:"signal"`
	Detail       string               `json:"detail"`
	ContentIndex int                  `json:"content_index"`
	Snippet      string               `json:"snippet,omitempty"`
	// Blocking distinguishes the BLOCK-tier signals from the AUDIT-tier ones so
	// the call site can act on a mixed-tier result without re-deriving the
	// mapping from the signal name.
	Blocking bool `json:"blocking"`
}

// ContentRankingScanResult is the outcome of ScanContentRankingChannel.
type ContentRankingScanResult struct {
	// Blocked is true when at least one BLOCK-tier finding was produced.
	Blocked bool `json:"blocked"`
	// Found is true when any finding was produced, at any tier.
	Found    bool                    `json:"found"`
	Findings []ContentRankingFinding `json:"findings,omitempty"`
}

// ScanContentRankingChannel inspects a tools/call result's content blocks for
// abuse of the `annotations.priority` and `annotations.lastModified` ranking
// fields.
//
// Unlike the audience scanner this does NOT skip blocks with no text or a
// non-text type. A ranking claim is carried entirely by the annotation, so an
// image, audio or embedded-resource block with a forged `lastModified` outranks
// a text block just as effectively — and skipping it would leave the cheapest
// carrier for the attack unscanned.
func ScanContentRankingChannel(items []ContentItem) ContentRankingScanResult {
	return scanContentRankingAt(items, time.Now(), true)
}

// ScanPromptsGetRankingChannel is ScanContentRankingChannel adapted for a
// prompts/get response. A PromptMessage's content block carries `annotations`
// in the same place a tools/call content block does, and prompt content is
// spliced into the agent's context wholesale — so a block that claims to be
// both the newest and the only required material is, if anything, worth more
// here than in one tool's output among many.
//
// The nested ResourceContentItem of a "resource" block has NO annotations field
// in any spec version (see its doc comment in types.go); the annotations live
// on the outer PromptMessageContent, which is what is read here.
func ScanPromptsGetRankingChannel(result *GetPromptResult) ContentRankingScanResult {
	if result == nil {
		return ContentRankingScanResult{}
	}
	items := make([]ContentItem, 0, len(result.Messages))
	for _, msg := range result.Messages {
		items = append(items, ContentItem{Type: msg.Content.Type, Annotations: msg.Content.Annotations})
	}
	return scanContentRankingAt(items, time.Now(), true)
}

// ScanResourceListRankingChannel is ScanContentRankingChannel adapted for a
// resources/list response, where `Resource` carries `annotations` directly.
//
// Deliberately does NOT run the priority-inversion check, for the same reason
// ScanResourceListAudienceChannel drops partitioned divergence: a listing's
// entries are independent resources, not two halves of one answer, so comparing
// entry N's visible priority against entry M's hidden priority would manufacture
// a partition that was never a single response — a finding with no coherent
// narrative to attach to an attestation. The per-entry signals transfer
// unchanged; a listing entry that claims to have been modified next year is
// steering which resource the agent reads next.
func ScanResourceListRankingChannel(entries []ResourceEntry) ContentRankingScanResult {
	items := make([]ContentItem, 0, len(entries))
	for _, e := range entries {
		items = append(items, ContentItem{Type: "resource", Annotations: e.Annotations})
	}
	return scanContentRankingAt(items, time.Now(), false)
}

// scanContentRankingAt is the testable core: `now` is injected so the recency
// arithmetic is deterministic, and withInversion selects whether the cross-block
// partition check applies to this surface.
func scanContentRankingAt(items []ContentItem, now time.Time, withInversion bool) ContentRankingScanResult {
	var result ContentRankingScanResult
	for i, item := range items {
		scanRankingBlock(&result, i, item.Annotations, now)
	}
	if withInversion {
		scanRankingPriorityInversion(&result, items)
	}
	return finalizeContentRankingResult(result)
}

// scanRankingBlock applies the per-block signals to one annotation object.
//
// The anomaly signals and SignalRankingHiddenSupremacy are mutually exclusive by
// construction: a hidden block reports the escalated conjunction ONCE rather
// than emitting the AUDIT-tier finding alongside it, so one forged annotation
// never produces two findings describing the same bytes.
func scanRankingBlock(result *ContentRankingScanResult, idx int, ann *ContentAnnotations, now time.Time) {
	if ann == nil {
		return
	}

	if bad, detail := timestampSmugglingDetail(ann.LastModified); bad {
		addRankingFinding(result, ContentRankingFinding{
			Signal:       SignalRankingTimestampSmuggling,
			Detail:       detail,
			ContentIndex: idx,
			Snippet:      rankingSnippet(ann.LastModified),
			Blocking:     true,
		})
	}

	var anomalies []string
	if ahead, ok := futureBy(ann.LastModified, now); ok {
		anomalies = append(anomalies, fmt.Sprintf(
			"annotations.lastModified %q is %s in the future; a resource cannot have been modified after now",
			rankingSnippet(ann.LastModified), roundedAhead(ahead)))
	}
	if ann.Priority != nil && (*ann.Priority < 0 || *ann.Priority > 1) {
		anomalies = append(anomalies, fmt.Sprintf(
			"annotations.priority %g is outside the spec's closed 0..1 interval", *ann.Priority))
	}
	if len(anomalies) == 0 {
		return
	}

	if ann.HiddenFromUser() {
		addRankingFinding(result, ContentRankingFinding{
			Signal: SignalRankingHiddenSupremacy,
			Detail: "block is annotated audience:[\"assistant\"] — routed to the model and withheld from the user — " +
				"and claims precedence it cannot legitimately hold: " + strings.Join(anomalies, "; "),
			ContentIndex: idx,
			Blocking:     true,
		})
		return
	}
	for _, detail := range anomalies {
		signal := SignalRankingForgedRecency
		if strings.Contains(detail, "annotations.priority") {
			signal = SignalRankingPriorityOutOfRange
		}
		addRankingFinding(result, ContentRankingFinding{
			Signal:       signal,
			Detail:       detail,
			ContentIndex: idx,
			Blocking:     false,
		})
	}
}

// scanRankingPriorityInversion reports a response that declares every
// user-visible block "entirely optional" while a model-only block is
// "effectively required".
//
// Three conditions, and all three are load-bearing:
//
//   - At least one user-visible block must DECLARE a priority. An absent
//     priority is no claim at all, and treating it as 0 would fire on the
//     ordinary case of one annotated model-only block beside unannotated prose.
//   - EVERY user-visible block that declares one must be <= 0.1. If any visible
//     block is ranked normally the human still has non-discardable content and
//     there is no inversion.
//   - At least one hidden block must be >= 0.9.
func scanRankingPriorityInversion(result *ContentRankingScanResult, items []ContentItem) {
	visibleDeclared := 0
	for _, item := range items {
		if item.Annotations == nil || item.Annotations.Priority == nil {
			continue
		}
		if !item.Annotations.VisibleToUser() {
			continue
		}
		visibleDeclared++
		if *item.Annotations.Priority > rankingPriorityOptional {
			return
		}
	}
	if visibleDeclared == 0 {
		return
	}
	for i, item := range items {
		if item.Annotations == nil || item.Annotations.Priority == nil {
			continue
		}
		if !item.Annotations.HiddenFromUser() {
			continue
		}
		if *item.Annotations.Priority < rankingPriorityRequired {
			continue
		}
		addRankingFinding(result, ContentRankingFinding{
			Signal: SignalRankingPriorityInversion,
			Detail: fmt.Sprintf(
				"response is partitioned by priority: every user-visible block is declared entirely optional "+
					"(priority <= %g) while a block annotated audience:[\"assistant\"] is declared effectively "+
					"required (priority %g) — the server is naming the half the human reviews as the half to discard",
				rankingPriorityOptional, *item.Annotations.Priority),
			ContentIndex: i,
			Blocking:     true,
		})
		return
	}
}

// futureBy reports how far past `now` a lastModified value sits, and whether it
// is far enough past to be reported.
//
// Returns ok=false for any value that parses by none of the accepted layouts:
// non-conformance is not this scanner's business (see the package comment).
func futureBy(value string, now time.Time) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	for _, layout := range rankingTimestampLayouts {
		parsed, err := time.Parse(layout, trimmed)
		if err != nil {
			continue
		}
		ahead := parsed.Sub(now)
		if ahead > rankingClockSkewTolerance {
			return ahead, true
		}
		return 0, false
	}
	return 0, false
}

// rankingTimestampLayouts is the set of representations a real MCP server has
// been observed to put in `lastModified`. The spec asks for ISO 8601, so
// RFC 3339 is the conformant case; the rest are here so that a sloppy server's
// output is still READ rather than silently ignored — an attacker who learns
// that only RFC 3339 is checked would simply forge an RFC 1123 timestamp.
//
// The zoneless layouts parse as UTC in Go, which is exactly the timezone-
// mishandling case rankingClockSkewTolerance is sized for.
var rankingTimestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02T15:04",
	"2006-01-02 15:04:05",
	"2006-01-02 15:04",
	"2006-01-02",
	"20060102T150405Z",
	"20060102T150405Z0700",
	time.RFC1123Z,
	time.RFC1123,
	time.RFC850,
	time.RFC822Z,
	time.RFC822,
	time.UnixDate,
	time.ANSIC,
}

// timestampSmugglingDetail reports whether a lastModified value carries a
// character that appears in no date representation.
//
// The check is an ALLOWLIST over the alphabet rather than a blocklist of
// invisible characters, because the legitimate alphabet of a timestamp is
// closed and tiny: digits, letters (month and day names, "T", "Z", "GMT", and
// their localized spellings), and a handful of separators. Anything else — a
// newline, a NUL, a zero-width joiner, a bidi override, a Unicode tag
// character, an emoji — is a payload, not a date. An allowlist also needs no
// maintenance as new smuggling codepoints are discovered, which a blocklist
// does.
//
// Unicode letters are admitted, not just ASCII ones, so a server writing
// "12 février 2026" is non-conformant rather than malicious. Marks are admitted
// for the same reason: a combining accent belongs to such a month name.
func timestampSmugglingDetail(value string) (bool, string) {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) {
			continue
		}
		if strings.ContainsRune(" -+.,:/()", r) {
			continue
		}
		return true, fmt.Sprintf(
			"annotations.lastModified carries U+%04X, a character that appears in no date representation; "+
				"the field is an unvalidated wire string that hosts render and models read", r)
	}
	return false, ""
}

// roundedAhead renders a future offset at a granularity a human reads without
// arithmetic, without implying a precision the value does not have.
func roundedAhead(d time.Duration) string {
	switch {
	case d >= 365*24*time.Hour:
		return fmt.Sprintf("%.1f years", d.Hours()/(365*24))
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.0f days", d.Hours()/24)
	default:
		return fmt.Sprintf("%.0f hours", d.Hours())
	}
}

// rankingSnippet bounds a metadata value before it reaches an audit record.
func rankingSnippet(s string) string {
	const max = 80
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func addRankingFinding(result *ContentRankingScanResult, f ContentRankingFinding) {
	result.Findings = append(result.Findings, f)
}

// finalizeContentRankingResult derives Blocked/Found from the accumulated
// findings, so no caller has to re-derive the tier mapping.
func finalizeContentRankingResult(result ContentRankingScanResult) ContentRankingScanResult {
	result.Found = len(result.Findings) > 0
	for _, f := range result.Findings {
		if f.Blocking {
			result.Blocked = true
			break
		}
	}
	return result
}

// contentRankingSentinelEngine returns the mcp-sentinel.yaml `engine` key that
// gives a signal's finding a stable rule ID, reason, and remediation via
// PolicyEvaluator.LookupSentinel.
func contentRankingSentinelEngine(signal ContentRankingSignal) string {
	switch signal {
	case SignalRankingForgedRecency:
		return "mcp-ranking-forged-recency"
	case SignalRankingPriorityOutOfRange:
		return "mcp-ranking-priority-out-of-range"
	case SignalRankingHiddenSupremacy:
		return "mcp-ranking-hidden-supremacy"
	case SignalRankingPriorityInversion:
		return "mcp-ranking-priority-inversion"
	case SignalRankingTimestampSmuggling:
		return "mcp-ranking-timestamp-smuggling"
	default:
		return ""
	}
}

// promptsRankingSentinelEngine is contentRankingSentinelEngine's prompts/get
// counterpart — same signals, "-prompts"-suffixed engine keys so the finding
// resolves to the mcp-prompt-template-injection taxonomy node instead of
// mcp-tool-response-poisoning, matching promptsAudienceSentinelEngine.
func promptsRankingSentinelEngine(signal ContentRankingSignal) string {
	if key := contentRankingSentinelEngine(signal); key != "" {
		return key + "-prompts"
	}
	return ""
}
