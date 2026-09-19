package mcp

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// BrowserGameJailbreakSignal is emitted once per session when the
// gamified-context-reframing jailbreak pattern ("BioShocking", LayerX
// Security, June 2026) is observed in an agentic browser session.
type BrowserGameJailbreakSignal string

const (
	// SignalBrowserGameJailbreakSession fires the first time a session shows:
	// (1) extended interactive engagement with a single page, (2) a
	// clipboard/credential-shaped read while engaged, (3) navigation to a
	// DIFFERENT origin, and (4) a paste/type/submit action carrying payload
	// content on that new origin. AUDIT.
	SignalBrowserGameJailbreakSession BrowserGameJailbreakSignal = "browser_game_jailbreak_session"
)

// syntheticBrowserGameJailbreak is the virtual tool name injected into the
// policy engine when the composite fires, mirroring the lethal-trifecta /
// sub-agent tracker approach.
//
// Deliberately avoids the substring "jailbreak" (and other keywords in
// mcp-safety-block-tool-name-injection's tool_name_regex) — a synthetic tool
// name is evaluated through the SAME policy engine as real tool names, so a
// name containing a trigger keyword gets BLOCKed by that unrelated rule
// before this composite's own AUDIT rule is ever reached.
const syntheticBrowserGameJailbreak = "__mcp_browser_game_reframing_session__"

// browserGameMinInteractions is the minimum number of interaction-class tool
// calls with a single page (since the last navigation) required before that
// page counts as "extended engagement" — the puzzle/game back-and-forth the
// taxonomy entry describes, not a single incidental click.
const browserGameMinInteractions = 3

// browserGameSessionState is the mutable per-session state machine.
type browserGameSessionState struct {
	// currentOrigins is the SET of origins the page under interactive engagement
	// may be at, not a single origin. A navigation whose `url` argument name
	// collides (two disguised spellings carrying different destinations) is
	// AMBIGUOUS: the tracker sees both and cannot know which one the server
	// loaded. Collapsing that to one origin let a decoy candidate suppress the
	// composite (#3740 finding 2) — see scanNavigateLocked. Normally one element.
	currentOrigins      []string
	interactionCount    int  // interaction calls observed since the last navigate
	sawCredentialSignal bool // a clipboard read was observed while engaged
	// awaitingOrigins is the SET of possible-current origins at which a paste
	// would complete a disclosure — disclosure eligibility tracked PER ORIGIN,
	// not as one shared flag (#3754 regression 2). It is always a subset of
	// currentOrigins. A shared boolean could not clear a window that every
	// concrete path had invalidated when currentOrigins held more than one member
	// (an unrelated same-origin candidate kept it alive), which fired a false
	// paste and latched `fired`, suppressing a later genuine detection.
	awaitingOrigins []string
	fired           bool
}

// BrowserGameJailbreakTracker detects the gamified context-reframing
// jailbreak pattern across a session's MCP browser/computer-use tool calls:
// an agent is walked through extended interactive engagement with one page
// (a puzzle/game), reads something credential-shaped (via clipboard) while
// still applying that page's "game logic," then navigates to a different
// origin and pastes/types/submits the harvested content there.
//
// This is the cross-call, ordering-aware sibling of LethalTrifectaTracker:
// where the lethal trifecta only needs three capability classes present
// anywhere in the session, this pattern additionally requires the specific
// sequence (engage → read → cross-origin navigate → disclose) that
// distinguishes a game-then-exfiltrate session from three unrelated actions.
//
// Request-side only: Scan sees only tool call arguments, never tool
// responses, so it cannot confirm the clipboard actually held a secret or
// that the pasted text matches it. The composite is a review signal (the
// behavioral shape LayerX documented is present), not proof of exfiltration
// — hence AUDIT, not BLOCK, matching the lethal-trifecta precedent.
//
// Session-scoped: one tracker per MessageHandler, same documented
// single-session-exact / shared-HTTP-proxy-aggregate tradeoff as the other
// per-session trackers.
type BrowserGameJailbreakTracker struct {
	mu    sync.Mutex
	state browserGameSessionState
}

// NewBrowserGameJailbreakTracker returns a ready tracker with empty state.
func NewBrowserGameJailbreakTracker() *BrowserGameJailbreakTracker {
	return &BrowserGameJailbreakTracker{}
}

// Scan classifies the current tool call, updates session state, and returns
// SignalBrowserGameJailbreakSession the moment the full pattern completes.
// Returns "" otherwise (including all calls after the signal has fired).
func (t *BrowserGameJailbreakTracker) Scan(toolName string, args map[string]interface{}) BrowserGameJailbreakSignal {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.state.fired {
		return ""
	}
	lname := strings.ToLower(toolName)

	switch {
	case isBrowserNavigateTool(lname):
		t.scanNavigateLocked(args)
		return ""

	case isClipboardReadTool(lname):
		t.state.sawCredentialSignal = true
		return ""

	case isBrowserDisclosureTool(lname):
		// Fire if ANY possible current origin is still armed. awaitingOrigins is a
		// subset of currentOrigins, so a non-empty set means the page could be at
		// an armed disclosure sink. An empty set means every concrete path
		// invalidated the window, so `fired` is never latched on a dead window.
		if len(t.state.awaitingOrigins) > 0 && hasPayloadArg(args) {
			t.state.fired = true
			t.state.awaitingOrigins = nil
			return SignalBrowserGameJailbreakSession
		}
		// Typing/pasting/submitting is itself interactive engagement when it
		// doesn't complete a pending disclosure (e.g. filling out the puzzle).
		t.state.interactionCount++
		return ""

	case isBrowserInteractionTool(lname):
		t.state.interactionCount++
		return ""
	}

	return ""
}

// scanNavigateLocked handles a navigation call. Caller must hold t.mu.
func (t *BrowserGameJailbreakTracker) scanNavigateLocked(args map[string]interface{}) {
	origins := allURLOrigins(args)
	if len(origins) == 0 {
		return
	}

	// Evaluate EVERY POSSIBLE TRANSITION — every (possible current origin, new
	// candidate origin) pair — against the PRE-call engagement state (#3727
	// pass-2 finding 2, corrected by #3740 finding 2). A colliding `url` argument
	// name resolves to several origins and the tracker cannot know which one the
	// server actually loaded, so BOTH ends of the transition are sets.
	//
	// #3727 evaluated every candidate but then collapsed the state to the LAST
	// origin, which reintroduced the suppression it was closing:
	//
	//	arming    a first navigation resolving to [game, sink] kept only `sink`,
	//	          so the later navigation to the sink read as SAME-origin and
	//	          never armed the disclosure window;
	//	clearing  an armed window at `sink` was cleared by candidates
	//	          [sink, unrelated], even though the same-origin candidate would
	//	          have preserved it — a decoy disarming a live detection.
	//
	// Disclosure eligibility is decided PER DESTINATION ORIGIN (#3754 regression
	// 2), not as one shared flag. A destination D is armed after this navigation
	// iff EITHER:
	//
	//	(a) some possible transition INTO D qualifies — a cross-origin move
	//	    (prev != D, prev != "") from a page that met the engagement +
	//	    credential-read bar; OR
	//	(b) D is a same-origin continuation of an already-armed origin — the page
	//	    stayed at D and D was already awaiting disclosure, so its window
	//	    survives a reload / same-origin move.
	//
	// This is the conservative reading of an ambiguous state — ARM when ANY
	// possible transition qualifies, CLEAR a destination when EVERY possible
	// transition into it invalidates its window. Because eligibility rides on the
	// specific origin rather than a shared boolean, a window that every concrete
	// path invalidated leaves NO origin armed (so a later paste cannot fire on it
	// and latch `fired`). With a single current origin and a single candidate
	// these rules reduce to exactly the previous conditions, so unambiguous
	// sessions are byte-identical.
	preCurrents := t.state.currentOrigins
	preAwaiting := t.state.awaitingOrigins
	preArmed := t.state.interactionCount >= browserGameMinInteractions && t.state.sawCredentialSignal

	var armed []string
	for _, dest := range origins {
		qualifies := false
		if preArmed {
			for _, prev := range preCurrents {
				if prev != "" && prev != dest {
					qualifies = true // (a) qualifying cross-origin transition into dest
					break
				}
			}
		}
		if !qualifies && containsOrigin(preCurrents, dest) && containsOrigin(preAwaiting, dest) {
			qualifies = true // (b) same-origin continuation of an already-armed origin
		}
		if qualifies {
			armed = append(armed, dest)
		}
	}
	t.state.awaitingOrigins = armed

	// Start tracking engagement fresh on the newly loaded page. With a collision,
	// every resolved origin stays a possible current page.
	t.state.currentOrigins = origins
	t.state.interactionCount = 0
	t.state.sawCredentialSignal = false
}

// containsOrigin reports whether origins contains o.
func containsOrigin(origins []string, o string) bool {
	for _, x := range origins {
		if x == o {
			return true
		}
	}
	return false
}

// isBrowserNavigateTool matches tool names that load a new page/origin.
func isBrowserNavigateTool(lname string) bool {
	needles := []string{
		"navigate", "goto", "go_to_url", "go_to_page", "open_url", "visit",
		"load_url", "page_goto", "browser_goto",
	}
	return containsAny(lname, needles)
}

// isClipboardReadTool matches tool names that read the clipboard — the
// "copy it" half of a copy-then-paste-elsewhere exfiltration move. Mirrors
// the tool family in mcp-computer-use-audit-clipboard-read.
func isClipboardReadTool(lname string) bool {
	needles := []string{
		"read_clipboard", "get_clipboard", "clipboard_read", "get_clipboard_content", "clipboard_get",
	}
	return containsAny(lname, needles)
}

// isBrowserDisclosureTool matches tool names that can carry content onto a
// page — the "paste/submit/share it there" half of the exfiltration move.
func isBrowserDisclosureTool(lname string) bool {
	needles := []string{
		"paste", "clipboard_paste", "clipboard_write", "type_text", "input_text",
		"keyboard_type", "fill", "submit", "click_submit", "enter_text", "set_value",
	}
	return containsAny(lname, needles)
}

// isBrowserInteractionTool matches generic UI interaction tool names that
// count as engagement with the current page but carry no disclosable payload
// themselves.
func isBrowserInteractionTool(lname string) bool {
	needles := []string{
		"click", "press", "interact", "browser_action", "computer_use", "activate",
	}
	return containsAny(lname, needles)
}

// urlArgNames are the argument keys most browser-automation navigate tools
// use for the destination URL.
var urlArgNames = []string{"url", "uri", "href", "link", "destination"}

// allURLOrigins extracts the host of every http(s) URL found under a known
// URL-ish key — returning EVERY origin the first such key resolves to, not just
// the first (#3727 pass-2 finding 2). A normalized-name collision resolves one
// `url` key to several values; returning them all lets the caller evaluate each,
// so a benign origin that sorts first cannot hide an attacker one.
//
// Resolution is argFieldRecovered (exact-then-render-recovery, not a raw map
// index and not the full resolveField ladder — #3691/#3712/#3720/#3727), so a
// Unicode-separator-corrupted key still resolves while an ASCII case/convention
// variant does not. When no keyed URL resolves it falls back to scanning all
// string values; that scan is deduped and sorted so the result is deterministic
// rather than map-iteration-ordered.
func allURLOrigins(args map[string]interface{}) []string {
	var origins []string
	seen := map[string]bool{}
	add := func(o string) {
		if o != "" && !seen[o] {
			seen[o] = true
			origins = append(origins, o)
		}
	}
	for _, k := range urlArgNames {
		before := len(origins)
		for _, v := range argFieldRecovered(args, k) {
			add(hostOf(argValueToString(v)))
		}
		if len(origins) > before {
			return origins // first key that yields an origin wins; all of its origins
		}
	}
	for _, v := range args {
		add(hostOf(argValueToString(v)))
	}
	sort.Strings(origins)
	return origins
}

// firstURLOrigin returns the first origin allURLOrigins resolves, or "". Kept as
// the single-value view for callers/tests that only need one; the tracker uses
// allURLOrigins so a collision is evaluated in full.
func firstURLOrigin(args map[string]interface{}) string {
	origins := allURLOrigins(args)
	if len(origins) == 0 {
		return ""
	}
	return origins[0]
}

// hostOf returns the lowercased hostname of raw if it parses as an http(s)
// URL, or "" otherwise.
func hostOf(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
