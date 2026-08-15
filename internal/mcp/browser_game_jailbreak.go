package mcp

import (
	"net/url"
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
	currentOrigin       string // origin of the page currently under interactive engagement
	interactionCount    int    // interaction calls observed on currentOrigin since the last navigate
	sawCredentialSignal bool   // a clipboard read was observed while engaged with currentOrigin
	awaitingDisclosure  bool   // just navigated to a new origin after engagement + a credential signal
	fired               bool
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
		if t.state.awaitingDisclosure && hasPayloadArg(args) {
			t.state.fired = true
			t.state.awaitingDisclosure = false
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
	origin := firstURLOrigin(args)
	if origin == "" {
		return
	}

	if t.state.currentOrigin != "" && origin != t.state.currentOrigin &&
		t.state.interactionCount >= browserGameMinInteractions && t.state.sawCredentialSignal {
		t.state.awaitingDisclosure = true
	} else if origin != t.state.currentOrigin {
		// Navigated away without meeting the engagement+credential-read bar —
		// any previously armed disclosure window is now stale.
		t.state.awaitingDisclosure = false
	}

	// Start tracking engagement fresh on the newly loaded page.
	t.state.currentOrigin = origin
	t.state.interactionCount = 0
	t.state.sawCredentialSignal = false
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

// firstURLOrigin extracts the host of the first http(s) URL found in args —
// checking known URL-ish keys first, then falling back to a scan of all
// string values for a scheme-prefixed URL.
func firstURLOrigin(args map[string]interface{}) string {
	for _, k := range urlArgNames {
		if v, ok := args[k]; ok {
			if origin := hostOf(argValueToString(v)); origin != "" {
				return origin
			}
		}
	}
	for _, v := range args {
		if origin := hostOf(argValueToString(v)); origin != "" {
			return origin
		}
	}
	return ""
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
