package mcp

import "testing"

// Regression tests for #3754 regression 2 -- the post-merge review of #3744.
// #3744 made currentOrigins a SET but left awaitingDisclosure a single shared
// boolean. When the possible-current-origin set holds more than one member, a
// navigation that is same-origin for ONE member (anySameOrigin == true) fails
// to clear the shared flag even though every concrete path has invalidated the
// window it was armed for. The stale flag then makes a paste fire falsely AND
// latches `fired`, suppressing a later genuine detection in the same session.
//
// The invariant: armed at the sink -> ambiguous nav [sink, other] -> unambiguous
// nav to other CLEARS the window (no false paste), AND a subsequent genuine
// armed session still fires.

const (
	poGameOrigin  = "puzzle.example.com"
	poSinkOrigin  = "attacker.example.net"
	poOtherOrigin = "unrelated.example.org"
)

// poArmAtSink walks a tracker to the armed-at-sink state: navigate to the game,
// engage, read the clipboard, navigate cross-origin to the sink. After this the
// sink is the sole possible current origin and disclosure is armed there.
func poArmAtSink(tr *BrowserGameJailbreakTracker) {
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poGameOrigin + "/game"})
	for i := 0; i < browserGameMinInteractions; i++ {
		tr.Scan("click", map[string]interface{}{"selector": "#next-level"})
	}
	tr.Scan("read_clipboard", map[string]interface{}{})
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poSinkOrigin + "/submit"})
}

// TestBrowserPerOrigin_AmbiguousThenAwayClears is the E2 regression. On the merge
// that introduced the bug the final paste FIRES; after the fix it must not.
func TestBrowserPerOrigin_AmbiguousThenAwayClears(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)

	// VACUITY CONTROL: armed at sink, an immediate paste fires (the window is
	// genuinely live before the clearing navigations).
	t.Run("control/armed window fires", func(t *testing.T) {
		tr := NewBrowserGameJailbreakTracker()
		poArmAtSink(tr)
		if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != SignalBrowserGameJailbreakSession {
			t.Fatalf("control: armed window gave %q, want %q", got, SignalBrowserGameJailbreakSession)
		}
	})

	t.Run("ambiguous [sink,other] then unambiguous other clears", func(t *testing.T) {
		tr := NewBrowserGameJailbreakTracker()
		poArmAtSink(tr)
		// Ambiguous navigation: could be same-origin (sink) or a move to other.
		tr.Scan("browser_navigate", map[string]interface{}{
			"url" + nbsp: "https://" + poSinkOrigin + "/page2",
			"url" + zwj:  "https://" + poOtherOrigin + "/land",
		})
		// Unambiguous navigation to other. Under BOTH concrete interpretations of
		// the prior step the sink-armed window is now dead: sink->other is a bare
		// cross-origin move with no fresh engagement, and other->other means we
		// were never at the sink. The window must clear.
		tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poOtherOrigin + "/next"})
		if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != "" {
			t.Fatalf("every concrete path invalidated the window, yet the paste produced %q; want no signal", got)
		}
	})
}

// TestBrowserPerOrigin_SameOriginReloadDoesNotArm pins that arming requires a
// CROSS-origin transition: engaging on a page, reading the clipboard, then
// re-navigating to the SAME origin (a reload) must not arm disclosure — there
// was no move to a different origin. Kills the mutation "drop the `prev != dest`
// cross-origin requirement in the (a) arming clause".
func TestBrowserPerOrigin_SameOriginReloadDoesNotArm(t *testing.T) {
	tr := NewBrowserGameJailbreakTracker()
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poGameOrigin + "/game"})
	for i := 0; i < browserGameMinInteractions; i++ {
		tr.Scan("click", map[string]interface{}{"selector": "#next-level"})
	}
	tr.Scan("read_clipboard", map[string]interface{}{})
	// Same-origin re-navigation (a reload of the game page), not a move elsewhere.
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poGameOrigin + "/game?level=2"})
	if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != "" {
		t.Fatalf("a same-origin reload must not arm disclosure (no cross-origin transition): got %q, want no signal", got)
	}
}

// TestBrowserPerOrigin_GenuineSessionAfterClearedAmbiguityStillFires is E2': the
// false paste above must not latch `fired`. After the cleared ambiguous window,
// a fresh genuine engage -> read -> cross-origin nav -> paste must still fire.
func TestBrowserPerOrigin_GenuineSessionAfterClearedAmbiguityStillFires(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)

	tr := NewBrowserGameJailbreakTracker()
	poArmAtSink(tr)
	tr.Scan("browser_navigate", map[string]interface{}{
		"url" + nbsp: "https://" + poSinkOrigin + "/page2",
		"url" + zwj:  "https://" + poOtherOrigin + "/land",
	})
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poOtherOrigin + "/next"})
	// The false paste that used to fire here (and latch `fired`):
	if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != "" {
		t.Fatalf("setup precondition: the cleared window must not fire, got %q", got)
	}

	// A genuine session now runs on the SAME tracker: re-engage on the current
	// page (other), read the clipboard, navigate cross-origin to the sink, paste.
	for i := 0; i < browserGameMinInteractions; i++ {
		tr.Scan("click", map[string]interface{}{"selector": "#next-level"})
	}
	tr.Scan("read_clipboard", map[string]interface{}{})
	tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + poSinkOrigin + "/submit"})
	if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != SignalBrowserGameJailbreakSession {
		t.Fatalf("a genuine session after a cleared ambiguous window was suppressed: got %q, want %q",
			got, SignalBrowserGameJailbreakSession)
	}
}
