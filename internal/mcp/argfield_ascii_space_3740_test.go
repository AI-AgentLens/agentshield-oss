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

// --- finding 3: recovery must delete only the disguise, never a typed space ---

// TestArgFieldRecovered_PreservesLegitimateASCIISpaces is the #3740 finding-3
// regression. Post-fold space stripping used to run over the WHOLE recovered
// string, so an ASCII space the caller actually typed disappeared as soon as any
// disguise rune elsewhere in the key made RecoverRenderedText report changed.
func TestArgFieldRecovered_PreservesLegitimateASCIISpaces(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)

	t.Run("control/plain ASCII key resolves exactly", func(t *testing.T) {
		if got := argFieldRecovered(map[string]interface{}{"url": "v"}, "url"); len(got) != 1 {
			t.Fatalf("vacuous control: exact ASCII `url` did not resolve, got %v", got)
		}
	})

	t.Run("control/url+NBSP still recovers to url", func(t *testing.T) {
		if got := argFieldRecovered(map[string]interface{}{"url" + nbsp: "v"}, "url"); len(got) != 1 {
			t.Fatalf("separator recovery regressed: `url`+NBSP did not resolve to `url`, got %v", got)
		}
	})

	t.Run("spaced input with ZWJ must not match an unspaced key", func(t *testing.T) {
		for name, k := range map[string]string{
			"ZWJ inside the second word": "u r" + zwj + "l",
			"ZWJ after the space":        "u " + zwj + "rl",
			"NBSP appended":              "u rl" + nbsp,
		} {
			if got := argFieldRecovered(map[string]interface{}{k: "v"}, "url"); len(got) != 0 {
				t.Errorf("%s: %q resolved to key `url` (%v) — the typed ASCII space was stripped", name, k, got)
			}
		}
	})

	t.Run("a spaced rule key matches its own spelling", func(t *testing.T) {
		// Exact: unchanged by recovery, resolved by the exact index.
		if got := argFieldRecovered(map[string]interface{}{"u rl": "v"}, "u rl"); len(got) != 1 {
			t.Errorf("exact spaced key did not resolve, got %v", got)
		}
		// Disguised: only the disguise rune is removed, the typed space survives.
		if got := argFieldRecovered(map[string]interface{}{"u r" + zwj + "l": "v"}, "u rl"); len(got) != 1 {
			t.Errorf("disguised spelling of the spaced key did not resolve, got %v", got)
		}
	})

	t.Run("an unspaced input must not match a spaced key", func(t *testing.T) {
		if got := argFieldRecovered(map[string]interface{}{"ur" + zwj + "l": "v"}, "u rl"); len(got) != 0 {
			t.Errorf("`url`-shaped input resolved to the spaced key `u rl`, got %v", got)
		}
	})
}

// TestRecoverDisguiseOnly_SpaceProvenance pins the exact space semantics the
// #3740 finding-3 fix chose, because "delete only the disguise" has three
// distinguishable cases and two of them are load-bearing elsewhere.
func TestRecoverDisguiseOnly_SpaceProvenance(t *testing.T) {
	nbsp := sepRune(0x00A0)
	zwj := sepRune(0x200D)
	thin := sepRune(0x2009)

	cases := []struct {
		name    string
		in      string
		want    string
		changed bool
	}{
		{"all-ASCII is never folded", "url", "url", false},
		{"all-ASCII with a typed space is never folded", "u rl", "u rl", false},
		{"trailing separator folds away", "url" + nbsp, "url", true},
		{"interior separator with no typed space still folds away (#3712)", "u" + nbsp + "rl", "url", true},
		{"zero-width interior still folds away", "u" + zwj + "rl", "url", true},
		{"separator run mixing ASCII and Unicode is trailing whitespace (#3731)", "url " + nbsp, "url", true},
		{"separator run, Unicode then ASCII", "url" + nbsp + " ", "url", true},
		{"separator run, alternating", "url " + nbsp + " " + thin, "url", true},
		{"a typed interior space survives a disguise elsewhere", "u r" + zwj + "l", "u rl", true},
		{"a typed interior space survives an appended separator", "u rl" + nbsp, "u rl", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := recoverDisguiseOnly(tc.in)
			if got != tc.want || changed != tc.changed {
				t.Errorf("recoverDisguiseOnly(%q) = (%q, %v), want (%q, %v)",
					tc.in, got, changed, tc.want, tc.changed)
			}
		})
	}
}
