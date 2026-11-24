package mcp

import (
	"encoding/json"
	"strings"
	"testing"
)

// A number too large for float64 is still a number, and it is larger than any
// cap. Before #4997 such a value, written as text or carried as a json.Number,
// counted as "not a number", so the cap was skipped: 400 nines in `amount`
// passed a cap of 100 while 500 was blocked.
func TestCheckValueLimits_NumberTooLargeForFloat64StillTripsTheCap(t *testing.T) {
	e := taxonomyValueLimitEvaluator() // cap-amount: `amount` over 100 on tool "pay" is BLOCK
	nines := strings.Repeat("9", 400)

	capFires := func(value interface{}) bool {
		for _, f := range e.CheckValueLimits("pay", map[string]interface{}{"amount": value}).Findings {
			if f.RuleID == "cap-amount" {
				return true
			}
		}
		return false
	}

	over := []struct {
		name  string
		value interface{}
	}{
		{"control: a number over the cap", 500.0},
		{"control: text over the cap", "500"},
		{"control: Infinity as text", "Infinity"},
		{"400 digits as text", nines},
		{"400 digits as text, padded", "  " + nines + " "},
		{"huge exponent as text", "1e400"},
		{"400 digits as json.Number", json.Number(nines)},
		{"huge exponent as json.Number", json.Number("1e400")},
	}
	for _, c := range over {
		if !capFires(c.value) {
			t.Errorf("%s: the cap did not fire", c.name)
		}
	}

	// The other direction, and things that are not numbers, must not start to
	// trip an upper cap.
	under := []struct {
		name  string
		value interface{}
	}{
		{"control: a number under the cap", 12.0},
		{"control: text under the cap", "12"},
		{"400 digits, negative, as text", "-" + nines},
		{"huge negative exponent as text", "-1e400"},
		{"huge negative exponent as json.Number", json.Number("-1e400")},
		{"a tiny number as text", "1e-400"},
		{"text that is not a number", "ninety"},
		{"digits followed by letters", nines + "abc"},
		{"empty text", ""},
		{"NaN as text", "NaN"},
	}
	for _, c := range under {
		if capFires(c.value) {
			t.Errorf("%s: the cap fired", c.name)
		}
	}
}
