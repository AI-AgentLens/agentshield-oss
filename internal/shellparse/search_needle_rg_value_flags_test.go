package shellparse

import "testing"

// #4657 pass 1: the needle finder applies grep's boolean-flag table to every
// grep-family name. ripgrep's -r REPLACEMENT and -E ENCODING and ag's -G FILE-REGEX
// take a value, so reading them as booleans made the value the needle, and rg
// prints a -r replacement. Those spellings must keep their words live; the
// grep spellings, and rg's glued or long forms, keep their needle.
func TestSearchToolNeedles_ValueFlagsOfRgAndAg_4657(t *testing.T) {
	cases := []struct {
		name, cmd string
		want      bool
	}{
		// control: grep's -r and -E are booleans, the next word is the needle
		{"grep -r bool", `grep -r foo dir`, true},
		{"grep -E bool", `grep -E foo file`, true},
		{"grep -G bool", `grep -G foo file`, true},
		{"rg bare pattern", `rg foo file`, true},
		{"ag bare pattern", `ag foo file`, true},
		{"rg -i bool", `rg -i foo file`, true},
		// the glued long form keeps the replacement in the text a rule reads;
		// only `foo` is redacted
		{"rg --replace= glued", `rg --replace=HELLO foo file`, true},
		// rg: -r and -E consume the next word
		{"rg -r separate", `rg -r HELLO foo file`, false},
		{"rg -E separate", `rg -E utf-16 foo file`, false},
		{"rg -ir cluster", `rg -ir HELLO foo file`, false},
		{"rg -rn cluster", `rg -rn HELLO foo file`, false},
		{"rg path-qualified", `/opt/homebrew/bin/rg -r HELLO foo file`, false},
		{"rg inline cluster -re", `rg -re"$p" file`, false},
		// ag: -G consumes the next word
		{"ag -G separate", `ag -G '\.go$' foo file`, false},
	}
	for _, tc := range cases {
		items, red := SearchToolNeedles(tc.cmd)
		if got := red != ""; got != tc.want {
			t.Errorf("%s: %q redacted=%v want %v (items=%v red=%q)", tc.name, tc.cmd, got, tc.want, items, red)
		}
	}
}
