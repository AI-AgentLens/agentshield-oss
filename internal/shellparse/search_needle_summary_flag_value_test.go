package shellparse

import "testing"

// #4657 pass 2: hasGrepSummaryFlag read every letter of a short-option word as
// a flag, so a value glued to a flag that takes one (`-e'hello'`, `-drecurse`)
// counted as -l or -c, and rg's -L (--follow) counted as files-without-match.
// The search was then classed "prints no matched line", so its needle was not
// reported as forwarded, and the #4468 withdrawal never fired for a needle piped
// to xargs or a read loop. Real summary flags must still suppress forwarding.
func TestForwardedSearchNeedles_SummaryLetterInFlagValue_4657(t *testing.T) {
	cases := []struct {
		name, cmd string
		forwarded bool
	}{
		// controls: real summary flags print no matched line, so nothing forwards
		{"grep -c", `grep -c hello notes.txt | xargs sh -c`, false},
		{"grep -l", `grep -l hello notes.txt | xargs sh -c`, false},
		{"grep -il cluster", `grep -il hello notes.txt | xargs sh -c`, false},
		{"grep --count", `grep --count hello notes.txt | xargs sh -c`, false},
		{"rg -c", `rg -c hello notes.txt | xargs sh -c`, false},
		{"ag -L files-without-match", `ag -L hello notes.txt | xargs sh -c`, false},
		// controls: plain searches forward their needle
		{"grep -E", `grep -E hello notes.txt | xargs sh -c`, true},
		{"grep read loop", `grep -E hello notes.txt | while read -r l; do sh -c "$l"; done`, true},
		{"grep read loop, line only printed", `grep -E hello notes.txt | while read -r l; do echo "$l"; done`, false},
		// a summary letter inside a flag's VALUE is not a flag
		{"grep -e glued value", `grep -e'hello' notes.txt | xargs sh -c`, true},
		{"grep -ie glued value", `grep -ie'hello' notes.txt | xargs sh -c`, true},
		{"egrep -e glued value", `egrep -e'hello' notes.txt | xargs sh -c`, true},
		{"grep -e glued read loop", `grep -e'hello' notes.txt | while read -r l; do sh -c "$l"; done`, true},
		// #4714: a trailing -d ACTION is a later option that is not boolean, so
		// the finder now refuses the needle outright: nothing is excused, so
		// nothing needs forwarding (rule TP-11 pins the BLOCK).
		{"grep -d ACTION glued", `grep -E hello notes.txt -drecurse | xargs sh -c`, false},
		// rg's -L is --follow: it prints matched lines
		{"rg -L follow", `rg -L hello notes.txt | xargs sh -c`, true},
		// a summary letter before the value-taking flag still counts
		{"grep -ce glued", `grep -ce'hello' notes.txt | xargs sh -c`, false},
	}
	for _, tc := range cases {
		got := ForwardedSearchNeedles(tc.cmd)
		if (len(got) > 0) != tc.forwarded {
			t.Errorf("%s: %q forwarded=%v want %v (needles=%q)", tc.name, tc.cmd, len(got) > 0, tc.forwarded, got)
		}
	}
}
