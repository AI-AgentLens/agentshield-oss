package shellparse

import "testing"

// #4714: grep permutes options, so a pattern option AFTER the first positional
// (`grep /etc/shadow -e root`) makes that positional a FILE. The needle finder
// took it as the pattern, and every search_needle rule excused the file it
// names (sec-block-etc-shadow decided ALLOW). `--file=PATS` before the operand
// did the same. Those shapes must refuse; a permuted boolean flag, a filter
// with an inline value, and anything after `--` keep the needle.
func TestSearchToolNeedles_PermutedPatternOption_4714(t *testing.T) {
	cases := []struct {
		name, cmd string
		needle    bool
	}{
		// controls: the first positional is the pattern
		{"plain", `grep foo file`, true},
		{"permuted boolean short", `grep foo file -n`, true},
		{"permuted boolean cluster", `grep foo file -in`, true},
		{"permuted boolean long", `grep foo file --count`, true},
		{"permuted filter with inline value", `grep foo file --include=*.go`, true},
		{"stdin operand", `grep foo -`, true},
		{"after end of options", `grep foo -- -e`, true},
		{"dynamic operand", `grep foo "$f"`, true},
		{"glued -e first, more -e later", `grep -efoo file -e bar`, true},
		// a later pattern option makes every positional a file
		{"later -e separate", `grep /etc/shadow -e root`, false},
		{"later -e glued", `grep /etc/shadow -eroot`, false},
		{"later -ie cluster", `grep /etc/shadow -ie root`, false},
		{"later --regexp=", `grep /etc/shadow --regexp=root`, false},
		{"later --regexp separate", `grep /etc/shadow --regexp root`, false},
		{"later -f", `grep /etc/shadow -f pats.txt`, false},
		{"later --file=", `grep /etc/shadow --file=pats.txt`, false},
		{"later abbreviated --rege=", `grep /etc/shadow --rege=root`, false},
		{"later value flag of unknown arity", `grep foo file -A 2`, false},
		{"egrep later -e", `egrep /etc/shadow -e root`, false},
		{"rg later -e", `rg /etc/shadow -e root`, false},
		// --file=PATS before the operand supplies the patterns too
		{"--file= before", `grep --file=pats.txt /etc/shadow`, false},
		{"abbreviated --fil= before", `grep --fil=pats.txt /etc/shadow`, false},
	}
	for _, tc := range cases {
		items, red := SearchToolNeedles(tc.cmd)
		if got := red != ""; got != tc.needle {
			t.Errorf("%s: %q needle=%v want %v (items=%v red=%q)", tc.name, tc.cmd, got, tc.needle, items, red)
		}
	}
}
