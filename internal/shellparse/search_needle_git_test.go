package shellparse

import "testing"

// #4331: the glued git pickaxe string is a search needle; every other
// spelling keeps its words live.
func TestSearchToolNeedles_GitPickaxe(t *testing.T) {
	cases := []struct {
		name, cmd string
		want      bool
	}{
		{"glued single-quoted", `git log -S'a.txt' --oneline`, true},
		{"glued double-quoted var", `git log -G"$p" -- x`, true},
		{"glued bare", `git diff -Sfoo HEAD~1`, true},
		{"show", `git show -S'x' abc`, true},
		{"separate word stays live", `git log -S 'a.txt'`, false},
		{"global option before subcommand", `git -c core.pager=x log -S'a'`, false},
		{"other subcommand", `git commit -S'a'`, false},
		{"after --", `git log -- -S'a'`, false},
		{"cmd subst", `git log -S"$(whoami)"`, false},
		{"unquoted var", `git log -S$p`, false},
	}
	for _, tc := range cases {
		items, red := SearchToolNeedles(tc.cmd)
		if got := red != ""; got != tc.want {
			t.Errorf("%s: %q redacted=%v want %v (items=%v red=%q)", tc.name, tc.cmd, got, tc.want, items, red)
		}
	}
}
