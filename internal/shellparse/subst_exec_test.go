package shellparse

import (
	"strings"
	"testing"
)

// TestExecutedSubstitutionBodies pins which substitutions have their OUTPUT
// executed (#3976). The payload is a harmless marker; what is asserted is
// only whether the marker's substitution is reported as executed.
func TestExecutedSubstitutionBodies(t *testing.T) {
	const m = "zqmarker now"
	hd := "cat <<'EOF'\n" + m + "\nEOF\n"
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// Positive: the substitution's output is run as a program.
		{"bash -c cmdsub", `bash -c "$(` + hd + `)"`, true},
		{"sh -ec cluster", `sh -ec "$(` + hd + `)"`, true},
		{"sudo bash -c", `sudo bash -c "$(` + hd + `)"`, true},
		{"env bash -c", `env FOO=1 bash -c "$(` + hd + `)"`, true},
		{"python3 -c", `python3 -c "$(` + hd + `)"`, true},
		{"node -e", `node -e "$(` + hd + `)"`, true},
		{"eval cmdsub", `eval "$(` + hd + `)"`, true},
		{"eval backquote", "eval \"`" + "echo " + m + "`\"", true},
		{"bash procsub", `bash <(` + hd + `)`, true},
		{"source procsub", `source <(` + hd + `)`, true},
		{"dot procsub", `. <(` + hd + `)`, true},
		{"bash here-string", `bash <<< "$(` + hd + `)"`, true},
		{"cmdsub as command word", `"$(` + hd + `)"`, true},
		{"capture then eval", `x=$(` + hd + `); eval "$x"`, true},
		{"capture then bash -c", `x=$(` + hd + `); bash -c "$x"`, true},
		{"export capture then run", `export x=$(` + hd + `); $x`, true},

		// Negative: the output is printed, stored, or handed to a script as data.
		{"echo cmdsub (printed)", `echo "$(` + hd + `)"`, false},
		{"git commit -m idiom", `git commit -m "$(` + hd + `)"`, false},
		{"gh body", `gh issue comment 1 --body "$(` + hd + `)"`, false},
		{"script arg, not program", `bash script.sh "$(` + hd + `)"`, false},
		{"procsub as script data", `python3 x.py <(` + hd + `)`, false},
		{"cat procsub", `cat <(` + hd + `)`, false},
		{"diff procsubs", `diff <(echo a) <(echo b)`, false},
		{"bash -c with dynamic program", `bash -c "$cmd"`, false},
		{"capture never executed", `x=$(` + hd + `); echo "$x"`, false},
		{"plain heredoc", hd, false},
		{"bash here-string with -c program", `bash -c 'echo hi' <<< "$(` + hd + `)"`, false},
	}
	for _, c := range cases {
		got := false
		for _, b := range ExecutedSubstitutionBodies(c.cmd) {
			if strings.Contains(b, m) || strings.Contains(b, "zqmarker") {
				got = true
			}
		}
		if got != c.want {
			t.Errorf("%s: executed=%v, want %v\n  cmd: %q\n  bodies: %q", c.name, got, c.want, c.cmd, ExecutedSubstitutionBodies(c.cmd))
		}
	}
}
