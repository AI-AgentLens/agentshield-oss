package shellparse

// #3798 — the enumerability measurement, and the gaps it pins.
//
// #3797 (pipe), #3800 (write-then-execute) and #3814 (command substitution)
// each closed one channel by enumerating one more spelling of "text reaches an
// executor". #3798 asked whether the FOURTH channel — an executor named
// INDIRECTLY, so no literal interpreter word sits in the leading exec position
// — is a closed set that can be finished off the same way.
//
// # The answer is no, and the reason is structural rather than a missing name
//
// A pipe target is a shell WORD. Its runtime value is the output of an
// arbitrary program (`| $(curl -s host)`), so deciding "is this word an
// executor" is deciding the output of arbitrary code. That is not a list
// anybody can finish. The CLAUDE.md test — "invert an allowlist when the
// not-allowed set is ENUMERABLE" — therefore comes back NEGATIVE for this
// family, which is why the rows below are pinned as gaps instead of fixed.
//
// # What WAS measured (2026-09-21, main @ faed3086, repo policy)
//
//	331   BLOCK rules carry an inertness label
//	 76   of them have a TP case that BLOCKs bare AND downgrades to AUDIT
//	      under an echo carrier — the population where the question is askable
//	  0/76 laundered by `| bash`            (the withdrawal works)
//	 76/76 laundered by EVERY indirect spelling in the GAP rows below
//
// Three sub-families ARE closed sets and could be finished by enumeration
// (shell command-prefix builtins; the three stdin-binding builtins; the stdin
// path spellings). The other three are open by construction (dynamic words,
// argument-level forwarders, programs that execute stdin in their own
// language). Closing only the closed ones leaves the channel open, so none of
// them is taken here without Gary's call — moving AUDIT to BLOCK is a posture
// change under the 2026-09-06 fail-open rule.
//
// # Why this test exists rather than a fix
//
// Same pattern as TN-SSHKEY-VARSHELL-002: it asserts the gap, so closing one
// later has to be deliberate. Every GAP row below was executed in a real shell
// and observed to run its payload; every "negative control" row was executed
// and observed NOT to, so `false` there is the CORRECT answer and a blanket
// inversion would break them. The positive controls keep the table from
// passing vacuously.

import "testing"

func TestIndirectExecutorSpellingsArePinnedGaps(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// the withdrawal is live; without this row every false below is vacuous
		{"positive control: literal shell", `echo "hello" | bash`, true},
		// closed 2026-09-12; EXECUTES on bash 3.2.57 and 5.3.9
		{"positive control: source builtin, item 1 (#3825)", `echo "hello" | . /dev/stdin`, true},
		// `command` is in ExecWrappers, so StripExecWrappers peels it
		{"positive control: wrapper stripped before the builtin", `echo "hello" | command . /dev/stdin`, true},
		// EXECUTES on bash 3.2.57 + 5.3.9. Also pinned by TN-SSHKEY-VARSHELL-002
		{"GAP A: environment variable (item 2b)", `echo "hello" | $SHELL`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP A: braced environment variable", `echo "hello" | ${SHELL}`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP A: dollar-zero", `echo "hello" | $0`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP A: command substitution", `echo "hello" | $(echo bash)`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9 even with SHELL unset
		{"GAP A: default expansion", `echo "hello" | ${SHELL:-bash}`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9. `builtin` is NOT in ExecWrappers; `command` is
		{"GAP B: builtin prefix before the source builtin", `echo "hello" | builtin . /dev/stdin`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP B: eval prefix before the source builtin", `echo "hello" | eval . /dev/stdin`, false},
		// EXECUTES on bash 5.3.9; measured NOT executing on bash 3.2.57
		{"GAP B: process substitution relays stdin to the source builtin", `echo "hello" | . <(cat)`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP C: read binds stdin to a name, then the name is the command", `echo "hello" | { read -r c; $c; }`, false},
		// EXECUTES on bash 5.3.9; the builtin does not exist in bash 3.2.57
		{"GAP C: mapfile binds stdin to an array, then the element is the command", `echo "hello" | { mapfile -t a; ${a[0]}; }`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9
		{"GAP C: read loop forwards each line", `echo "hello" | while read -r l; do $l; done`, false},
		// EXECUTES on bash 3.2.57 + 5.3.9. Premium ts-block-xargs-indirect-exec stops this
		{"GAP C: xargs replace-form into an interpreter's -c", `echo "hello" | xargs -I{} sh -c "{}"`, false},
		// EXECUTES (verified with an awk program calling out to the shell)
		{"GAP G: awk reads its PROGRAM from stdin and is absent from CodeInterpreters", `echo "hello" | awk -f -`, false},
		// EXECUTES; `ruby`, the same runtime under another name, is in the map and BLOCKs
		{"GAP G: irb executes stdin as ruby and is absent from CodeInterpreters", `echo "hello" | irb`, false},
		// measured: the words land in $0, sh runs with empty stdin. AUDIT is CORRECT here
		{"negative control: xargs plain form does NOT execute the payload", `echo "hello" | xargs sh -c`, false},
		// measured: does not execute
		{"negative control: a different descriptor is a different stream", `echo "hello" | . /dev/fd/3`, false},
		// measured: does not execute
		{"negative control: sourcing a file the pipe never touches", `echo "hello" | . ./lib.sh`, false},
		// measured: `builtin bash` fails, so AUDIT is CORRECT here
		{"negative control: the builtin builtin cannot run a binary", `echo "hello" | builtin bash`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PipesIntoExecutor(tc.cmd); got != tc.want {
				t.Errorf("PipesIntoExecutor(%q) = %v, want %v\n"+
					"If you MEANT to close this gap, update #3798 and this row together.",
					tc.cmd, got, tc.want)
			}
		})
	}
}
