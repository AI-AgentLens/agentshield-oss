package shellparse

import "testing"

// ZshReading (#4598): the text a command the bash parser rejects reads as
// once the zsh parser has read it. Inert stand-ins only; the policy tests
// carry the witnesses.
func TestZshReading(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		// No reading: bash already parses it, or zsh rejects it too.
		{"bash-valid", `: ${HOME}; echo B1`, ""},
		{"bash-valid brace group", `{ echo B2; }`, ""},
		{"empty", ``, ""},
		{"zsh short for is a residual (#4598)", `for i (1) echo B4`, ""},
		{"rejected by both", `echo "unterminated`, ""},

		// The issue's transforms.
		{"parameter flags", `: ${(U)HOME}; echo B1`, `: ${HOME}; echo B1`},
		{"brace group without separator", `{ echo B2 }`, `{ echo B2 ; }`},
		{"anonymous function", `() { echo B3 }`, `{ echo B3 ; }`},
		{"anonymous function, reserved word", `function { echo B3 }`, `{ echo B3 ; }`},

		// Other zsh-only spellings the dialect parses.
		{"flags inside double quotes", `echo "${(L)HOME}/x"; echo y`, `echo "${HOME}/x"; echo y`},
		{"nested expansion", `echo ${${HOME}:h}`, `echo ${HOME}`},
		{"is-set expansion", `echo ${+HOME}`, `echo ${HOME}`},
		{"split option", `echo ${=HOME}`, `echo ${HOME}`},
		{"brace group in a pipeline", `{ echo e } | cat`, `{ echo e ; } | cat`},
		{"brace group in a list", `echo x; { echo y }; echo z`, `echo x; { echo y ; }; echo z`},
		{"multi-statement brace group", `{ echo a; echo b }`, `{ echo a; echo b ; }`},
		{"named function body", `f() { echo c }`, `f() { echo c ; }`},
		{"multi-name function", `function a b { echo d }`, `a() { echo d ; }`},
		{"temp-file process substitution", `diff =(ls) =(ls -a)`, `diff <(ls) <(ls -a)`},
		{"heredoc on the brace line", "{ cat <<EOF }\nbody\nEOF", "{ cat <<EOF ; }\nbody\nEOF"},
		{"brace group inside a substitution", `echo $( { echo h } )`, `echo $( { echo h ; } )`},

		// The zsh parser rejects a backslash-spliced assignment name as the
		// bash parser does; it is read through #3211's fold, as
		// DequoteCommand reads it for bash. The fold alone is not a zsh
		// reading.
		{"backslash-spliced assignment name", `: ${(U)HOME}; export FO\O=1`, `: ${HOME}; export FOO=1`},
		{"fold alone is #3211's", `export FO\O=1`, ""},

		// A leaf statement no edit makes bash is written `:`.
		{"floating-point arithmetic statement", `: $((1.5)); echo g`, `:; echo g`},
		{"unrenderable statement in a pipeline", `echo g | : $((1.5))`, `echo g | :`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ZshReading(tc.in)
			if got != tc.want {
				t.Errorf("ZshReading(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if got != "" && !parsesAsBash(got) {
				t.Errorf("reading %q does not parse as bash", got)
			}
		})
	}
}

// A leaf statement with a heredoc that no edit makes bash is not written `:`:
// its body would be left behind as commands. There is no reading at all.
func TestZshReading_HeredocLeafThatStaysZshHasNoReading(t *testing.T) {
	in := "cat <<EOF $((1.5))\nline one\nEOF\necho after"
	if got := ZshReading(in); got != "" {
		t.Errorf("ZshReading(%q) = %q, want no reading", in, got)
	}
}

// Every reading parses as bash, and none is longer than a small constant over
// the input: the edits rename or remove, they never add statements.
func TestZshReading_NeverPanicsAndAlwaysParses(t *testing.T) {
	for _, in := range []string{
		`${(`, `() {`, `{ }`, `{`, `}`, `() { } () { }`, `${(U)}`, `${${${x}}}`,
		`: ${(%):-%n}`, `echo ${x[(i)y]}`, `echo ${(s.:.)PATH}`, `cmd &|`, `cmd &!`,
		"a\n{ b }\n() { c }\n: ${(U)d}", `{ { { echo deep } } }`,
	} {
		got := ZshReading(in)
		if got != "" && !parsesAsBash(got) {
			t.Errorf("ZshReading(%q) = %q, which does not parse as bash", in, got)
		}
		if len(got) > len(in)+64 {
			t.Errorf("ZshReading(%q) = %q grew past the input", in, got)
		}
	}
}
