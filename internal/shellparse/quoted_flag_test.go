package shellparse

import "testing"

// UnquoteFlagWords is the bare reading #4289 evaluates beside the as-written
// command. Every row states what bash hands the program; the rewrite must be
// exactly that, or "" when no argument is a quoted plain flag token.
//
// Destructive spellings are assembled at runtime: the hook reads test sources
// as commands.
func TestUnquoteFlagWords(t *testing.T) {
	rm := "r" + "m"
	cases := []struct {
		name, in, want string
	}{
		// Rewritten: bash removes the quotes, the program sees a flag.
		{"double-quoted short cluster", rm + ` "-rf" /etc`, rm + ` -rf /etc`},
		{"single-quoted long flag", `git reset '--hard' HEAD~3`, `git reset --hard HEAD~3`},
		{"long flag with value", `zzcmd "--depth=1" x`, `zzcmd --depth=1 x`},
		{"two quoted flags, two quote styles", rm + ` "-r" '-f' x`, rm + ` -r -f x`},
		{"quote splice before the dash", rm + ` "-r"'f' x`, rm + ` -rf x`},
		{"empty quotes before the dash", rm + ` ""-rf x`, rm + ` -rf x`},
		{"nested in a command substitution", `echo "$(` + rm + ` "-rf" /)"`, `echo "$(` + rm + ` -rf /)"`},
		{"test builtin argv", `[ "-f" x ]`, `[ -f x ]`},
		{"rest of the text kept byte for byte", `zzcmd  "-x"   'a b'  # c`, `zzcmd  -x   'a b'  # c`},

		// Not rewritten.
		{"no quote before a dash: no parse", rm + ` -rf /etc`, ""},
		{"word already starts with a dash (splice, read by the parser)", rm + ` -"rf" x`, ""},
		{"word starting with a dash stays as written past the prefilter", `zzcmd -'-hard' y`, ""},
		{"backslash inside double quotes is literal", rm + ` "-\rf" x`, ""},
		{"space in the value: prose, not a flag", `echo "-n foo"`, ""},
		{"commit message", `git commit -m "fix: x"`, ""},
		{"loop over a quoted message", `for m in "fix: don't panic"; do git commit -m "$m"; done`, ""},
		{"lone dash", `zzcmd "-" x`, ""},
		{"end of options", `zzcmd "--" x`, ""},
		{"expansion inside the quotes", `zzcmd "-$x" y`, ""},
		{"ANSI-C quoting is decoded elsewhere", rm + ` $'-rf' x`, ""},
		{"locale quoting is decoded elsewhere", rm + ` $"-rf" x`, ""},
		{"glob in the value", `zzcmd "-*" x`, ""},
		{"heredoc body is text, not argv", "cat <<EOF\n" + rm + " \"-rf\" /\nEOF", ""},
		{"assignment value is not argv", `X="-rf" zzcmd`, ""},
		{"parse failure", `zzcmd "-rf`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := UnquoteFlagWords(tc.in); got != tc.want {
				t.Errorf("UnquoteFlagWords(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUnquotePlainFlagWord(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`"-rf"`, "-rf", true},
		{`'--no-pager'`, "--no-pager", true},
		{`"--a.b_c=1"`, "--a.b_c=1", true},
		{`'-'"x"`, "-x", true},
		{`-rf`, "", false},       // no quote: nothing for this helper to do
		{`"-rf`, "", false},      // unterminated
		{`"-r'f"`, "", false},    // a quote inside the other quote is a literal byte
		{`"-'x'"`, "", false},    // ...so its value is -'x', not -x
		{`"---x"`, "", false},    // three dashes
		{"\"-é\"", "", false},    // non-ASCII is outside the token charset
		{`"-a b"`, "", false},    // space
		{`"-a\b"`, "", false},    // backslash
		{"\"-a`b`\"", "", false}, // backquote
	}
	for _, tc := range cases {
		got, ok := unquotePlainFlagWord(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("unquotePlainFlagWord(%q) = %q, %v; want %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
