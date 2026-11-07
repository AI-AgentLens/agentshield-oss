package guardian

import (
	"strings"
	"testing"
)

// legacyStripPythonStringLiterals is stripPythonStringLiterals as it was at
// 08585cb1, the merge before #4619: every literal deleted, no f-string fields.
// It is the reading the current function must keep as a prefix (#4621).
func legacyStripPythonStringLiterals(cmd string) string {
	cmd = tripleQuoteSingleRe.ReplaceAllString(cmd, "")
	cmd = tripleQuoteDoubleRe.ReplaceAllString(cmd, "")
	cmd = innerSingleQuoteRe.ReplaceAllString(cmd, "")
	cmd = innerEscapedDoubleQuoteRe.ReplaceAllString(cmd, "")
	return cmd
}

// TestStripPythonStringLiterals_LegacyIsBytePrefix4621 pins the stricter-of-two
// shape: the pre-#4619 strip is a byte-identical prefix of the result, and the
// f-string fields follow on a line of their own. A field spliced in place could
// move a later `<<` cut or pair a stray quote with a later one; text after the
// prefix can do neither to the prefix.
func TestStripPythonStringLiterals_LegacyIsBytePrefix4621(t *testing.T) {
	var inputs []string
	for _, tc := range fstring4611Fire {
		inputs = append(inputs, tc.cmd)
	}
	for _, tc := range fstring4611Quiet {
		inputs = append(inputs, tc.cmd)
	}

	withFields := 0
	for _, cmd := range inputs {
		legacy := legacyStripPythonStringLiterals(cmd)
		got := stripPythonStringLiterals(cmd)
		if !strings.HasPrefix(got, legacy) {
			t.Errorf("legacy strip is not a prefix\n  cmd:    %q\n  legacy: %q\n  got:    %q", cmd, legacy, got)
			continue
		}
		rest := got[len(legacy):]
		if rest == "" {
			continue
		}
		withFields++
		if !strings.HasPrefix(rest, "\n") || !strings.HasSuffix(rest, "\n") {
			t.Errorf("fields are not on a line of their own\n  cmd:  %q\n  rest: %q", cmd, rest)
		}
	}
	// Vacuity floor: most rows carry an f-string with a field, so a function
	// that never appends anything must not pass this test by default.
	if withFields < 10 {
		t.Errorf("only %d of %d inputs carried appended fields; the prefix check is close to vacuous", withFields, len(inputs))
	}
}

// TestStripPythonStringLiterals_AppendedFields4621 pins the exact output for the
// two #4621 probes, and that a command with no f-string is left as before.
func TestStripPythonStringLiterals_AppendedFields4621(t *testing.T) {
	cases := []struct{ name, cmd, want string }{
		{
			"probe a: the << stays in the appended line",
			`python3 -c "x=f'{1<<2}'; eval(input())"`,
			`python3 -c "x=f; eval(input())"` + "\n 1<<2 \n",
		},
		{
			"probe c: the lone quote stays in the appended line",
			`python3 -c "x=f'''{\"'\"}'''; eval(input()); y='z'"`,
			`python3 -c "x=f; eval(input()); y="` + "\n" + ` \"'\" ` + "\n",
		},
		{
			"no f-string: legacy output unchanged",
			`python3 -c "x='eval(input())'; print(1)"`,
			`python3 -c "x=; print(1)"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripPythonStringLiterals(tc.cmd); got != tc.want {
				t.Errorf("stripPythonStringLiterals(%q)\n  got:  %q\n  want: %q", tc.cmd, got, tc.want)
			}
		})
	}
}
