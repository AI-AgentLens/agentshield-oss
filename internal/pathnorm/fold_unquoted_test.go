package pathnorm

import "testing"

// TestFoldObfuscatingBackslashesUnquoted is the guard on the one thing that
// separates this from FoldObfuscatingBackslashes: quote state.
//
// It is only ever called on input the shell parser has already REJECTED
// (shellparse.DequoteCommand's #3211 retry), so there is no AST to ask and the
// quote state has to be recovered lexically. A backslash before an
// alphanumeric is literal inside BOTH quote forms, so folding one would invent
// a command bash would never run — and that reconstruction is handed to
// command_regex as an extra match candidate, i.e. it can manufacture a BLOCK.
func TestFoldObfuscatingBackslashesUnquoted(t *testing.T) {
	for name, tc := range map[string]struct {
		in          string
		want        string
		wantChanged bool
	}{
		// The shape the retry exists for: an escaped character in an
		// assignment NAME, which mvdan/sh rejects and bash accepts.
		"assignment name": {`export FO\O=1`, `export FOO=1`, true},
		"declare name":    {`declare -x MY\VAR=/tmp/x`, `declare -x MYVAR=/tmp/x`, true},

		// Single quotes: nothing is special, not even a backslash.
		"single quoted stays":        {`printf 'a\nb'`, `printf 'a\nb'`, false},
		"single quoted with outside": {`printf 'a\nb' && r\m x`, `printf 'a\nb' && rm x`, true},

		// Double quotes: backslash is special only before $ ` " \ and newline,
		// so \n is literal there too.
		"double quoted stays":  {`printf "a\nb"`, `printf "a\nb"`, false},
		"double escaped quote": {`echo "he said \"hi\"" && r\m x`, `echo "he said \"hi\"" && rm x`, true},

		// An escaped quote OUTSIDE quotes must not flip the state. If it did,
		// everything after it would be treated as quoted and left unfolded —
		// silently reopening the bypass rather than mangling anything, which
		// is the harder failure to notice.
		"escaped quote does not open a span": {`echo \'x\' && r\m y`, `echo \'x\' && rm y`, true},
		"escaped dquote does not open":       {`echo \"x\" && r\m y`, `echo \"x\" && rm y`, true},

		// Nothing to do.
		"no backslash":      {`rm -rf /`, `rm -rf /`, false},
		"trailing lone":     {`trailing\`, `trailing\`, false},
		"unfoldable target": {`a\$b`, `a\$b`, false},

		// Unterminated quote — the exact reason the parser failed. The scan
		// must not run off the end or panic; leaving the tail unfolded is the
		// safe answer.
		"unterminated single": {`echo 'a\nb`, `echo 'a\nb`, false},
		"unterminated double": {`echo "a\nb`, `echo "a\nb`, false},
		"empty":               {``, ``, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, changed := FoldObfuscatingBackslashesUnquoted(tc.in)
			if got != tc.want || changed != tc.wantChanged {
				t.Errorf("in %q\n  got  %q (changed=%v)\n  want %q (changed=%v)",
					tc.in, got, changed, tc.want, tc.wantChanged)
			}
		})
	}
}

// TestFoldUnquotedIsNeverBroaderThanNaive pins the relationship between the two
// folds. The quote-aware one must only ever fold a SUBSET of what the naive one
// does — if it ever folded something the naive version left alone, that would
// be a bug in the scanner rather than a tightening.
func TestFoldUnquotedIsNeverBroaderThanNaive(t *testing.T) {
	for _, in := range []string{
		`export FO\O=1`,
		`printf 'a\nb'`,
		`printf "a\nb"`,
		`cat 'lit\eral' && r\m x`,
		`echo \'q\' && r\m y`,
		`a\b'c\d"e\f`,
		`\\\a`,
		`'\'`,
	} {
		strict, _ := FoldObfuscatingBackslashesUnquoted(in)
		naive, _ := FoldObfuscatingBackslashes(in)
		if len(strict) < len(naive) {
			t.Errorf("quote-aware fold removed MORE than the naive one for %q:\n  strict=%q\n  naive =%q",
				in, strict, naive)
		}
	}
}
