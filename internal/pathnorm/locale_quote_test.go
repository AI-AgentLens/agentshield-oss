package pathnorm

import "testing"

// TestStripShellQuotes_LocaleQuoteDecoded closes the second surface of issue
// #3208: $"..." (bash locale-translated quoting) looks the enclosed text up
// in the current message catalog and falls back to the literal text when
// none matches — which, for the shell an AI agent drives, is always: no
// TEXTDOMAIN is set and no catalog is installed. So $"rm" runs exactly rm.
// Verified against bash 3.2. Before this fix StripShellQuotes bailed on ANY
// "$" in the token, leaving the executable spelled literally "$\"rm\"" and
// silencing every structural/regex rule keyed on "rm".
func TestStripShellQuotes_LocaleQuoteDecoded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"bare-locale-quote", `$"rm"`, `rm`},
		{"locale-quote-with-flags", `$"sudo"`, `sudo`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripShellQuotes(tc.in); got != tc.want {
				t.Errorf("StripShellQuotes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripShellQuotes_LocaleQuoteWithGenuineDynamicContentUntouched — a
// $"..." span that itself carries a nested dynamic expansion can't be
// resolved statically and must fall through unchanged, same as any other
// dynamic word.
func TestStripShellQuotes_LocaleQuoteWithGenuineDynamicContentUntouched(t *testing.T) {
	in := `$"$HOME"`
	if got := StripShellQuotes(in); got != in {
		t.Errorf("StripShellQuotes(%q) = %q, want unchanged", in, got)
	}
}

// TestFoldObfuscatingBackslashes_AlnumFolded pins the exec-position fold gate
// (issue #3208): a backslash escaping an ASCII alphanumeric character is
// obfuscation, not escaping, and always folds.
func TestFoldObfuscatingBackslashes_AlnumFolded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single-char-splice", `r\m`, `rm`},
		{"second-word-splice", `d\d`, `dd`},
		{"digit-splice", `ext\4`, `ext4`},
		{"multiple-splices", `r\m -\r\f /`, `rm -rf /`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := FoldObfuscatingBackslashes(tc.in)
			if !changed {
				t.Fatalf("FoldObfuscatingBackslashes(%q) reported no change", tc.in)
			}
			if got != tc.want {
				t.Errorf("FoldObfuscatingBackslashes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFoldObfuscatingBackslashes_PunctFolded pins the punctuation extension
// (issue #3209): a backslash escaping one of `- / . : , _ + @` carries no
// syntactic weight in shell grammar either, so it folds exactly like an
// alphanumeric escape.
func TestFoldObfuscatingBackslashes_PunctFolded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"long-flag-dash", `-\-force`, `--force`},
		{"path-slash", `/etc\/shadow`, `/etc/shadow`},
		{"dot", `foo\.bar`, `foo.bar`},
		{"colon", `a\:b`, `a:b`},
		{"comma", `a\,b`, `a,b`},
		{"underscore", `a\_b`, `a_b`},
		{"plus", `a\+b`, `a+b`},
		{"at", `user\@host`, `user@host`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := FoldObfuscatingBackslashes(tc.in)
			if !changed {
				t.Fatalf("FoldObfuscatingBackslashes(%q) reported no change", tc.in)
			}
			if got != tc.want {
				t.Errorf("FoldObfuscatingBackslashes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestFoldObfuscatingBackslashes_NonAlnumUntouched is the FP boundary: an
// escape of a character that IS shell-special (glob, separator, statement
// terminator, expansion marker, the escape character itself) changes what
// the command DOES if folded, so it must survive completely untouched. These
// are exactly the examples from the issue's "Proposed gate" section.
func TestFoldObfuscatingBackslashes_NonAlnumUntouched(t *testing.T) {
	cases := []string{
		`\*.go`,        // suppresses globbing
		`hello\ world`, // escapes a word-separator space
		`\;`,           // command/exec-terminator
		`foo\$bar`,     // prevents expansion
		`\\`,           // escaped backslash itself, nothing alnum follows
		`\~`,           // home-directory expansion marker
		`\=`,           // assignment marker
		`\^`,           // history-expansion marker (csh-family, still excluded)
		`\!`,           // history-expansion / negation marker
		`a\#b`,         // comment marker
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got, changed := FoldObfuscatingBackslashes(in)
			if changed || got != in {
				t.Errorf("FoldObfuscatingBackslashes(%q) = %q, changed=%v, want unchanged", in, got, changed)
			}
		})
	}
}

// TestFoldObfuscatingBackslashes_NoBackslashIsNoOp — the common case (no
// backslash at all) must short-circuit without allocating.
func TestFoldObfuscatingBackslashes_NoBackslashIsNoOp(t *testing.T) {
	for _, in := range []string{"", "rm", "-rf", "/etc/passwd"} {
		got, changed := FoldObfuscatingBackslashes(in)
		if changed || got != in {
			t.Errorf("FoldObfuscatingBackslashes(%q) = %q, changed=%v, want unchanged", in, got, changed)
		}
	}
}
