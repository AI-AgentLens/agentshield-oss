package pathnorm

import "testing"

// TestDecodeANSICEscapes_RecognizedForms covers every escape class bash's
// $'...' ANSI-C quoting recognizes — the encoding attackers use to hide an
// executable name or path from any rule keyed on the literal text (issue
// #3099).
func TestDecodeANSICEscapes_RecognizedForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"hex-rm", `\x72\x6d`, "rm"},
		// \cX is X & 0x1f in bash (verified on bash 5.3); \c? is DEL (#4543).
		{"ctrl-star-is-newline", `\c*`, "\n"},
		{"ctrl-paren-is-tab", `\c)`, "\t"},
		{"ctrl-digit", `\c1`, "\x11"},
		{"ctrl-hash", `\c#`, "\x03"},
		{"ctrl-question-is-del", `\c?`, "\x7f"},
		{"ctrl-bracket-is-esc", `\c[`, "\x1b"},
		{"ctrl-lower-j-is-newline", `\cj`, "\n"},
		{"hex-single-digit-boundary", `\x41`, "A"},
		{"octal-rm", `\162\155`, "rm"},
		{"octal-one-digit", `\7`, "\a"},
		{"unicode-4hex", "\\u0072\\u006d", "rm"},
		{"unicode-8hex", "\\U00000072\\U0000006d", "rm"},
		{"standard-escapes", `\n\t\r\a\b\f\v`, "\n\t\r\a\b\f\v"},
		{"escape-char", `\e`, "\x1b"},
		{"escape-char-upper", `\E`, "\x1b"},
		{"backslash-quote-dquote-question", `\\\'\"\?`, `\'"?`},
		{"control-char", `\cA`, "\x01"},
		{"control-char-lowercase-letter", `\ca`, "\x01"},
		{"mixed-literal-and-escape", `/etc/\x70\x61\x73\x73\x77\x64`, "/etc/passwd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, changed := DecodeANSICEscapes(tc.in)
			if !changed {
				t.Errorf("DecodeANSICEscapes(%q) reported no change, want decoded", tc.in)
			}
			if got != tc.want {
				t.Errorf("DecodeANSICEscapes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestDecodeANSICEscapes_UnrecognizedRetained — an unrecognized backslash
// sequence must keep BOTH the backslash and the character, never silently
// drop either (bash's own undefined behavior, and the conservative choice:
// this function can only ever reveal more text, never hide any).
func TestDecodeANSICEscapes_UnrecognizedRetained(t *testing.T) {
	cases := []string{`\d`, `\g`, `\z`, `\!`}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			got, _ := DecodeANSICEscapes(in)
			if got != in {
				t.Errorf("DecodeANSICEscapes(%q) = %q, want unchanged %q", in, got, in)
			}
		})
	}
}

// TestDecodeANSICEscapes_NoBackslashIsNoOp — the common case (plain text,
// terminal color codes with a single \x escape) is a cheap no-op.
func TestDecodeANSICEscapes_NoBackslashIsNoOp(t *testing.T) {
	cases := []string{"", "hello", "foo bar baz"}
	for _, in := range cases {
		got, changed := DecodeANSICEscapes(in)
		if changed || got != in {
			t.Errorf("DecodeANSICEscapes(%q) = (%q, %v), want (%q, false)", in, got, changed, in)
		}
	}
}

// TestDecodeANSICEscapes_TruncatedEscapeLeftLiteral — a trailing/invalid
// hex-digit-less \x, \u, \U, \c must not consume or corrupt anything; the
// backslash+letter is retained and the loop still advances.
func TestDecodeANSICEscapes_TruncatedEscapeLeftLiteral(t *testing.T) {
	cases := []struct{ in, want string }{
		{`\x`, `\x`},
		{`\xZZ`, `\xZZ`},
		{`\u`, `\u`},
		{`\uZZZZ`, `\uZZZZ`},
	}
	for _, tc := range cases {
		got, _ := DecodeANSICEscapes(tc.in)
		if got != tc.want {
			t.Errorf("DecodeANSICEscapes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestStripShellQuotes_ANSICDecoded is the pathnorm-level integration point:
// the structural channel (NormalizeExecName, matchArgGlob, normalizeTargetPath)
// all route through StripShellQuotes, so ANSI-C decoding must happen here for
// the executable-name and protected-path surfaces to see through it.
func TestStripShellQuotes_ANSICDecoded(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"single-span-two-escapes", `$'\x72\x6d'`, "rm"},
		{"split-across-two-fragments", `$'\x72'$'\x6d'`, "rm"},
		{"split-many-fragments-credentials", `$'\x63'$'\x72'$'\x65'$'\x64'$'\x65'$'\x6e'$'\x74'$'\x69'$'\x61'$'\x6c'$'\x73'`, "credentials"},
		{"mixed-literal-and-dollar-quoted", `$'\x7e'/.ssh/id_rsa`, "~/.ssh/id_rsa"},
		{"octal-split", `$'\162'$'\155'`, "rm"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripShellQuotes(tc.in); got != tc.want {
				t.Errorf("StripShellQuotes(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestStripShellQuotes_GenuineDynamicStillBailsAfterANSICAttempt — a token
// mixing statically-resolvable ANSI-C content with a REAL dynamic expansion
// ($VAR, $(...)) must still return the ORIGINAL input unchanged, matching
// StripShellQuotes' existing contract for dynamic content.
func TestStripShellQuotes_GenuineDynamicStillBailsAfterANSICAttempt(t *testing.T) {
	cases := []string{
		`$'\x2f'$HOME/id_rsa`,
		`$'\x2f'$(whoami)`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := StripShellQuotes(in); got != in {
				t.Errorf("StripShellQuotes(%q) = %q, want unchanged (genuine dynamic content present)", in, got)
			}
		})
	}
}

// TestANSICNULIndex_ByteZeroForms — every escape bash decodes to byte 0 is
// found, at the offset of its backslash (#4540). bash ends the $'...' body
// there; each spelling was checked against bash 3.2.57 and 5.3.9 with
// printf and od.
func TestANSICNULIndex_ByteZeroForms(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"octal-1", `\0`, 0},
		{"octal-2", `\00`, 0},
		{"octal-3", `\000`, 0},
		{"octal-400-wraps-to-0", `\400`, 0},
		{"hex-1", `\x0`, 0},
		{"hex-2", `\x00`, 0},
		{"unicode-1", `\u0`, 0},
		{"unicode-4", `\u0000`, 0},
		{"unicode-long-1", `\U0`, 0},
		{"unicode-long-8", `\U00000000`, 0},
		{"control-at", `\c@`, 0},
		{"control-backquote", "\\c`", 0},
		{"control-space", `\c `, 0},
		{"control-0x80", "\\c\x80", 0},
		{"control-0xa0", "\\c\xa0", 0},
		{"control-0xc0", "\\c\xc0", 0},
		{"control-0xe0", "\\c\xe0", 0},
		{"after-text", `rm\0zz`, 2},
		{"after-decoded-escape", `a\x41\0b`, 5},
		{"first-of-two", `a\0b\0`, 1},
		{"after-escaped-backslash", `\\\0`, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ANSICNULIndex(tc.in); got != tc.want {
				t.Errorf("ANSICNULIndex(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

// TestANSICNULIndex_NonZeroForms — escapes that decode to something other
// than byte 0 do not end the body, including the look-alikes: \x0b is ONE hex
// escape (0x0b), \401 keeps its low 8 bits (0x01), \c followed by a byte
// whose low five bits are not all zero is a control character, and \\0 is an
// escaped backslash followed by a literal 0.
func TestANSICNULIndex_NonZeroForms(t *testing.T) {
	cases := []string{
		"", "plain", `\x01`, `\x0b`, `\001`, `\401`, `\777`, `\u0001`, `\u000b`,
		`\U00000001`, `\cA`, `\c?`, `\cJ`, "\\c\xc3", `\\0`, `\x`, `\u`, `\c`,
		`\n\t\e`, `\d`,
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if got := ANSICNULIndex(in); got != -1 {
				t.Errorf("ANSICNULIndex(%q) = %d, want -1", in, got)
			}
		})
	}
}

// TestDecodeANSICEscapes_KeepsNULAsWritten pins the as-written decoder. It is
// deliberately NOT cut at byte 0: the as-written evaluation must stay
// byte-for-byte pre-#4540, because zsh keeps the NUL and runs the text after
// it in eval, trap, alias and source. The bash reading is a separate,
// stricter-only evaluation (policy.Engine.EvaluateANSICNUL).
func TestDecodeANSICEscapes_KeepsNULAsWritten(t *testing.T) {
	cases := []struct{ in, want string }{
		{`r\0m`, "r\x00m"},
		{`rm\000zz`, "rm\x00zz"},
		{`\400`, "\x00"},
		{`\x00`, "\x00"},
		{`\u0000`, "\x00"},
		{`\c@`, "\x00"},
		{"\\c`", "\x00"}, // X & 0x1f, not XOR 0x40 (#4543)
		{`\c `, "\x00"},
	}
	for _, tc := range cases {
		if got, _ := DecodeANSICEscapes(tc.in); got != tc.want {
			t.Errorf("DecodeANSICEscapes(%q) = %q, want %q (the as-written decoder must not change)", tc.in, got, tc.want)
		}
	}
}

// TestCutDollarQuotedSpansAtNUL is the text-only cut used when the parser
// rejects a command: each $'...' body ends at its first byte-0 escape, every
// other byte is kept, and "" means nothing was cut.
func TestCutDollarQuotedSpansAtNUL(t *testing.T) {
	cases := []struct{ in, want string }{
		{`ec$'\0'ho (`, `ec$''ho (`},
		{`$'echo\0zz' x << 'EOF'`, `$'echo' x << 'EOF'`},
		{`a$'\x41\c@b' $'\x42' c$'\400'd`, `a$'\x41' $'\x42' c$''d`},
		{`$'it\'s\0' x`, `$'it\'s' x`},
		{`ec$'\x41'ho (`, ""},
		{`echo $'unterminated\0`, ""},
		{`echo plain`, ""},
	}
	for _, tc := range cases {
		if got := CutDollarQuotedSpansAtNUL(tc.in); got != tc.want {
			t.Errorf("CutDollarQuotedSpansAtNUL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
