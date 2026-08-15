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
