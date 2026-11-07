package guardian

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

const (
	rlo4604 = "‮"
	zw4604  = "​"
)

// #4604 (byte-escape half): printf and echo write `\xe2\x80\xae` as the bytes
// of a bidi override, and the same escape for U+200B five times as five
// zero-width spaces. Each escaped spelling must decide like its raw control.
func TestGuardianEmittedInvisibleParity_4604(t *testing.T) {
	hexEsc := func(r string) string {
		out := ""
		for _, b := range []byte(r) {
			out += fmt.Sprintf(`\x%02x`, b)
		}
		return out
	}
	octEsc := func(r string) string {
		out := ""
		for _, b := range []byte(r) {
			out += fmt.Sprintf(`\%03o`, b)
		}
		return out
	}
	payloads := []struct{ name, raw, ch string }{
		{"bidi override", "see file MARKER" + rlo4604 + " txt", rlo4604},
		{"five zero-width", "M" + zw4604 + "A" + zw4604 + "R" + zw4604 + "K" + zw4604 + "E" + zw4604 + "R", zw4604},
	}
	encoders := map[string]func(string) string{"hex": hexEsc, "octal": octEsc}
	for _, target := range []string{"", " >> README.md", " >> notes.md"} {
		for _, p := range payloads {
			control := "printf '" + p.raw + `\n'` + target
			want, ok := findingByRule(guardianFindings(t, control), "guardian-unicode_steganography")
			if !ok {
				t.Fatalf("control %q did not fire; the rows test nothing", control)
			}
			for name, enc := range encoders {
				for _, form := range []string{`printf '%s\n'`, `echo '%s'`, `echo -e '%s'`} {
					// \ddd is printf's octal; echo -e needs the leading 0.
					if name == "octal" && strings.HasPrefix(form, "echo") {
						continue
					}
					body := strings.ReplaceAll(p.raw, p.ch, enc(p.ch))
					cmd := fmt.Sprintf(form, body) + target
					t.Run(p.name+"/"+name+"/"+form+"/"+strings.TrimSpace(target), func(t *testing.T) {
						got, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography")
						if !ok {
							t.Fatalf("unicode_steganography lost on %q", cmd)
						}
						if got.Decision != want.Decision {
							t.Errorf("decided %s, control %s", got.Decision, want.Decision)
						}
					})
				}
			}
		}
	}
}

func TestDecodeEmittedInvisible_4604(t *testing.T) {
	cases := []struct{ in, want string }{
		{`printf 'a\xe2\x80\xaeb'`, "printf 'a" + rlo4604 + "b'"},
		{`printf 'a\342\200\256b'`, "printf 'a" + rlo4604 + "b'"},
		{`echo -e 'a\0342\0200\0256b'`, "echo -e 'a" + rlo4604 + "b'"},
		{`printf 'a\xe2\x80\x8b\xe2\x80\x8bb'`, "printf 'a" + zw4604 + zw4604 + "b'"},
		{`printf 'a\x41b'`, ""},              // printable: never decoded
		{`printf 'a\xe2\x80\xa6b'`, ""},      // U+2026 ellipsis: visible
		{`printf 'a\xe2\x80b'`, ""},          // truncated sequence
		{`printf 'a\\xe2\\x80\\xaeb'`, ""},   // escaped backslashes
		{`printf '%s' 'a\xe2\x80\xaeb'`, ""}, // argument, not the format
		{`ls -la`, ""},
	}
	for _, tc := range cases {
		if got := shellparse.DecodeEmittedInvisible(tc.in); got != tc.want {
			t.Errorf("DecodeEmittedInvisible(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A visible escape run and a lone zero-width escape stay quiet.
func TestGuardianEmittedInvisibleAddsNoFalseSignals_4604(t *testing.T) {
	for _, cmd := range []string{
		`printf 'caf\xc3\xa9\n' >> notes.md`,
		`printf 'one\xe2\x80\x8bzero\n' >> notes.md`, // 1 < the threshold of 5
		`printf 'a\xe2\x80\xa6b\n' >> notes.md`,
	} {
		if _, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography"); ok {
			t.Errorf("unicode_steganography fired on %q", cmd)
		}
	}
}

// #4604 (\u half): bash 4.2+ and zsh printf write \uHHHH / \UHHHHHHHH as the
// UTF-8 of one character. Spelled with a built backslash, so no test source
// carries the character itself.
func TestGuardianEmittedUnicodeEscapeParity_4604(t *testing.T) {
	bs := "\\"
	cases := []struct{ name, esc, raw string }{
		{"u202e", bs + "u202e", rlo4604},
		{"U0000202E", bs + "U0000202E", rlo4604},
	}
	for _, c := range cases {
		control := "printf 'see file MARKER" + c.raw + " txt" + bs + "n' >> README.md"
		want, ok := findingByRule(guardianFindings(t, control), "guardian-unicode_steganography")
		if !ok {
			t.Fatalf("control did not fire; the rows test nothing")
		}
		for _, form := range []string{"printf 'see file MARKER%s txt" + bs + "n'", "echo 'see file MARKER%s txt'"} {
			cmd := fmt.Sprintf(form, c.esc) + " >> README.md"
			got, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography")
			if !ok || got.Decision != want.Decision {
				t.Errorf("%s: %q decided %v (found=%v), control %s", c.name, cmd, got.Decision, ok, want.Decision)
			}
		}
	}
	zw := bs + "u200b"
	five := "M" + zw + "A" + zw + "R" + zw + "K" + zw + "E" + zw + "R"
	if _, ok := findingByRule(guardianFindings(t, "printf '"+five+bs+"n' >> README.md"), "guardian-unicode_steganography"); !ok {
		t.Errorf("five escaped zero-width spaces did not fire")
	}
}

func TestDecodeEmittedInvisibleUnicodeEscapes_4604(t *testing.T) {
	bs := "\\"
	cases := []struct{ in, want string }{
		{"printf 'a" + bs + "u202eb'", "printf 'a" + rlo4604 + "b'"},
		{"printf 'a" + bs + "U0000200bb'", "printf 'a" + zw4604 + "b'"},
		{"printf 'a" + bs + "u0041b'", ""},      // printable
		{"printf 'a" + bs + "u2026b'", ""},      // ellipsis: visible
		{"printf 'a" + bs + "ub'", ""},          // no digit
		{"printf '%s' 'a" + bs + "u202eb'", ""}, // argument, not the format
		{"printf 'a" + bs + bs + "u202eb'", ""}, // escaped backslash
	}
	for _, tc := range cases {
		if got := shellparse.DecodeEmittedInvisible(tc.in); got != tc.want {
			t.Errorf("DecodeEmittedInvisible(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
