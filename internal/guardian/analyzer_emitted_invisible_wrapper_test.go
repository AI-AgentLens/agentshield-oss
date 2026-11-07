package guardian

import (
	"fmt"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The #4660 fix round: an escaped invisible character written by a printf or
// echo behind an exec wrapper. Bare, `printf '<five escaped U+200B>' >>
// src/auth.py` (TP-STEG-AI-003) BLOCKs; behind sudo, nohup or env it AUDITed,
// because the emitted-escape reading keyed on Args[0] and saw `sudo`. Each
// escaped spelling (hex and octal from #4659, \u from #4660) must decide like
// the raw control behind a wrapper wherever the program that runs there writes
// those bytes, and stay silent where it writes them as text (wrappedRows4660).
//
// Escapes are built from a backslash at run time, so no test source carries
// either the character or its escaped spelling.

const bs4660 = "\\"

// escapeInvisible4660 spells r in encoding enc for program prog: printf's
// octal is \ddd, echo's is \0ddd.
func escapeInvisible4660(enc, prog string, r string) string {
	var out strings.Builder
	switch enc {
	case "hex":
		for _, b := range []byte(r) {
			fmt.Fprintf(&out, "%sx%02x", bs4660, b)
		}
	case "octal":
		lead := ""
		if prog == "echo" {
			lead = "0"
		}
		for _, b := range []byte(r) {
			fmt.Fprintf(&out, "%s%s%03o", bs4660, lead, b)
		}
	case "u":
		fmt.Fprintf(&out, "%su%04x", bs4660, []rune(r)[0])
	}
	return out.String()
}

// fiveZeroWidth4660 is TP-STEG-AI-003's payload shape: five U+200B between
// visible letters, exactly the signal's threshold.
func fiveZeroWidth4660(z string) string {
	return "M" + z + "A" + z + "R" + z + "K" + z + "E" + z + "R"
}

// wrappedRows4660 is the wrapped matrix and what each row must decide. A row
// fires only where some real target writes the invisible bytes: class 4's
// identical-bytes condition (Gary, 2026-10-30). Measured on macOS that day:
//
//   - printf behind any wrapper: GNU printf writes all three spellings
//     (documented), BSD printf writes octal. Fires.
//   - echo without -e behind a wrapper that runs a program (sudo, env -i,
//     nohup): /bin/echo writes the escapes as text on every platform. SILENT,
//     per Gary's 2026-10-30 decision.
//   - echo -e behind those: GNU echo -e writes \x and \0ddd; it has no \u.
//   - `command echo`: /bin/sh's builtin writes \x and \0ddd without -e (zsh's
//     `command` runs /bin/echo); nothing writes \u.
//   - `builtin echo`, `noglob echo`: zsh's builtin writes all three.
type wrappedRow4660 struct {
	prefix, prog, enc string
	fire              bool
}

func wrappedRows4660() []wrappedRow4660 {
	var rows []wrappedRow4660
	add := func(prefixes []string, prog string, fire func(enc string) bool) {
		for _, p := range prefixes {
			for _, enc := range []string{"hex", "octal", "u"} {
				rows = append(rows, wrappedRow4660{p, prog, enc, fire(enc)})
			}
		}
	}
	always := func(string) bool { return true }
	never := func(string) bool { return false }
	noUnicode := func(enc string) bool { return enc != "u" }
	external := []string{"sudo", "env -i", "nohup"}
	add([]string{"sudo", "env -i", "nohup", "command", "builtin", "noglob"}, "printf", always)
	add(external, "echo", never) // Gary, 2026-10-30: /bin/echo decodes nothing without -e
	add(external, "echo -e", noUnicode)
	add([]string{"command"}, "echo", noUnicode)
	add([]string{"command"}, "echo -e", noUnicode)
	add([]string{"builtin", "noglob"}, "echo", always)
	return rows
}

func emittedCommand4660(wrapper, prog, body string) string {
	cmd := "printf '" + body + bs4660 + "n'"
	if prog != "printf" {
		cmd = prog + " '" + body + "'"
	}
	if wrapper != "" {
		cmd = wrapper + " " + cmd
	}
	return cmd + " >> src/auth.py"
}

func TestGuardianEmittedInvisibleBehindWrapper_4660(t *testing.T) {
	for _, r := range wrappedRows4660() {
		encProg := "echo"
		if r.prog == "printf" {
			encProg = "printf"
		}
		cmd := emittedCommand4660(r.prefix, r.prog, fiveZeroWidth4660(escapeInvisible4660(r.enc, encProg, zw4604)))
		t.Run(r.enc+"/"+r.prefix+"/"+r.prog, func(t *testing.T) {
			got, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography")
			if !r.fire {
				if ok {
					t.Errorf("fired on %q: no target writes these bytes there", cmd)
				}
				return
			}
			control := emittedCommand4660(r.prefix, r.prog, fiveZeroWidth4660(zw4604))
			want, cok := findingByRule(guardianFindings(t, control), "guardian-unicode_steganography")
			if !cok {
				t.Fatalf("raw control %q did not fire; the row tests nothing", control)
			}
			if !ok {
				t.Fatalf("unicode_steganography lost behind %q: %q", r.prefix, cmd)
			}
			if got.Decision != want.Decision {
				t.Errorf("%q decided %s, raw control %s", cmd, got.Decision, want.Decision)
			}
		})
	}
}

// The bidi override fires on one character, so it is the sharpest probe of a
// wrapper whose option grammar must be walked: a value-taking flag, an
// assignment, nesting, and a path-qualified wrapper.
func TestGuardianEmittedInvisibleBehindWrapperOptions_4660(t *testing.T) {
	for _, wrapper := range []string{"sudo -u root", "env FOO=1", "nice -n 5", "sudo nohup", "/usr/bin/env", "timeout -s KILL 5"} {
		for _, enc := range []string{"hex", "octal", "u"} {
			cmd := wrapper + " printf 'see file MARKER" + escapeInvisible4660(enc, "printf", rlo4604) + " txt" + bs4660 + "n' >> README.md"
			if _, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography"); !ok {
				t.Errorf("unicode_steganography lost on %q", cmd)
			}
		}
	}
}

// What the wrapped reading must leave quiet: ordinary escapes, a single
// zero-width character (below the threshold of 5), an escape in a printf
// ARGUMENT (printf decodes only its format), an escaped backslash, a wrapper
// whose target is not printf/echo at all, and printf/echo as the ARGUMENT of a
// program that is not a wrapper (only the ExecWrappers table is looked
// through).
func TestGuardianEmittedInvisibleBehindWrapperStaysQuiet_4660(t *testing.T) {
	five := func(enc string) string { return fiveZeroWidth4660(escapeInvisible4660(enc, "printf", zw4604)) }
	quiet := []string{
		"sudo printf 'a" + bs4660 + "tb" + bs4660 + "x41c" + bs4660 + "n' >> notes.md",
		"env -i printf 'col1" + bs4660 + "tcol2" + bs4660 + "101" + bs4660 + "n' >> notes.md",
		"nohup echo 'tab" + bs4660 + "there' >> notes.md",
		"command printf 'caf" + bs4660 + "xc3" + bs4660 + "xa9" + bs4660 + "n' >> notes.md",
		"sudo printf 'a" + bs4660 + "xe2" + bs4660 + "x80" + bs4660 + "xa6b" + bs4660 + "n' >> notes.md", // U+2026: visible
	}
	for _, enc := range []string{"hex", "octal", "u"} {
		one := "one" + escapeInvisible4660(enc, "printf", zw4604) + "zero"
		quiet = append(quiet,
			"sudo printf '"+one+bs4660+"n' >> notes.md",                                          // 1 < 5
			"sudo printf '%s"+bs4660+"n' '"+five(enc)+"' >> notes.md",                            // argument, not the format
			"env -i printf -- '%s"+bs4660+"n' '"+five(enc)+"' >> notes.md",                       // after --, still an argument
			"sudo cat '"+five(enc)+"' >> notes.md",                                               // the target is not printf/echo
			"sudo printf '"+strings.ReplaceAll(five(enc), bs4660, bs4660+bs4660)+"' >> notes.md", // escaped backslashes
			"grep echo '"+five(enc)+"' notes.md",                                                 // echo is grep's pattern
			"git log --grep printf '"+five(enc)+"'",                                              // not a wrapper either
		)
	}
	for _, cmd := range quiet {
		if _, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography"); ok {
			t.Errorf("unicode_steganography fired on %q", cmd)
		}
	}
}

func TestDecodeEmittedInvisibleWrapped_4660(t *testing.T) {
	u := bs4660 + "u202e"
	hex := bs4660 + "xe2" + bs4660 + "x80" + bs4660 + "xae"
	cases := []struct{ name, in, want string }{
		{"sudo", "sudo printf 'a" + u + "b'", "sudo printf 'a" + rlo4604 + "b'"},
		{"env -i, echo -e", "env -i echo -e 'a" + hex + "b'", "env -i echo -e 'a" + rlo4604 + "b'"},
		{"command echo, hex", "command echo 'a" + hex + "b'", "command echo 'a" + rlo4604 + "b'"},
		{"builtin echo, u-escape", "builtin echo 'a" + u + "b'", "builtin echo 'a" + rlo4604 + "b'"},
		{"builtin printf, u-escape", "builtin printf 'a" + u + "b'", "builtin printf 'a" + rlo4604 + "b'"},
		{"noglob echo, u-escape", "noglob echo 'a" + u + "b'", "noglob echo 'a" + rlo4604 + "b'"},
		{"nested", "sudo nohup printf 'a" + hex + "b'", "sudo nohup printf 'a" + rlo4604 + "b'"},
		{"value flag", "sudo -u root printf 'a" + u + "b'", "sudo -u root printf 'a" + rlo4604 + "b'"},
		{"in a pipeline", "ls | sudo tee x && nohup printf 'a" + u + "b'", "ls | sudo tee x && nohup printf 'a" + rlo4604 + "b'"},
		// A bare printf beside a wrapped one: both decoded, the bare one
		// exactly as DecodeEmittedInvisible decodes it.
		{"bare beside wrapped", "printf 'a" + u + "b'; sudo printf 'c" + u + "d'", "printf 'a" + rlo4604 + "b'; sudo printf 'c" + rlo4604 + "d'"},

		// "" whenever no WRAPPED call adds a decoded run, so a caller never
		// appends a copy of the first reading.
		{"bare only", "printf 'a" + u + "b'", ""},
		{"no wrapper target", "sudo -i", ""},
		{"wrapped, not printf/echo", "sudo cat 'a" + u + "b'", ""},
		{"wrapped printable", "sudo printf 'a" + bs4660 + "x41b'", ""},
		{"wrapped argument", "sudo printf '%s' 'a" + u + "b'", ""},
		{"wrapped escaped backslash", "sudo printf 'a" + bs4660 + u + "b'", ""},
		{"wrapper is a printf ARGUMENT", "printf 'sudo' 'a" + u + "b'", ""},
		{"printf is the ARGUMENT of a non-wrapper", "grep printf 'a" + u + "b'", ""},
		{"relative ./env is a project script", "./env printf 'a" + u + "b'", ""},
		{"no backslash", "sudo printf hello", ""},
		// Gary, 2026-10-30: echo behind a wrapper that runs a program is
		// /bin/echo, which decodes nothing without -e, and no echo but zsh's
		// builtin decodes the u-escape.
		{"env -i echo, no -e", "env -i echo 'a" + hex + "b'", ""},
		{"sudo echo, no -e", "sudo echo 'a" + u + "b'", ""},
		{"sudo echo -e, u-escape", "sudo echo -e 'a" + u + "b'", ""},
		{"command echo, u-escape", "command echo 'a" + u + "b'", ""},
		{"command sudo echo: the program wins", "command sudo echo 'a" + hex + "b'", ""},
		{"/usr/bin/command is a program", "/usr/bin/command echo 'a" + hex + "b'", ""},
	}
	for _, tc := range cases {
		if got := shellparse.DecodeEmittedInvisibleWrapped(tc.in); got != tc.want {
			t.Errorf("%s: DecodeEmittedInvisibleWrapped(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
	// The first reading is untouched by the look-through: it still skips the
	// wrapped call.
	if got := shellparse.DecodeEmittedInvisible("sudo printf 'a" + u + "b'"); got != "" {
		t.Errorf("DecodeEmittedInvisible changed: decoded a wrapped call to %q", got)
	}
}

// The same reading on the guardian's other candidate forms: `${IFS}` for the
// space, an unset-parameter splice in the program name, and the command as a
// `bash <<EOF` body each write the same bytes as the bare printf, and only
// the normalized or inline-code form shows the printf. TestIFSSeparatorParity,
// TestUnsetParamExpParity and TestHeredocShellExecParity each counted
// TP-STEG-AI-003 as one more leak before the decoders read every form.
func TestGuardianEmittedInvisibleOnEveryForm_4660(t *testing.T) {
	for _, enc := range []string{"hex", "octal", "u"} {
		body := fiveZeroWidth4660(escapeInvisible4660(enc, "printf", zw4604))
		for name, cmd := range map[string]string{
			"ifs":            "printf${IFS}'" + body + "' >> src/auth.py",
			"unset splice":   "p${zqx}rintf '" + body + "' >> src/auth.py",
			"heredoc":        "bash <<EOF\nprintf '" + body + "' >> src/auth.py\nEOF",
			"heredoc+sudo":   "bash <<EOF\nsudo printf '" + body + "' >> src/auth.py\nEOF",
			"ifs+wrapper":    "nohup${IFS}printf '" + body + "' >> src/auth.py",
			"splice+wrapper": "s${zqx}udo printf '" + body + "' >> src/auth.py",
		} {
			if _, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography"); !ok {
				t.Errorf("%s/%s: unicode_steganography lost on %q", enc, name, cmd)
			}
		}
	}
	// The same narrowing on those forms: an external wrapper before echo
	// without -e writes the escapes as text (Gary, 2026-10-30).
	for _, enc := range []string{"hex", "octal", "u"} {
		body := fiveZeroWidth4660(escapeInvisible4660(enc, "echo", zw4604))
		for name, cmd := range map[string]string{
			"ifs+wrapper echo":    "nohup${IFS}echo '" + body + "' >> src/auth.py",
			"splice+wrapper echo": "s${zqx}udo echo '" + body + "' >> src/auth.py",
			"heredoc+sudo echo":   "bash <<EOF\nsudo echo '" + body + "' >> src/auth.py\nEOF",
		} {
			if _, ok := findingByRule(guardianFindings(t, cmd), "guardian-unicode_steganography"); ok {
				t.Errorf("%s/%s: unicode_steganography fired on %q", enc, name, cmd)
			}
		}
	}
	// A python heredoc is not shell source: its printf text is not read.
	quiet := "python3 <<EOF\nprintf '" + fiveZeroWidth4660(escapeInvisible4660("u", "printf", zw4604)) + "'\nEOF"
	if _, ok := findingByRule(guardianFindings(t, quiet), "guardian-unicode_steganography"); ok {
		t.Errorf("unicode_steganography fired on a python heredoc body: %q", quiet)
	}
}
