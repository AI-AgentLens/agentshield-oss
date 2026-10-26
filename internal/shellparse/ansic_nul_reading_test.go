package shellparse

import "testing"

// TestANSICNULReading cuts each $'...' body at the first escape bash decodes
// to byte 0 (#4540) and leaves every other byte as written. The verbs are
// benign on purpose: the rewrite does not depend on what the word means.
func TestANSICNULReading(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"splice", `ec$'\0'ho hi`, `ec$''ho hi`},
		{"truncate", `$'echo\0zz' hi`, `$'echo' hi`},
		{"nul-last", `$'echo\0' hi`, `$'echo' hi`},
		{"octal-400", `ec$'\400'ho hi`, `ec$''ho hi`},
		{"hex-1", `ec$'\x0'ho hi`, `ec$''ho hi`},
		{"unicode-1", `ec$'\u0'ho hi`, `ec$''ho hi`},
		{"control-at", `ec$'\c@'ho hi`, `ec$''ho hi`},
		{"control-backquote", "ec$'\\c`'ho hi", `ec$''ho hi`},
		{"keeps-prefix-escapes", `$'\x65cho\0zz' hi`, `$'\x65cho' hi`},
		{"several-spans", `a$'\0'b $'c\x00d' $'\x41' $'e\c@f'`, `a$''b $'c' $'\x41' $'e'`},
		{"in-command-substitution", `x=$(ec$'\0'ho hi)`, `x=$(ec$''ho hi)`},
		{"in-pipeline-and-list", `ec$'\0'ho a | ca$'\0't && ls`, `ec$''ho a | ca$''t && ls`},
		{"in-redirect-target", `echo hi > /tmp/a$'\0'b`, `echo hi > /tmp/a$''b`},
		{"in-assignment", `v=$'a\0b' env`, `v=$'a' env`},
		// Text an executor re-parses is cut by text (#4542).
		{"heredoc-body", "bash <<EOF\nec$'\\0'ho hi\nEOF", "bash <<EOF\nec$''ho hi\nEOF"},
		{"heredoc-body-quoted-delim", "sh <<'EOF'\n$'echo\\0zz' hi\nEOF", "sh <<'EOF'\n$'echo' hi\nEOF"},
		{"bash-c-double-quoted", `bash -c "ec$'\0'ho hi"`, `bash -c "ec$''ho hi"`},
		{"eval-double-quoted", `eval "ec$'\0'ho hi"`, `eval "ec$''ho hi"`},
		{"sudo-env-bash-c", `sudo env bash -c "ec$'\0'ho hi"`, `sudo env bash -c "ec$''ho hi"`},
		// The parser rejects these, so the text fallback cuts them.
		{"does-not-parse", `ec$'\0'ho (`, `ec$''ho (`},
		{"unterminated-heredoc", `t$'\0'ee out.txt << 'EOF'`, `t$''ee out.txt << 'EOF'`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ANSICNULReading(tc.in); got != tc.want {
				t.Errorf("ANSICNULReading(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestANSICNULReading_NoCut returns "" — no second reading — when there is no
// byte-0 escape in a $'...' span the parser sees.
func TestANSICNULReading_NoCut(t *testing.T) {
	cases := []struct{ name, in string }{
		{"no-dollar-quote", `echo hi`},
		{"no-backslash", `echo $'hi'`},
		{"non-zero-escapes", `printf $'a\x41\n\t\001'`},
		{"hex-0b-is-one-escape", `ec$'\x0b'ho hi`},
		{"escaped-backslash-then-0", `echo $'\\0'`},
		{"plain-single-quotes", `echo '\0' '$'\0`},
		{"inside-double-quotes", `echo "$'\0'"`},
		{"quoted-arg-of-non-carrier", `echo 'ec$'\0'ho hi'`},
		{"comment", `echo hi # $'\0'`},
		{"does-not-parse-no-nul", `ec$'\x41'ho (`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ANSICNULReading(tc.in); got != "" {
				t.Errorf("ANSICNULReading(%q) = %q, want \"\" (no cut)", tc.in, got)
			}
		})
	}
}

// TestMayHaveNULEscape: the pre-parse gate passes every byte-0 spelling and
// rejects the common non-zero ones, so it can only skip parses, never cuts.
func TestMayHaveNULEscape(t *testing.T) {
	for _, in := range []string{`\0`, `a\00`, `\400`, `\x0`, `\x00`, `\u0`, `\U0`, `\c@`, "\\c`", `\\\0`, `\n\0`} {
		if !mayHaveNULEscape(in) {
			t.Errorf("mayHaveNULEscape(%q) = false; the gate would skip a byte-0 escape", in)
		}
	}
	for _, in := range []string{``, `plain`, `\n`, `\t\r`, `\e[0m`, `\\`, `trailing\`} {
		if mayHaveNULEscape(in) {
			t.Errorf("mayHaveNULEscape(%q) = true; want false", in)
		}
	}
}
