package shellparse

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestLiteralExecName pins the contract the builtin recognisers rely on: the
// name comes back the way the shell resolves it, not the way it was spelled.
func TestLiteralExecName(t *testing.T) {
	tests := []struct {
		src    string
		want   string
		wantOK bool
	}{
		{`read zc`, "read", true},
		{`r\ead zc`, "read", true},
		{`"read" zc`, "read", true},
		{`'read' zc`, "read", true},
		{`re""ad zc`, "read", true},
		{`m\apfile -t za`, "mapfile", true},
		// Must NOT resolve to the builtin: inside quotes a backslash before an
		// ordinary character is LITERAL, and an escaped backslash is a
		// backslash. bash reports each of these as "command not found". The
		// first cut of this helper flattened the word and stripped every
		// backslash, so all four compared equal to the builtin — and on the
		// shift recogniser that REMOVED a BLOCK (#3874 adversarial review).
		{`'s\hift' 3`, `s\hift`, true},
		{`"s\hift" 3`, `s\hift`, true},
		{`\\shift 3`, `\shift`, true},
		{`shift\\ 3`, `shift\`, true},
		{`'\read' zc`, `\read`, true},
		// Builtin names are case-sensitive.
		{`SHIFT 3`, "SHIFT", true},
		// Inside double quotes a backslash IS removed before $ ` " and \.
		{`"re\"ad" zc`, `re"ad`, true},
		{`"read\\" zc`, `read\`, true},
		// ANSI-C quoting with an escape to decode: refuse rather than guess.
		{`$'re\x61d' zc`, "", false},
		{`$'read' zc`, "read", true},
		// A dynamic word has no static name; the recogniser must bail, not
		// guess.
		{`$cmd zc`, "", false},
		{`$(echo read) zc`, "", false},
	}
	for _, tc := range tests {
		t.Run(tc.src, func(t *testing.T) {
			f, err := syntax.NewParser().Parse(strings.NewReader(tc.src), "")
			if err != nil || len(f.Stmts) != 1 {
				t.Fatalf("parse %q: %v", tc.src, err)
			}
			call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
			if !ok {
				t.Fatalf("%q is not a CallExpr", tc.src)
			}
			got, gotOK := literalExecName(call)
			if got != tc.want || gotOK != tc.wantOK {
				t.Errorf("literalExecName(%q) = (%q, %v), want (%q, %v)", tc.src, got, gotOK, tc.want, tc.wantOK)
			}
		})
	}
	if got, ok := literalExecName(nil); ok || got != "" {
		t.Errorf("literalExecName(nil) = (%q, %v), want (\"\", false)", got, ok)
	}
	if got, ok := literalExecName(&syntax.CallExpr{}); ok || got != "" {
		t.Errorf("literalExecName(no args) = (%q, %v), want (\"\", false)", got, ok)
	}
}

// TestBuiltinBindingSurvivesExecNameSplice covers #3848 class A: a builtin
// that binds a variable (read, mapfile, readarray, set --) or invalidates one
// (shift) is the same builtin when its name is spelled with a no-op backslash
// or empty quotes. Before the fix each recogniser compared the raw literal, so
// the binding was dropped and the resolved command never reached a rule.
func TestBuiltinBindingSurvivesExecNameSplice(t *testing.T) {
	tests := []struct {
		name string
		cmd  string
		want string
	}{
		{
			name: "backslash-spliced read scalar",
			cmd:  `r\ead zc <<< "rm -rf /"; $zc`,
			want: `r\ead zc <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "empty-quote-spliced read array",
			cmd:  `re""ad -ra parts <<< "rm -rf /"; "${parts[@]}"`,
			want: `re""ad -ra parts <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "backslash-spliced mapfile",
			cmd:  `m\apfile -t za <<< "rm -rf /"; ${za[0]}`,
			want: `m\apfile -t za <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "backslash-spliced readarray",
			cmd:  `r\eadarray za <<< "rm -rf /"; ${za[0]}`,
			want: `r\eadarray za <<< "rm -rf /"; rm -rf /`,
		},
		{
			name: "backslash-spliced read from a heredoc",
			cmd:  "r\\ead zc <<'EOF'\nrm -rf /\nEOF\n$zc",
			want: "r\\ead zc <<'EOF'\nrm -rf /\nEOF\nrm -rf /",
		},
		{
			name: "backslash-spliced set --",
			cmd:  `s\et -- rm -rf /; "$@"`,
			want: `s\et -- rm -rf /; rm -rf /`,
		},
		{
			// The false-BLOCK direction. An unrecognised `s\hift` left the
			// positional binding live, so "$@" resolved to words bash had
			// already shifted away.
			name: "backslash-spliced shift still bails positional resolution",
			cmd:  `set -- rm ls; s\hift; $1 -rf /`,
			want: "",
		},
		{
			// Quoted backslash: NOT shift, so the positional list survives and
			// "$@" still resolves. The regression the review of #3874 caught.
			name: "single-quoted s\\hift is not shift",
			cmd:  `set -- rm ls; 's\hift'; $1 -rf /`,
			want: `set -- rm ls; 's\hift'; rm -rf /`,
		},
		{
			name: "escaped-backslash shift is not shift",
			cmd:  `set -- rm ls; \\shift; $1 -rf /`,
			want: `set -- rm ls; \\shift; rm -rf /`,
		},
		{
			name: "uppercase SHIFT is not shift",
			cmd:  `set -- rm ls; SHIFT; $1 -rf /`,
			want: `set -- rm ls; SHIFT; rm -rf /`,
		},
		{
			name: "single-quoted backslash read binds nothing",
			cmd:  `'\read' zc <<< "rm -rf /"; $zc`,
			want: "",
		},
		{
			name: "benign value resolves to the benign command",
			cmd:  `r\ead zc <<< "ls -la /tmp"; $zc`,
			want: `r\ead zc <<< "ls -la /tmp"; ls -la /tmp`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResolveIndirectExecutables(tc.cmd); got != tc.want {
				t.Errorf("ResolveIndirectExecutables(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}
