package analyzer

import (
	"slices"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// resolveDecoded must return exactly the value resolve returns, or the body a
// carrier walks would change under every existing reading.
func TestResolveDecoded_AgreesWithResolve4925(t *testing.T) {
	words := []string{
		`plain`,
		`'single'`,
		`"dq $(echo ` + encodedSSHKeyB64 + ` | base64 -d) tail"`,
		`pre$(echo ` + encodedSSHKeyB64 + ` | base64 -d)"$V"post`,
		`"$V/$(echo ` + encodedSSHKeyB64 + ` | base64 -d)"`,
		`$(date)`,
		`"$UNSET"`,
	}
	for _, src := range words {
		f, err := shellparse.ParseText("x "+src, syntax.Variant(syntax.LangBash))
		if err != nil {
			t.Fatalf("parse %q: %v", src, err)
		}
		w := f.Stmts[0].Cmd.(*syntax.CallExpr).Args[1]
		ev := newScopeEval(map[string]string{"V": "/v"})
		want, wantOK := ev.resolve(w)
		got, spans, gotOK := ev.resolveDecoded(w)
		if got != want || gotOK != wantOK {
			t.Errorf("%s: resolveDecoded = %q,%v; resolve = %q,%v", src, got, gotOK, want, wantOK)
		}
		for _, s := range spans {
			if s.start < 0 || s.end > len(got) || s.start >= s.end || got[s.start:s.end] != expectedSSHKey {
				t.Errorf("%s: span %v of %q is not the decoded text", src, s, got)
			}
		}
	}
}

func TestSourceArgDecoded_LocatesTheBody4925(t *testing.T) {
	span := []decodeSpan{{4, 8}}
	cases := []struct {
		name  string
		body  string
		words []string
		spans [][]decodeSpan
		want  []decodeSpan
	}{
		{"whole word", "cat XXXX", []string{"man", "-P", "cat XXXX", "ls"},
			[][]decodeSpan{nil, nil, span, nil}, span},
		{"flag=value tail", "cat XXXX", []string{"man", "--pager=cat XXXX", "ls"},
			[][]decodeSpan{nil, {{12, 16}}, nil}, span},
		{"joined operands", "cat XXXX", []string{"watch", "-n", "1", "cat", "XXXX"},
			[][]decodeSpan{nil, nil, nil, nil, {{0, 4}}}, span},
		{"not a word of argv", "XXXX", []string{"osascript", "-e", `do shell script "XXXX"`},
			[][]decodeSpan{nil, nil, {{17, 21}}}, nil},
		{"no decode in argv", "cat x", []string{"man", "-P", "cat x"},
			[][]decodeSpan{nil, nil, nil}, nil},
		// The decode is a page name, not part of the source.
		{"decode elsewhere", "less", []string{"man", "-P", "less", "XXXX"},
			[][]decodeSpan{nil, nil, nil, {{0, 4}}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sourceArgDecoded(tc.body, tc.words, tc.spans)
			if !slices.Equal(got, tc.want) {
				t.Errorf("sourceArgDecoded = %v, want %v", got, tc.want)
			}
		})
	}
}
