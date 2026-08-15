package shellparse

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// TestDeclClauseAssigns is the per-keyword breadth surface for the declaration
// blind spot — one parse per case, so the corpus sweep in the analyzer package
// can stay at a single position.
func TestDeclClauseAssigns(t *testing.T) {
	cases := []struct {
		src  string
		want map[string]string // name -> literal value; nil means "declined"
	}{
		{"export x=rm", map[string]string{"x": "rm"}},
		{"declare x=rm", map[string]string{"x": "rm"}},
		{"local x=rm", map[string]string{"x": "rm"}},
		{"readonly x=rm", map[string]string{"x": "rm"}},
		{"typeset x=rm", map[string]string{"x": "rm"}},
		{"declare -x x=rm", map[string]string{"x": "rm"}},
		{"export -f x=rm", map[string]string{"x": "rm"}},
		{"export a=rm b=/etc", map[string]string{"a": "rm", "b": "/etc"}},

		// A bare re-export binds nothing — must not be recorded as x="".
		{"export x", map[string]string{}},

		// Semantics-changing flags: the assigned TEXT is not the stored value.
		{"declare -n ref=cmd", nil},
		{"local -n ref=cmd", nil},
		{"declare -i n=3+4", nil},
		{"declare -xn ref=cmd", nil}, // bundled spelling
		{"typeset -i n=1+1", nil},
	}

	for _, tc := range cases {
		t.Run(tc.src, func(t *testing.T) {
			file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).
				Parse(strings.NewReader(tc.src), "")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			var decl *syntax.DeclClause
			syntax.Walk(file, func(n syntax.Node) bool {
				if d, ok := n.(*syntax.DeclClause); ok && decl == nil {
					decl = d
				}
				return true
			})
			if decl == nil {
				t.Fatalf("%q did not parse as a DeclClause", tc.src)
			}

			got := DeclClauseAssigns(decl)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("%q: expected the clause to be declined, got %d assigns", tc.src, len(got))
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("%q: got %d assigns, want %d", tc.src, len(got), len(tc.want))
			}
			for _, a := range got {
				val, ok := literalWordValue(a.Value)
				if !ok {
					t.Fatalf("%q: %s has no literal value", tc.src, a.Name.Value)
				}
				if want := tc.want[a.Name.Value]; val != want {
					t.Errorf("%q: %s = %q, want %q", tc.src, a.Name.Value, val, want)
				}
			}
		})
	}
}

// TestDeclClauseResolvesExecutable pins the end-to-end shape: a declaration
// keyword in front of the binding must not hide the executable name, on its own
// or composed with the #3244 operator evaluation.
func TestDeclClauseResolvesExecutable(t *testing.T) {
	cases := []struct {
		command string
		want    string
	}{
		{"x=rm;$x -rf /", "rm"},
		{"export x=rm;$x -rf /", "rm"},
		{"declare x=rm;$x -rf /", "rm"},
		{"local x=rm;$x -rf /", "rm"},
		{"readonly x=rm;$x -rf /", "rm"},
		{"typeset x=rm;$x -rf /", "rm"},
		{"declare -x x=rm;$x -rf /", "rm"},
		{"export x=Zrm;${x#Z} -rf /", "rm"},
	}
	for _, tc := range cases {
		t.Run(tc.command, func(t *testing.T) {
			segs := AllSegments(Parse(tc.command, 5))
			var last string
			for _, s := range segs {
				last = s.Executable
			}
			if last != tc.want {
				t.Errorf("Parse(%q) resolved executable %q, want %q", tc.command, last, tc.want)
			}
		})
	}
}

// TestDeclClauseNamerefNotResolved is the negative control. `declare -n ref=cmd`
// makes $ref expand to the value of the variable NAMED cmd — folding "cmd" in
// as if it were a plain scalar would resolve the executable to the wrong thing.
func TestDeclClauseNamerefNotResolved(t *testing.T) {
	for _, cmd := range []string{
		"declare -n ref=rm;$ref -rf /",
		"local -n ref=rm;$ref -rf /",
	} {
		for _, s := range AllSegments(Parse(cmd, 5)) {
			if s.Executable == "rm" {
				t.Errorf("Parse(%q) folded a nameref as a scalar", cmd)
			}
		}
	}
}
