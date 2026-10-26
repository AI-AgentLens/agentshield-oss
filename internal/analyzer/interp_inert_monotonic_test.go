package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	"gopkg.in/yaml.v3"
)

// Sweep the actual accuracy corpus, every Go test's strings and constant
// concatenations, YAML fixtures/packs, and opaque fixture/probe files. Check
// standalone bodies in every historical language as well as extracted command
// bodies. The oracle is a frozen copy, not the production legacy AND helper.
func TestInterpInertMonotonicRepository(t *testing.T) {
	inputs := map[string]string{}
	add := func(s, origin string) {
		if s != "" {
			inputs[s] = origin
		}
	}
	for _, tc := range testdata.AllTestCases() {
		add(tc.Command, tc.ID)
	}
	err := filepath.WalkDir("../..", func(file string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".gocache" || d.Name() == ".gotmp" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := filepath.Ext(file)
		isGo := ext == ".go" && (strings.HasSuffix(file, "_test.go") || strings.Contains(file, "/testdata/"))
		isYAML := ext == ".yaml" || ext == ".yml"
		isFixture := (strings.Contains(file, "/testdata/") || strings.Contains(file, "/.review-4418/")) && (ext == ".sh" || ext == ".txt" || ext == ".json" || ext == ".jsonl")
		if !isGo && !isYAML && !isFixture {
			return nil
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		if isGo {
			f, err := parser.ParseFile(token.NewFileSet(), file, b, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if e, ok := n.(ast.Expr); ok {
					if s, ok := interpTestString(e); ok {
						add(s, file)
					}
				}
				return true
			})
		} else if isYAML {
			var doc yaml.Node
			if err := yaml.Unmarshal(b, &doc); err != nil {
				return err
			}
			var visit func(*yaml.Node)
			visit = func(n *yaml.Node) {
				if n.Kind == yaml.ScalarNode {
					add(n.Value, file)
				}
				for _, c := range n.Content {
					visit(c)
				}
			}
			visit(&doc)
		} else {
			add(string(b), file)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	bodies, accepted, commands := 0, 0, 0
	for input, origin := range inputs {
		for _, lang := range []string{"python", "python2", "python3", "node", "ruby", "perl"} {
			bodies++
			if interpHeredocExecFree(lang, input) {
				accepted++
				if !reviewLegacyExecFree(lang, input) {
					t.Fatalf("inertness widened: %s (%s): %q", origin, lang, input)
				}
			}
			assertInterpSpanSubset(t, origin, lang, input, input)
		}
		if !strings.Contains(input, "<<") {
			continue
		}
		commands++
		oldItems, _ := reviewLegacyInertLiterals(input)
		newItems, _ := InertInterpreterHeredocLiterals(input)
		if len(newItems) > 0 && len(oldItems) == 0 {
			t.Fatalf("new command exclusion: %s: %q", origin, input)
		}
		for _, sp := range shellparse.InterpreterHeredocLiteralSpans(input) {
			oldBody, body := input[sp.Start:sp.End], input[sp.Start:sp.BodyEnd]
			if interpHeredocExecFree(sp.Lang, body) && legacyInterpHeredocExecFree(sp.Lang, oldBody) && !reviewLegacyExecFree(sp.Lang, oldBody) {
				t.Fatalf("legacy range widened: %s", origin)
			}
			assertInterpSpanSubset(t, origin, sp.Lang, oldBody, body)
		}
		// The optional historical check must also preserve command purity when
		// Hdoc.End includes a quoted or call-shaped closing delimiter at EOF.
		if shellparse.CommandLineIsPure(input, interpHeredocExecFree, legacyInterpHeredocExecFree) &&
			!shellparse.CommandLineIsPure(input, func(string, string) bool { return true }, reviewLegacyExecFree) {
			t.Fatalf("command purity widened: %s: %q", origin, input)
		}
	}
	if accepted == 0 || commands == 0 {
		t.Fatal("vacuous corpus sweep")
	}
	t.Logf("%d unique inputs; %d body/language checks (%d inert); %d heredoc commands", len(inputs), bodies, accepted, commands)
}

func interpTestString(e ast.Expr) (string, bool) {
	return interpTestStringDepth(e, 0)
}

func interpTestStringDepth(e ast.Expr, depth int) (string, bool) {
	if depth > 100 {
		return "", false
	}
	switch e := e.(type) {
	case *ast.BasicLit:
		if e.Kind == token.STRING {
			s, err := strconv.Unquote(e.Value)
			return s, err == nil
		}
	case *ast.ParenExpr:
		return interpTestStringDepth(e.X, depth+1)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			a, ok := interpTestStringDepth(e.X, depth+1)
			b, ok2 := interpTestStringDepth(e.Y, depth+1)
			return a + b, ok && ok2
		}
	case *ast.Ident:
		// Resolve local constant/fixture bindings as well as literal-only
		// concatenations, e.g. the review's shared adb payload constant.
		if e.Obj != nil {
			switch decl := e.Obj.Decl.(type) {
			case *ast.ValueSpec:
				for i, name := range decl.Names {
					if name.Name == e.Name && i < len(decl.Values) {
						return interpTestStringDepth(decl.Values[i], depth+1)
					}
				}
			case *ast.AssignStmt:
				for i, lhs := range decl.Lhs {
					if name, ok := lhs.(*ast.Ident); ok && name.Name == e.Name && i < len(decl.Rhs) {
						return interpTestStringDepth(decl.Rhs[i], depth+1)
					}
				}
			}
		}
	}
	return "", false
}

func assertInterpSpanSubset(t *testing.T, origin, lang, oldBody, body string) {
	t.Helper()
	old := reviewLegacySpans(lang, oldBody)
	sort.Slice(old, func(i, j int) bool { return old[i][0] < old[j][0] })
	covered := make([]bool, len(oldBody))
	last := 0
	for _, s := range old {
		if s[0] < last {
			continue
		}
		for i := s[0]; i < s[1]; i++ {
			covered[i] = true
		}
		last = s[1]
	}
	_, fresh, _ := scanInertBody(lang, body)
	for _, s := range intersectInertLiteralSpans(lang, oldBody, body) {
		for i := s[0]; i < s[1]; i++ {
			inFresh := false
			for _, n := range fresh {
				if i >= n[0] && i < n[1] {
					inFresh = true
					break
				}
			}
			if !covered[i] || !inFresh {
				t.Fatalf("span widened: %s (%s) byte %d: %q", origin, lang, i, body)
			}
		}
	}
}
