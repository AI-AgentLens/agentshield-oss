package archtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"
)

// Every shell parse goes through shellparse.ParseText (#4778).
//
// mvdan builds a `|`/`|&`/`||`/`&&` chain as a left-nested tree and its
// walkers recurse once per level, so a chain of about 320 000 operators
// overflows the Go stack, which kills the process. ParseText refuses a text
// past shellparse.MaxChainOperators (it panics with *ChainTooLongError, which
// every evaluation surface turns into its fail-safe decision). A text a
// reading DERIVES from the command (a nested shell's text after variable
// substitution, a decoded $'...', a fold's output) can be far longer than the
// command, so a check on the command alone is not enough: every parse has to
// make it. A tree that a walker recurses over comes from a parse, so with
// every parse bounded, every walk is too.
//
// A direct syntax.NewParser anywhere else is a parse that skips the bound.
// parseAllowlist holds the files that may call it, each with its reason; the
// only one is the helper itself.

const syntaxImportPath = "mvdan.cc/sh/v3/syntax"

var parseAllowlist = map[string]string{
	"internal/shellparse/chain_bound.go": "ParseText itself: it checks the bound, then parses",
}

// directParserCalls returns, for each file, the positions of every reference
// to the syntax package's NewParser, under whatever name the file imports the
// package as.
func directParserCalls(fset *token.FileSet, files map[string]*ast.File) map[string][]string {
	out := map[string][]string{}
	for rel, f := range files {
		local := map[string]bool{}
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil || path != syntaxImportPath {
				continue
			}
			name := "syntax"
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = true
		}
		if len(local) == 0 {
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "NewParser" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && local[id.Name] {
				out[rel] = append(out[rel], fset.Position(sel.Pos()).String())
			}
			return true
		})
	}
	return out
}

func TestShellParsesGoThroughParseText(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for _, gf := range moduleFiles(t, root, parser.SkipObjectResolution) {
		// moduleFiles parses with its own FileSet; re-parse here so the
		// positions this test reports are its own.
		f, err := parser.ParseFile(fset, root+"/"+gf.rel, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files[gf.rel] = f
	}
	calls := directParserCalls(fset, files)
	if len(calls["internal/shellparse/chain_bound.go"]) == 0 {
		t.Fatal("control: ParseText's own syntax.NewParser was not found, so the scan sees nothing")
	}
	var bad []string
	for rel, pos := range calls {
		if _, ok := parseAllowlist[rel]; ok {
			continue
		}
		bad = append(bad, pos...)
	}
	sort.Strings(bad)
	for _, p := range bad {
		t.Errorf("%s: syntax.NewParser outside shellparse.ParseText; parse through ParseText so the chain bound (#4778) applies, or add the file to parseAllowlist with the reason its text is already bounded", p)
	}
	for rel := range parseAllowlist {
		if _, ok := files[rel]; !ok {
			t.Errorf("parseAllowlist names %s, which does not exist", rel)
		}
	}
}

// TestShellParsesGoThroughParseText_SelfTest: the scan finds a direct call
// under the default and an aliased import name, and nothing in a file that
// only parses through the helper.
func TestShellParsesGoThroughParseText_SelfTest(t *testing.T) {
	srcs := map[string]string{
		"direct.go":  "package p\nimport \"mvdan.cc/sh/v3/syntax\"\nvar _ = syntax.NewParser()\n",
		"aliased.go": "package p\nimport sh \"mvdan.cc/sh/v3/syntax\"\nfunc f() { _ = sh.NewParser(sh.KeepComments(false)) }\n",
		"helper.go":  "package p\nimport (\n\"mvdan.cc/sh/v3/syntax\"\n\"github.com/AI-AgentLens/agentshield/internal/shellparse\"\n)\nfunc f() { _, _ = shellparse.ParseText(\"a\", syntax.KeepComments(false)) }\n",
		"other.go":   "package p\ntype q struct{}\nfunc (q) NewParser() {}\nvar syntax q\nvar _ = func() int { syntax.NewParser(); return 0 }\n",
	}
	fset := token.NewFileSet()
	files := map[string]*ast.File{}
	for name, src := range srcs {
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = f
	}
	got := directParserCalls(fset, files)
	for _, want := range []string{"direct.go", "aliased.go"} {
		if len(got[want]) != 1 {
			t.Errorf("%s: %d direct calls found, want 1", want, len(got[want]))
		}
	}
	for _, clean := range []string{"helper.go", "other.go"} {
		if len(got[clean]) != 0 {
			t.Errorf("%s: %v reported, want none", clean, got[clean])
		}
	}
}
