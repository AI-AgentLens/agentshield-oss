package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestRedactedFormsCoverMatcherTransforms holds redactedForms (position.go) to
// the renderings RegexAnalyzer.Analyze matches against. A position exclusion
// holds only if no redacted rendering still matches, so a rendering the
// matcher has and subtraction lacks is a needle-shaped bypass: the real
// payload matches only there, the needle is the one match subtraction can
// see, and the exclusion excuses the whole command. #4400 hit that three
// times while redactedForms was a hand-kept subset (a missing pass, missing
// renderings, then the order of two passes), so both now call one builder.
//
// The test pins that structure rather than a list of names:
//   - Analyze and redactedForms both call buildWholeCommandForms;
//   - every other shellparse call left in Analyze is also made by
//     redactedForms (under the name in sameBodies when the matcher uses a
//     variant that also reports a count), or is recorded in notAForm with
//     the reason it renders no command text.
//
// A transform added to Analyze outside the builder fails this test until
// someone decides. Entries that no longer match a call fail too.
func TestRedactedFormsCoverMatcherTransforms(t *testing.T) {
	const builder = "buildWholeCommandForms"
	sameBodies := map[string]string{
		"ExecutedTextReport": "ExecutedText", // same bodies plus an unresolved count
	}
	notAForm := map[string]string{
		"AllowDisqualified":        "decides whether an ALLOW rule may apply; renders nothing",
		"SplitSequencedStatements": "splits the command; redactedForms splits with SplitTopLevelStatements",
		"BasenameCommandWord":      "program-name reading for restricting rules; StatementRestrictCandidates applies it per statement when restrictForms is set",
		"DequoteCommand":           "the dequoted whole command, passed into the builder; redactedForms computes the same",
		"NormalizeIFS":             "the IFS-normalized whole command, passed into the builder; redactedForms computes the same",
	}

	files := parseAnalyzerSources(t)
	for _, fn := range []struct{ recv, name string }{{"RegexAnalyzer", "Analyze"}, {"", "redactedForms"}} {
		if !localCalls(t, files, fn.recv, fn.name)[builder] {
			t.Errorf("%s does not call %s; the matcher and subtraction must share one whole-command builder (#4400)", fn.name, builder)
		}
	}

	matcher := shellparseCalls(t, files, "RegexAnalyzer", "Analyze")
	redacted := shellparseCalls(t, files, "", "redactedForms")
	var missing []string
	for _, name := range sortedCallNames(matcher) {
		switch {
		case redacted[name]:
		case sameBodies[name] != "" && redacted[sameBodies[name]]:
		case notAForm[name] != "":
		default:
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		t.Errorf("RegexAnalyzer.Analyze matches against shellparse transforms outside %s that redactedForms does not apply: %s\n"+
			"Move each into %s, add it to redactedForms (position.go), or, if it renders no command text, "+
			"record it in notAForm with the reason.", builder, strings.Join(missing, ", "), builder)
	}
	for _, lists := range []struct {
		label string
		m     map[string]string
	}{{"sameBodies", sameBodies}, {"notAForm", notAForm}} {
		for name := range lists.m {
			if !matcher[name] {
				t.Errorf("%s lists %s, which RegexAnalyzer.Analyze no longer calls; remove the entry", lists.label, name)
			}
		}
	}
}

func parseAnalyzerSources(t *testing.T) []*ast.File {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, p, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	if len(files) == 0 {
		t.Fatal("no analyzer sources found; the test must run from internal/analyzer")
	}
	return files
}

// findFunc returns the declaration of fn, a method on recv when recv is set.
func findFunc(t *testing.T, files []*ast.File, recv, fn string) *ast.FuncDecl {
	t.Helper()
	for _, f := range files {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Name.Name != fn {
				continue
			}
			if recv == "" && fd.Recv == nil {
				return fd
			}
			if recv != "" && fd.Recv != nil && len(fd.Recv.List) == 1 && receiverName(fd.Recv.List[0].Type) == recv {
				return fd
			}
		}
	}
	t.Fatalf("function %s (receiver %q) not found", fn, recv)
	return nil
}

func receiverName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		e = star.X
	}
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// shellparseCalls is every shellparse.X called anywhere inside the function,
// closures included.
func shellparseCalls(t *testing.T, files []*ast.File, recv, fn string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	ast.Inspect(findFunc(t, files, recv, fn), func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if se, ok := call.Fun.(*ast.SelectorExpr); ok {
			if id, ok := se.X.(*ast.Ident); ok && id.Name == "shellparse" {
				out[se.Sel.Name] = true
			}
		}
		return true
	})
	return out
}

// localCalls is every bare-name function called inside the function.
func localCalls(t *testing.T, files []*ast.File, recv, fn string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	ast.Inspect(findFunc(t, files, recv, fn), func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				out[id.Name] = true
			}
		}
		return true
	})
	return out
}

func sortedCallNames(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
