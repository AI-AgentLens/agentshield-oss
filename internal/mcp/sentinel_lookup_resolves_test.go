package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
)

// #4274: a Go detection is attributed to its rule by handing an ENGINE name to
// PolicyEvaluator.LookupSentinel, directly or through a wrapper such as
// sentinelTaxonomyRef. handler.go handed the inputSchema-injection lookup the
// rule's ID instead. The lookup returned nil, every call site tolerates nil,
// and every inputSchema-injection receipt went out without its rule. Nothing
// failed.
//
// The ratchet below closes that class from the source side. It parses the
// non-test Go in the module, statically resolves every value that can reach a
// sentinel lookup, and requires each to name exactly one loaded rule. Zero is
// this bug; two is #4269, which TestSentinelEngines_OneRulePerEngine also
// catches from the pack side. Call sites are found by walking the source, so a
// new lookup, wrapper or engine picker is covered without editing this test,
// and an argument the resolver cannot follow fails the test instead of being
// skipped.

const (
	inputSchemaInjectionRuleID = "mcp-tool-inputschema-injection"
	inputSchemaInjectionNode   = "unauthorized-execution/agentic-attacks/mcp-tool-inputschema-injection"
)

// knownPhantomSentinelEngines are looked up with no rule behind them, on
// purpose and with a correct receipt. The ratchet fails if an entry gains a
// rule or stops being looked up, so this list can only shrink.
var knownPhantomSentinelEngines = map[string]string{
	// FilterErrorResponse looks the error.message surface up under the id its
	// receipt already cites, so that a sentinel added later would take over.
	// None exists. The receipt cites mcp-error-message-injection, a pack-less
	// id (#4164), with a literal TaxonomyRef on the mcp-error-message-injection
	// node, so the attestation is right without a rule.
	"mcp-error-message-injection": "pack-less id by design, tracked in #4164",

	// overrideDirectiveSentinelEngine names two engines no sentinel declares
	// yet. Its doc comment says so: adding the rules is a pack decision. The
	// receipt cites the pack-less id mcp-response-override-directive, and
	// sentinelTaxonomyRef falls back to the generic response-poisoning node
	// (#4060, #4073).
	"mcp-response-override-directive-bare":     "no sentinel yet, a pack decision (#4060)",
	"mcp-response-override-directive-directed": "no sentinel yet, a pack decision (#4060)",
}

// sentinelEngineRef is one value that can reach a sentinel lookup.
type sentinelEngineRef struct {
	engine string
	origin string // file:line of the literal the value came from
	site   string // file:line of the lookup it reaches
}

type sentinelCall struct {
	call *ast.CallExpr
	fn   *ast.FuncDecl
}

// sentinelSource is one package's non-test files, indexed for resolution.
type sentinelSource struct {
	fset   *token.FileSet
	root   string
	files  []*ast.File
	funcs  map[string][]*ast.FuncDecl
	consts map[string]ast.Expr
	types  map[string]bool
	calls  []sentinelCall
	used   map[string]int // resolution path -> uses; the vacuity control
}

func newSentinelSource(fset *token.FileSet, root string, files []*ast.File) *sentinelSource {
	s := &sentinelSource{
		fset: fset, root: root, files: files,
		funcs: map[string][]*ast.FuncDecl{}, consts: map[string]ast.Expr{},
		types: map[string]bool{}, used: map[string]int{},
	}
	for _, f := range files {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				s.funcs[d.Name.Name] = append(s.funcs[d.Name.Name], d)
				if d.Body != nil {
					ast.Inspect(d.Body, func(n ast.Node) bool {
						if c, ok := n.(*ast.CallExpr); ok {
							s.calls = append(s.calls, sentinelCall{c, d})
						}
						return true
					})
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch sp := spec.(type) {
					case *ast.ValueSpec:
						if d.Tok == token.CONST && len(sp.Values) == len(sp.Names) {
							for i, n := range sp.Names {
								s.consts[n.Name] = sp.Values[i]
							}
						}
					case *ast.TypeSpec:
						s.types[sp.Name.Name] = true
					}
				}
			}
		}
	}
	return s
}

func (s *sentinelSource) at(p token.Pos) string {
	pos := s.fset.Position(p)
	if rel, err := filepath.Rel(s.root, pos.Filename); err == nil {
		return fmt.Sprintf("%s:%d", rel, pos.Line)
	}
	return fmt.Sprintf("%s:%d", pos.Filename, pos.Line)
}

func (s *sentinelSource) fail(n ast.Node, format string, args ...any) []string {
	return []string{s.at(n.Pos()) + ": " + fmt.Sprintf(format, args...)}
}

// lookups returns every value that can reach a sentinel lookup in the package,
// the number of lookup sites, and one problem per argument it cannot resolve.
// A lookup is a call to a method named LookupSentinel, or a read of a field
// named SentinelRules (LookupSentinel's own body is the definition).
func (s *sentinelSource) lookups() (refs []sentinelEngineRef, sites int, problems []string) {
	for _, f := range s.files {
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			written := map[ast.Expr]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if a, ok := n.(*ast.AssignStmt); ok {
					for _, l := range a.Lhs {
						written[l] = true
					}
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				var arg ast.Expr
				switch x := n.(type) {
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "LookupSentinel" && len(x.Args) == 1 {
						arg = x.Args[0]
					}
				case *ast.IndexExpr:
					if sel, ok := x.X.(*ast.SelectorExpr); ok && sel.Sel.Name == "SentinelRules" && !written[x] && fn.Name.Name != "LookupSentinel" {
						arg = x.Index
					}
				}
				if arg == nil {
					return true
				}
				sites++
				site := s.at(n.Pos())
				vals, errs := s.resolve(arg, fn, 0)
				for _, e := range errs {
					problems = append(problems, fmt.Sprintf("lookup at %s: %s", site, e))
				}
				reached := false
				for _, v := range vals {
					// "" is an engine picker's "no engine for this signal";
					// every caller skips it or tolerates the nil lookup.
					if v.engine == "" {
						continue
					}
					reached = true
					v.site = site
					refs = append(refs, v)
				}
				if !reached && len(errs) == 0 {
					problems = append(problems, fmt.Sprintf("lookup at %s: only an empty engine can reach it", site))
				}
				return true
			})
		}
	}
	return refs, sites, problems
}

// resolve returns every string e can evaluate to, following literals,
// constants, string concatenation, local variables, a function's parameters
// (through every call of that function in the package), and the return
// statements of a function in the package. Anything else is a problem.
func (s *sentinelSource) resolve(e ast.Expr, fn *ast.FuncDecl, depth int) ([]sentinelEngineRef, []string) {
	if depth > 12 {
		return nil, s.fail(e, "resolution deeper than 12 steps")
	}
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind == token.STRING {
			if v, err := strconv.Unquote(x.Value); err == nil {
				s.used["literal"]++
				return []sentinelEngineRef{{engine: v, origin: s.at(x.Pos())}}, nil
			}
		}
	case *ast.ParenExpr:
		return s.resolve(x.X, fn, depth+1)
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			left, lerr := s.resolve(x.X, fn, depth+1)
			right, rerr := s.resolve(x.Y, fn, depth+1)
			var out []sentinelEngineRef
			for _, l := range left {
				for _, r := range right {
					v := l.engine + r.engine
					if l.engine == "" || r.engine == "" {
						// A picker's "no engine" stays no engine: the one
						// concatenating picker guards it (key != "").
						v = ""
					}
					out = append(out, sentinelEngineRef{engine: v, origin: l.origin})
				}
			}
			s.used["concat"]++
			return out, append(lerr, rerr...)
		}
	case *ast.Ident:
		return s.resolveIdent(x, fn, depth)
	case *ast.CallExpr:
		return s.resolveCall(x, fn, depth)
	}
	return nil, s.fail(e, "cannot resolve %s statically", types.ExprString(e))
}

func (s *sentinelSource) resolveIdent(id *ast.Ident, fn *ast.FuncDecl, depth int) ([]sentinelEngineRef, []string) {
	obj := id.Obj
	if obj == nil {
		// Declared in another file of the package: only constants resolve.
		if v, ok := s.consts[id.Name]; ok {
			s.used["const"]++
			return s.resolve(v, nil, depth+1)
		}
		return nil, s.fail(id, "cannot resolve identifier %s", id.Name)
	}
	switch obj.Kind {
	case ast.Con:
		if vs, ok := obj.Decl.(*ast.ValueSpec); ok && len(vs.Values) == len(vs.Names) {
			for i, n := range vs.Names {
				if n.Name == id.Name {
					s.used["const"]++
					return s.resolve(vs.Values[i], nil, depth+1)
				}
			}
		}
		return nil, s.fail(id, "constant %s has no explicit value", id.Name)
	case ast.Var:
		return s.resolveVar(id, obj, fn, depth)
	}
	return nil, s.fail(id, "cannot resolve identifier %s", id.Name)
}

// resolveVar follows a local variable or parameter: its declaration, then
// every plain reassignment before the use. A reassignment after the use (the
// `rule = sentinel.ID` that records the hit) cannot reach the lookup in
// straight-line code. The resolver does not model a loop carrying a later
// assignment back to an earlier use; no lookup site does that today.
func (s *sentinelSource) resolveVar(id *ast.Ident, obj *ast.Object, fn *ast.FuncDecl, depth int) ([]sentinelEngineRef, []string) {
	if fn == nil || fn.Body == nil {
		return nil, s.fail(id, "variable %s outside a function body", id.Name)
	}
	var out []sentinelEngineRef
	var errs []string
	add := func(v []sentinelEngineRef, e []string) {
		out = append(out, v...)
		errs = append(errs, e...)
	}
	switch d := obj.Decl.(type) {
	case *ast.Field:
		idx, ok := paramIndex(fn, d, id.Name)
		if !ok {
			return nil, s.fail(id, "%s is a receiver or closure parameter", id.Name)
		}
		s.used["param"]++
		callers := s.callersOf(fn)
		if len(callers) == 0 {
			errs = append(errs, s.fail(id, "parameter %s of %s: no call of %s in the package", id.Name, fn.Name.Name, fn.Name.Name)...)
		}
		for _, c := range callers {
			if idx >= len(c.call.Args) || c.call.Ellipsis.IsValid() {
				errs = append(errs, s.fail(c.call, "call of %s does not pass argument %d directly", fn.Name.Name, idx)...)
				continue
			}
			add(s.resolve(c.call.Args[idx], c.fn, depth+1))
		}
	case *ast.AssignStmt:
		s.used["local"]++
		add(s.assigned(d, id.Name, fn, depth))
	case *ast.ValueSpec:
		if d.Pos() < fn.Body.Pos() || d.End() > fn.Body.End() {
			return nil, s.fail(id, "%s is a package-level variable; any code can reassign it", id.Name)
		}
		s.used["local"]++
		for i, n := range d.Names {
			if n.Name != id.Name {
				continue
			}
			switch {
			case len(d.Values) == 0:
				out = append(out, sentinelEngineRef{engine: "", origin: s.at(n.Pos())})
			case len(d.Values) == len(d.Names):
				add(s.resolve(d.Values[i], fn, depth+1))
			default:
				errs = append(errs, s.fail(d, "multi-value declaration of %s", id.Name)...)
			}
		}
	default:
		return nil, s.fail(id, "unsupported declaration of %s", id.Name)
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		a, ok := n.(*ast.AssignStmt)
		if !ok || a == obj.Decl || a.Pos() >= id.Pos() {
			return true
		}
		for _, l := range a.Lhs {
			if li, ok := l.(*ast.Ident); ok && li.Obj == obj {
				if a.Tok != token.ASSIGN {
					errs = append(errs, s.fail(a, "%s updated with %s", li.Name, a.Tok)...)
					continue
				}
				add(s.assigned(a, li.Name, fn, depth))
			}
		}
		return true
	})
	return out, errs
}

func (s *sentinelSource) assigned(a *ast.AssignStmt, name string, fn *ast.FuncDecl, depth int) ([]sentinelEngineRef, []string) {
	for i, l := range a.Lhs {
		if li, ok := l.(*ast.Ident); ok && li.Name == name {
			if len(a.Rhs) != len(a.Lhs) {
				return nil, s.fail(a, "%s assigned from a multi-value expression", name)
			}
			return s.resolve(a.Rhs[i], fn, depth+1)
		}
	}
	return nil, s.fail(a, "assignment does not name %s", name)
}

// paramIndex returns the flat index of the named parameter declared by field
// in fn's own parameter list (not its receiver, not a closure's).
func paramIndex(fn *ast.FuncDecl, field *ast.Field, name string) (int, bool) {
	idx := 0
	for _, f := range fn.Type.Params.List {
		if len(f.Names) == 0 {
			idx++
			continue
		}
		for _, n := range f.Names {
			if f == field && n.Name == name {
				return idx, true
			}
			idx++
		}
	}
	return 0, false
}

func (s *sentinelSource) callersOf(fn *ast.FuncDecl) []sentinelCall {
	var out []sentinelCall
	for _, c := range s.calls {
		switch f := c.call.Fun.(type) {
		case *ast.Ident:
			if fn.Recv == nil && f.Name == fn.Name.Name {
				out = append(out, c)
			}
		case *ast.SelectorExpr:
			if fn.Recv != nil && f.Sel.Name == fn.Name.Name {
				out = append(out, c)
			}
		}
	}
	return out
}

// resolveCall follows a conversion to its operand, and a call of a function in
// the package to every value its return statements can produce.
func (s *sentinelSource) resolveCall(c *ast.CallExpr, fn *ast.FuncDecl, depth int) ([]sentinelEngineRef, []string) {
	var name string
	method := false
	switch f := c.Fun.(type) {
	case *ast.Ident:
		name = f.Name
	case *ast.SelectorExpr:
		name, method = f.Sel.Name, true
	default:
		return nil, s.fail(c, "cannot resolve call %s", types.ExprString(c))
	}
	if !method && len(c.Args) == 1 && (name == "string" || s.types[name]) {
		return s.resolve(c.Args[0], fn, depth+1)
	}
	var callees []*ast.FuncDecl
	for _, d := range s.funcs[name] {
		if (d.Recv != nil) == method && d.Body != nil {
			callees = append(callees, d)
		}
	}
	if len(callees) == 0 {
		return nil, s.fail(c, "cannot resolve call %s: not a function of this package", types.ExprString(c))
	}
	var out []sentinelEngineRef
	var errs []string
	for _, d := range callees {
		if d.Type.Results == nil || d.Type.Results.NumFields() != 1 {
			errs = append(errs, s.fail(c, "%s does not return exactly one value", name)...)
			continue
		}
		s.used["return"]++
		ast.Inspect(d.Body, func(n ast.Node) bool {
			switch r := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ReturnStmt:
				if len(r.Results) != 1 {
					errs = append(errs, s.fail(r, "bare return in %s", name)...)
					return true
				}
				v, e := s.resolve(r.Results[0], d, depth+1)
				out = append(out, v...)
				errs = append(errs, e...)
			}
			return true
		})
	}
	return out, errs
}

// sentinelEngineProblems requires every ref to name exactly one rule. A
// known-gap engine may name none, but must still be looked up and still name
// none, so the gap list cannot go stale.
func sentinelEngineProblems(refs []sentinelEngineRef, rules []MCPRule, knownGaps map[string]string) []string {
	byEngine := map[string][]string{}
	for _, r := range rules {
		if r.Engine != "" {
			byEngine[r.Engine] = append(byEngine[r.Engine], r.ID)
		}
	}
	seen := map[string]bool{}
	var problems []string
	add := func(p string) {
		if !seen[p] {
			seen[p] = true
			problems = append(problems, p)
		}
	}
	gapSeen := map[string]bool{}
	for _, ref := range refs {
		ids := byEngine[ref.engine]
		if len(ids) == 0 {
			if _, ok := knownGaps[ref.engine]; ok {
				gapSeen[ref.engine] = true
				continue
			}
		}
		if len(ids) != 1 {
			sorted := append([]string(nil), ids...)
			sort.Strings(sorted)
			add(fmt.Sprintf("lookup at %s: engine %q (from %s) names %d loaded rules %v, want exactly 1", ref.site, ref.engine, ref.origin, len(ids), sorted))
		}
	}
	for g := range knownGaps {
		switch {
		case len(byEngine[g]) != 0:
			add(fmt.Sprintf("known gap %q now names rules %v: delete it from the gap list", g, byEngine[g]))
		case !gapSeen[g]:
			add(fmt.Sprintf("known gap %q is no longer looked up: delete it from the gap list", g))
		}
	}
	sort.Strings(problems)
	return problems
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

// loadSentinelSources parses, per package, the non-test Go of every directory
// in the module whose source mentions a sentinel lookup.
func loadSentinelSources(t *testing.T) []*sentinelSource {
	t.Helper()
	root := moduleRoot(t)
	fset := token.NewFileSet()
	var out []*sentinelSource
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != root && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" || name == "node_modules") {
			return filepath.SkipDir
		}
		entries, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		var srcs []string
		mentions := false
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(path, n))
			if err != nil {
				return err
			}
			if bytes.Contains(b, []byte("LookupSentinel")) || bytes.Contains(b, []byte("SentinelRules")) {
				mentions = true
			}
			srcs = append(srcs, filepath.Join(path, n))
		}
		if !mentions {
			return nil
		}
		byPkg := map[string][]*ast.File{}
		for _, p := range srcs {
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				return err
			}
			byPkg[f.Name.Name] = append(byPkg[f.Name.Name], f)
		}
		for _, files := range byPkg {
			out = append(out, newSentinelSource(fset, root, files))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestSentinelLookups_EveryEngineResolvesToOneRule is the #4274 ratchet: every
// value that can reach a sentinel lookup in non-test Go names exactly one rule
// of the shipped corpus (community + premium, through the real loader).
func TestSentinelLookups_EveryEngineResolvesToOneRule(t *testing.T) {
	p := embeddedSentinelPolicy(t)
	var refs []sentinelEngineRef
	sites := 0
	used := map[string]int{}
	for _, s := range loadSentinelSources(t) {
		r, n, problems := s.lookups()
		refs = append(refs, r...)
		sites += n
		for _, pr := range problems {
			t.Errorf("unresolvable sentinel lookup (pass a literal, a constant or an engine picker the resolver follows): %s", pr)
		}
		for k, v := range s.used {
			used[k] += v
		}
	}
	// Vacuity controls: the denominator, and every resolution path in use.
	if sites < 100 {
		t.Fatalf("only %d sentinel lookup sites found, want >= 100: the walk lost the source and this gate is vacuous", sites)
	}
	for _, path := range []string{"literal", "const", "concat", "local", "param", "return"} {
		if used[path] == 0 {
			t.Errorf("no lookup resolved through %s: the resolver lost a path the source uses", path)
		}
	}
	for _, pr := range sentinelEngineProblems(refs, p.Rules, knownPhantomSentinelEngines) {
		t.Error(pr)
	}
	distinct := map[string]bool{}
	for _, r := range refs {
		distinct[r.engine] = true
	}
	t.Logf("%d lookup sites, %d engine values (%d distinct) checked against the loaded corpus; paths used: %v", sites, len(refs), len(distinct), used)
}

// TestSentinelLookupRatchet_FlagsPhantomSharedAndUnresolvable is the ratchet's
// own negative control, on a synthetic package: it must flag an engine that
// names no rule (on each path the resolver follows), an engine two rules
// share, an argument it cannot resolve, and a stale gap-list entry.
func TestSentinelLookupRatchet_FlagsPhantomSharedAndUnresolvable(t *testing.T) {
	const src = `package fake

const goodConst = "eng-good"

type E struct{ SentinelRules map[string]int }
type H struct{ E *E }

func (e *E) LookupSentinel(engine string) int { return e.SentinelRules[engine] }

func pick(n int) string {
	switch n {
	case 1:
		return "eng-good"
	case 2:
		return "eng-phantom-picker"
	}
	return ""
}

func (h *H) ref(engine string) int { return h.E.LookupSentinel(engine) }

func (h *H) run(n int, x string) {
	h.E.LookupSentinel("eng-good")
	h.E.LookupSentinel(goodConst)
	h.E.LookupSentinel(pick(n))
	h.ref("eng-phantom-param")
	h.E.LookupSentinel("eng-phantom-literal")
	h.E.LookupSentinel("eng-shared")
	_ = h.E.SentinelRules["eng-phantom-index"]
	rule := "eng-good"
	if n > 3 {
		rule = "eng-phantom-local"
	}
	if h.E.LookupSentinel(rule) != 0 {
		rule = "assigned-after-the-lookup"
	}
	h.E.LookupSentinel(strings.ToLower(x))
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fake.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := newSentinelSource(fset, "", []*ast.File{f})
	refs, sites, unresolved := s.lookups()
	// Nine: eight in run, one in ref. LookupSentinel's own read of
	// SentinelRules is the definition, not a lookup site.
	if sites != 9 {
		t.Errorf("found %d lookup sites, want 9", sites)
	}
	if len(unresolved) != 1 || !strings.Contains(unresolved[0], "strings.ToLower") {
		t.Errorf("unresolvable arguments = %v, want exactly the strings.ToLower call", unresolved)
	}
	rules := []MCPRule{
		{ID: "r-good", Engine: "eng-good"},
		{ID: "r-shared-1", Engine: "eng-shared"},
		{ID: "r-shared-2", Engine: "eng-shared"},
	}
	problems := strings.Join(sentinelEngineProblems(refs, rules, nil), "\n")
	for _, want := range []string{"eng-phantom-picker", "eng-phantom-param", "eng-phantom-literal", "eng-phantom-index", "eng-phantom-local", `"eng-shared"`} {
		if !strings.Contains(problems, want) {
			t.Errorf("ratchet did not flag %s; problems:\n%s", want, problems)
		}
	}
	for _, notWant := range []string{`"eng-good"`, "assigned-after-the-lookup"} {
		if strings.Contains(problems, notWant) {
			t.Errorf("ratchet flagged %s, which names one rule or cannot reach a lookup; problems:\n%s", notWant, problems)
		}
	}
	gaps := map[string]string{"eng-phantom-literal": "ok", "eng-good": "now resolves", "eng-gone": "no longer looked up"}
	gapProblems := strings.Join(sentinelEngineProblems(refs, rules, gaps), "\n")
	if strings.Contains(gapProblems, `"eng-phantom-literal"`) {
		t.Errorf("a listed gap was flagged:\n%s", gapProblems)
	}
	for _, want := range []string{`known gap "eng-good" now names rules`, `known gap "eng-gone" is no longer looked up`} {
		if !strings.Contains(gapProblems, want) {
			t.Errorf("stale gap entry not flagged (%s):\n%s", want, gapProblems)
		}
	}
}

// TestInputSchemaInjectionReceipt_CitesItsRuleAndNode drives the #2311
// inputSchema-injection fixtures through the proxy handler with the shipped
// packs and reads the receipt. Before #4274 the lookup passed the rule id as
// the engine, got nil, and the receipt never named the inputSchema rule.
func TestInputSchemaInjectionReceipt_CitesItsRuleAndNode(t *testing.T) {
	p := embeddedSentinelPolicy(t)
	ev := NewPolicyEvaluator(p)
	var rule *MCPRule
	for i := range p.Rules {
		if p.Rules[i].ID == inputSchemaInjectionRuleID {
			rule = &p.Rules[i]
		}
	}
	if rule == nil {
		t.Fatalf("rule %s is not in the shipped corpus", inputSchemaInjectionRuleID)
	}
	if rule.Taxonomy != inputSchemaInjectionNode {
		t.Errorf("rule %s attests to %q, want %q", rule.ID, rule.Taxonomy, inputSchemaInjectionNode)
	}
	checked := 0
	for _, sc := range scenarios.InputSchemaInjectionScenarios2311 {
		if sc.Classification != "TP" {
			continue
		}
		t.Run(sc.ID, func(t *testing.T) {
			tool := ToolDefinition{Name: sc.ToolName, Description: sc.ToolDescription, InputSchema: json.RawMessage(sc.InputSchema)}
			raised := false
			for _, f := range ScanToolDescription(tool).Findings {
				raised = raised || f.Signal == SignalInputSchemaPropDescInjection
			}
			if !raised {
				t.Fatalf("fixture does not raise %s, so it cannot test the receipt", SignalInputSchemaPropDescInjection)
			}
			h := &MessageHandler{Stderr: io.Discard, ServerName: "s", Evaluator: ev}
			e := descScanEntry(t, filterOne(t, h, tool))
			if e.Decision != "BLOCK" {
				t.Errorf("decision = %s, want BLOCK", e.Decision)
			}
			if !hasRuleID(e.TriggeredRules, inputSchemaInjectionRuleID) {
				t.Errorf("receipt cites %v, want %s (node %s)", e.TriggeredRules, inputSchemaInjectionRuleID, inputSchemaInjectionNode)
			}
		})
		checked++
	}
	if checked < 4 {
		t.Fatalf("only %d TP fixtures checked, want >= 4", checked)
	}
}

// TestInputSchemaInjectionReceipt_NotCitedWithoutItsFinding is the absence
// half of the receipt contract (#4282 item 1). The presence test above pins
// that an inputSchema finding cites mcp-tool-inputschema-injection; it passes
// a handler that ALSO cites the rule for other findings. The #4281 review's
// mutant MF3 (cite it on credential-harvest findings too) passed the whole
// ./internal/mcp/ suite. That is wrong evidence on the attestation path: a
// receipt naming a node the agent never hit.
//
// Each #2311 TP payload is moved to a surface that is not an inputSchema
// property: the tool description, outputSchema, _meta, and the inputSchema
// root description. The scanner still flags it there, so each fixture yields a
// description-scan receipt, and that receipt must name neither the rule nor
// its node. Description-only scenario TPs (credential harvest, hidden
// instructions, exfiltration, ...) are added for the same reason.
func TestInputSchemaInjectionReceipt_NotCitedWithoutItsFinding(t *testing.T) {
	p := embeddedSentinelPolicy(t)
	ev := NewPolicyEvaluator(p)
	nodeOf := map[string]string{}
	for _, r := range p.Rules {
		nodeOf[r.ID] = r.Taxonomy
	}
	// Positive control: the rule is loaded and resolvable, so an absent
	// citation is the handler's choice, not a missing sentinel.
	if sent := ev.LookupSentinel(inputSchemaPropInjectionSentinelEngine); sent == nil || sent.ID != inputSchemaInjectionRuleID {
		t.Fatalf("engine %s does not resolve to %s; absence would be vacuous", inputSchemaPropInjectionSentinelEngine, inputSchemaInjectionRuleID)
	}

	type fixture struct {
		id   string
		tool ToolDefinition
	}
	var fixtures []fixture
	clean := json.RawMessage(`{"type":"object","properties":{"x":{"type":"string"}}}`)
	moved := 0
	for _, sc := range scenarios.InputSchemaInjectionScenarios2311 {
		if sc.Classification != "TP" {
			continue
		}
		schema := json.RawMessage(sc.InputSchema)
		payload := firstPropertyDescription(t, schema)
		root, err := json.Marshal(map[string]any{
			"type":        "object",
			"description": payload,
			"properties":  map[string]any{"x": map[string]any{"type": "string"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures,
			fixture{"description-only/" + sc.ID, ToolDefinition{Name: "t_desc", Description: payload, InputSchema: clean}},
			fixture{"outputSchema/" + sc.ID, ToolDefinition{Name: "t_out", Description: "Reads a document.", OutputSchema: schema}},
			fixture{"_meta/" + sc.ID, ToolDefinition{Name: "t_meta", Description: "Reads a document.", Meta: schema}},
			fixture{"schema-root-description/" + sc.ID, ToolDefinition{Name: "t_root", Description: "Reads a document.", InputSchema: root}},
		)
		moved++
	}
	if moved < 4 {
		t.Fatalf("only %d #2311 TP payloads moved, want >= 4", moved)
	}
	descOnly := 0
	for _, sc := range scenarios.AllScenarios() {
		if sc.Classification != "TP" || sc.ToolDescription == "" || sc.InputSchema != "" {
			continue
		}
		tool := ToolDefinition{Name: "t_scn", Description: sc.ToolDescription}
		if !ScanToolDescription(tool).Poisoned {
			continue // a TP that needs its schema, title or call to fire
		}
		fixtures = append(fixtures, fixture{"description-only/" + sc.ID, tool})
		descOnly++
	}
	if descOnly < 20 {
		t.Fatalf("only %d description-only scenario TPs flag on their own, want >= 20", descOnly)
	}

	signals := map[PoisonSignal]int{}
	for _, fx := range fixtures {
		t.Run(fx.id, func(t *testing.T) {
			for _, f := range ScanToolDescription(fx.tool).Findings {
				if f.Signal == SignalInputSchemaPropDescInjection {
					t.Fatalf("fixture raises %s, so it cannot test absence", SignalInputSchemaPropDescInjection)
				}
				signals[f.Signal]++
			}
			h := &MessageHandler{Stderr: io.Discard, ServerName: "s", Evaluator: ev}
			audits := filterOne(t, h, fx.tool)
			descScanEntry(t, audits) // the payload was flagged on this surface
			for _, a := range audits {
				for _, id := range a.TriggeredRules {
					if id == inputSchemaInjectionRuleID || nodeOf[id] == inputSchemaInjectionNode {
						t.Errorf("audit source=%s cites %s (node %s) with no inputSchema finding; rules %v", a.Source, id, nodeOf[id], a.TriggeredRules)
					}
				}
				if a.TaxonomyRef == inputSchemaInjectionNode {
					t.Errorf("audit source=%s carries taxonomy_ref %s with no inputSchema finding", a.Source, a.TaxonomyRef)
				}
			}
		})
	}
	// MF3 widened the citation to credential-harvest findings. The fixtures
	// must raise that signal, and a few others, or the guard is vacuous for it.
	if signals[SignalCredentialHarvest] == 0 {
		t.Errorf("no fixture raises %s; the MF3 shape is untested", SignalCredentialHarvest)
	}
	if len(signals) < 8 {
		t.Errorf("fixtures raise only %d distinct signals, want >= 8: %v", len(signals), signals)
	}
	t.Logf("%d fixtures (%d moved #2311 payloads x4 surfaces, %d description-only TPs), %d distinct signals", len(fixtures), moved, descOnly, len(signals))
}

// firstPropertyDescription returns the first property description in a JSON
// schema, searching nested properties and $defs, so a #2311 payload can be
// moved to another surface.
func firstPropertyDescription(t *testing.T, schema json.RawMessage) string {
	t.Helper()
	var v any
	if err := json.Unmarshal(schema, &v); err != nil {
		t.Fatalf("schema does not parse: %v", err)
	}
	var walk func(any, bool) string
	walk = func(n any, inProps bool) string {
		m, ok := n.(map[string]any)
		if !ok {
			return ""
		}
		if d, ok := m["description"].(string); ok && inProps {
			return d
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch k {
			case "properties", "$defs", "definitions":
				if children, ok := m[k].(map[string]any); ok {
					ckeys := make([]string, 0, len(children))
					for ck := range children {
						ckeys = append(ckeys, ck)
					}
					sort.Strings(ckeys)
					for _, ck := range ckeys {
						if d := walk(children[ck], k == "properties"); d != "" {
							return d
						}
					}
				}
			}
		}
		return ""
	}
	d := walk(v, false)
	if d == "" {
		t.Fatalf("no property description in %s", schema)
	}
	return d
}
