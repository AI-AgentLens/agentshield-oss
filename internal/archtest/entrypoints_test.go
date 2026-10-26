package archtest

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"testing"
)

// engineConstructors are the functions that build a decision engine, keyed by
// the package that defines them.
var engineConstructors = map[string][]string{
	"internal/policy": {"NewEngine", "NewEngineWithAnalyzers"},
	"internal/mcp":    {"NewPolicyEvaluator"},
}

// assemblyBuilders are the composition-root functions every enforcing surface
// builds its engine through (#4315 step 1).
var assemblyBuilders = map[string][]string{
	"internal/assembly": {"ShellEngine", "MCPEvaluator"},
}

// entryPoint describes one function that builds an engine.
type entryPoint struct {
	surface string
	// enforcing is true when the engine decides live agent actions, as
	// opposed to a diagnostic CLI or a build tool. Every enforcing surface
	// must get the same overlays (org blocklist and allowlist, data labels);
	// #4315's surface-parity test is meant to cover exactly these.
	enforcing bool
	calls     int // how many references the function holds
}

// directConstructionSites are the only functions allowed to call an engine
// constructor directly, keyed "file:Function". internal/assembly is the
// composition root. The others are diagnostics, build tools and samples that
// decide nothing live. None may be enforcing: an enforcing surface that built
// its own engine would skip whatever assembly installs, which is how data
// labels came to skip the hook's tool path (#4318).
var directConstructionSites = map[string]entryPoint{
	"internal/assembly/assembly.go:ShellEngine":  {surface: "composition root, shell", calls: 1},
	"internal/assembly/assembly.go:MCPEvaluator": {surface: "composition root, MCP", calls: 1},
	"internal/cli/scan.go:scanCommand":           {surface: "agentshield scan (self-test, shell and MCP)", calls: 2},
	"cmd/mcp-gen/dedup.go:NewCoverageChecker":    {surface: "mcp-gen coverage checker (build tool)", calls: 1},
	"samples/mcp-demo/main.go:main":              {surface: "MCP demo sample", calls: 1},
}

// registeredEntryPoints lists every caller of the assembly builders, keyed
// "file:Function", with the surface it serves. It must match the code exactly.
//
// Why: each surface used to build its own engine and wire its own features,
// and a feature wired by hand at some surfaces silently skips the rest. This
// list makes adding a surface a deliberate edit: a new caller fails the test
// until it is registered, and an enforcing one must also get a parity row.
var registeredEntryPoints = map[string]entryPoint{
	// Decide live agent actions.
	"internal/cli/hook.go:evaluateCommandNoted":              {surface: "shell hook (every harness's shell tool)", enforcing: true, calls: 1},
	"internal/cli/hook.go:handleClaudeCodeMCPCall":           {surface: "hook tool path (built-in tools and mcp__* via PreToolUse)", enforcing: true, calls: 1},
	"internal/cli/mcp_proxy.go:mcpProxyCommand":              {surface: "stdio MCP proxy", enforcing: true, calls: 1},
	"internal/cli/mcp_http_proxy.go:mcpHTTPProxyCommand":     {surface: "HTTP MCP proxy", enforcing: true, calls: 1},
	"cmd/shield-server/server.go:(*Server).loadShellEngine":  {surface: "shield-server /v1/evaluate, shell", enforcing: true, calls: 1},
	"cmd/shield-server/server.go:(*Server).loadMCPEvaluator": {surface: "shield-server /v1/evaluate, MCP", enforcing: true, calls: 1},

	// Diagnostics that predict an enforcing surface.
	"internal/cli/check.go:newCheckEngine": {surface: "agentshield check (predicts the shell hook)", calls: 1},
	"internal/cli/mcp_eval.go:mcpEvalRun":  {surface: "agentshield mcp-eval (predicts the hook tool path)", calls: 1},
}

// constructorRefs finds every reference to one of the given functions
// (package -> names) outside its own package, keyed "file:Function" (methods
// as "(*T).M" or "T.M", package scope as "<package scope>"). A reference that
// is not a call, such as passing the function as a value, counts too.
func constructorRefs(files []goFile, defs map[string][]string) map[string]int {
	refs := map[string]int{}
	for _, f := range files {
		// local import name -> constructor names visible through it
		visible := map[string]map[string]bool{}
		for _, imp := range internalImports(f.file) {
			names, ok := defs[imp.rel]
			if !ok || imp.rel == f.pkg {
				continue
			}
			set := map[string]bool{}
			for _, n := range names {
				set[n] = true
			}
			visible[imp.local] = set
		}
		if len(visible) == 0 {
			continue
		}
		count := func(scope string, n ast.Node) {
			ast.Inspect(n, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if ok && visible[x.Name][sel.Sel.Name] {
					refs[f.rel+":"+scope]++
				}
				return true
			})
		}
		for _, decl := range f.file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				count(funcName(d), d)
			case *ast.GenDecl:
				count("<package scope>", d)
			}
		}
	}
	return refs
}

func funcName(d *ast.FuncDecl) string {
	if d.Recv == nil || len(d.Recv.List) == 0 {
		return d.Name.Name
	}
	switch r := d.Recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := r.X.(*ast.Ident); ok {
			return "(*" + id.Name + ")." + d.Name.Name
		}
	case *ast.Ident:
		return r.Name + "." + d.Name.Name
	}
	return d.Name.Name
}

// checkRegistry compares the references found against a registry and returns
// one message per mismatch.
func checkRegistry(refs map[string]int, registry map[string]entryPoint, unregistered string) []string {
	var problems []string
	var keys []string
	for k := range refs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ep, ok := registry[k]
		switch {
		case !ok:
			problems = append(problems, fmt.Sprintf("%s: %s (%d reference(s))", unregistered, k, refs[k]))
		case ep.calls != refs[k]:
			problems = append(problems, fmt.Sprintf("%s: registered with %d reference(s), found %d", k, ep.calls, refs[k]))
		}
	}
	var gone []string
	for k := range registry {
		if _, ok := refs[k]; !ok {
			gone = append(gone, k)
		}
	}
	sort.Strings(gone)
	for _, k := range gone {
		problems = append(problems, "registered but no longer found, delete it: "+k)
	}
	return problems
}

// TestEnforcingSurfacesBuildThroughAssembly: an engine constructor may be
// called directly only by internal/assembly and the registered non-enforcing
// sites.
func TestEnforcingSurfacesBuildThroughAssembly(t *testing.T) {
	refs := constructorRefs(moduleFiles(t, moduleRoot(t), parser.SkipObjectResolution), engineConstructors)
	for _, p := range checkRegistry(refs, directConstructionSites, "engine constructor called outside internal/assembly") {
		t.Errorf("%s\n"+
			"  A surface that decides live agent actions must build its engine with\n"+
			"  assembly.ShellEngine / assembly.MCPEvaluator, or org policy and data labels\n"+
			"  will silently skip it (#4315, #4318). A diagnostic or build tool may build\n"+
			"  directly: register it in directConstructionSites.", p)
	}
	for k, ep := range directConstructionSites {
		if ep.enforcing {
			t.Errorf("%s is marked enforcing but builds its engine directly; route it through internal/assembly", k)
		}
	}
}

// TestAssemblyCallersAreRegistered: every caller of the assembly builders is
// registered with its surface.
func TestAssemblyCallersAreRegistered(t *testing.T) {
	refs := constructorRefs(moduleFiles(t, moduleRoot(t), parser.SkipObjectResolution), assemblyBuilders)
	for _, p := range checkRegistry(refs, registeredEntryPoints, "unregistered caller of internal/assembly") {
		t.Errorf("%s\n"+
			"  Register it in registeredEntryPoints with its surface. If it decides live agent\n"+
			"  actions (enforcing: true), it also needs a row in #4315's surface-parity test.", p)
	}
}

// TestEngineConstructionSites_Denominator: both finders must see a floor of
// references. A finder that matched nothing would pass every registry check
// against an empty registry.
func TestEngineConstructionSites_Denominator(t *testing.T) {
	files := moduleFiles(t, moduleRoot(t), parser.SkipObjectResolution)
	count := func(refs map[string]int) (n int) {
		for _, c := range refs {
			n += c
		}
		return n
	}
	if n := count(constructorRefs(files, engineConstructors)); n < 5 {
		t.Errorf("found %d engine-constructor references, want >= 5: the finder is not seeing them", n)
	}
	if n := count(constructorRefs(files, assemblyBuilders)); n < 6 {
		t.Errorf("found %d assembly-builder references, want >= 6: the finder is not seeing them", n)
	}
	enforcing := 0
	for _, ep := range registeredEntryPoints {
		if ep.enforcing {
			enforcing++
		}
	}
	if enforcing < 6 {
		t.Errorf("only %d enforcing surfaces registered, want 6 (hook shell, hook tools, two proxies, shield-server shell and MCP)", enforcing)
	}
}

// TestConstructorRefs_SelfTest checks alias handling, method naming and
// same-package exclusion on hand-written sources.
func TestConstructorRefs_SelfTest(t *testing.T) {
	src := map[string]string{
		"internal/cli/a.go": `package cli
import pol "` + modulePath + `/internal/policy"
func one() { _, _ = pol.NewEngine(nil) }
type S struct{}
func (s *S) two() { f := pol.NewEngineWithAnalyzers; _ = f }
var three, _ = pol.NewEngine(nil)
`,
		// The constructor's own package does not count.
		"internal/policy/b.go": `package policy
func NewEngineWithAnalyzers() { NewEngine(nil) }
`,
	}
	fset := token.NewFileSet()
	var files []goFile
	for rel, s := range src {
		f, err := parser.ParseFile(fset, rel, s, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, goFile{rel: rel, pkg: rel[:strings.LastIndex(rel, "/")], file: f})
	}
	got := constructorRefs(files, engineConstructors)
	want := map[string]int{
		"internal/cli/a.go:one":             1,
		"internal/cli/a.go:(*S).two":        1,
		"internal/cli/a.go:<package scope>": 1,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("constructorRefs = %v, want %v", got, want)
	}
}
