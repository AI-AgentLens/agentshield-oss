package archtest

import (
	"go/parser"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The import column of ADR-001's package table
// (docs/architecture/adr-001-tool-routing-dialect-lanes.md, "Packages"):
//
//	internal/facts     the contract a new lane hands the back end: stdlib only
//	internal/psreader  the PowerShell lane: internal/facts and stdlib only
//	internal/policy    the back end: may import facts, never a lane (D3)
//
// The first two keep a lane free of dialect-foreign code and of anything that
// could reach a process or .NET (D7); the third keeps dialect knowledge out of
// the back end. This file is self-contained on purpose: its helpers are
// prefixed `lane` so they cannot collide with another rule added beside it.

// laneImportRules lists, per package, the module packages it may import.
// Standard-library imports are always allowed; any other import (a module
// package not listed, or a third-party module) is a violation.
var laneImportRules = map[string][]string{
	"internal/facts":    {},
	"internal/psreader": {"internal/facts"},
}

// laneNoProcessImports are the standard-library ways a Go package starts a
// process or loads foreign code. ADR-001 D7: a lane reads text as characters
// and never runs PowerShell (or anything else), so no package in
// laneImportRules may import these, stdlib or not. `C` is cgo.
var laneNoProcessImports = []string{"os/exec", "syscall", "plugin", "C"}

// laneForbiddenImporters: no package at or under the key may import any of
// the listed packages.
var laneForbiddenImporters = map[string][]string{
	"internal/policy": {"internal/psreader"},
}

// laneImportGraph maps each module package (non-test files) to every import
// path its files name, standard library included.
func laneImportGraph(t *testing.T) map[string]map[string]bool {
	t.Helper()
	g := map[string]map[string]bool{}
	for _, f := range moduleFiles(t, moduleRoot(t), parser.ImportsOnly) {
		if g[f.pkg] == nil {
			g[f.pkg] = map[string]bool{}
		}
		for _, spec := range f.file.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: bad import %s", f.rel, spec.Path.Value)
			}
			g[f.pkg][p] = true
		}
	}
	return g
}

// laneIsStdlib: a standard-library path has no dot in its first element
// (`encoding/json`), unlike a module path (`github.com/…`, `gopkg.in/…`).
func laneIsStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return !strings.Contains(first, ".")
}

// laneViolations checks a graph against both rule sets.
func laneViolations(g map[string]map[string]bool, allowed map[string][]string, forbidden map[string][]string) []string {
	var out []string
	noProcess := map[string]bool{}
	for _, p := range laneNoProcessImports {
		noProcess[p] = true
	}
	for pkg, may := range allowed {
		ok := map[string]bool{}
		for _, m := range may {
			ok[modulePath+"/"+m] = true
		}
		for imp := range g[pkg] {
			if !laneIsStdlib(imp) && !ok[imp] || noProcess[imp] {
				out = append(out, pkg+" imports "+imp)
			}
		}
	}
	for root, never := range forbidden {
		for pkg, imports := range g {
			if pkg != root && !strings.HasPrefix(pkg, root+"/") {
				continue
			}
			for _, n := range never {
				if imports[modulePath+"/"+n] {
					out = append(out, pkg+" imports "+n)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func TestDialectLaneImports(t *testing.T) {
	g := laneImportGraph(t)
	// Denominator: the packages the rules name must exist, or a rename
	// would leave the rules checking nothing.
	for pkg := range laneImportRules {
		if g[pkg] == nil {
			t.Errorf("%s has no non-test Go files: fix laneImportRules", pkg)
		}
	}
	for root := range laneForbiddenImporters {
		if g[root] == nil {
			t.Errorf("%s has no non-test Go files: fix laneForbiddenImporters", root)
		}
	}
	if !g["internal/psreader"][modulePath+"/internal/facts"] {
		t.Errorf("control edge internal/psreader -> internal/facts not found: the import walk is broken")
	}
	for _, v := range laneViolations(g, laneImportRules, laneForbiddenImporters) {
		t.Errorf("dialect-lane layering (ADR-001): %s", v)
	}
}

// TestDialectLaneImports_SelfTest proves the checker reports each kind of
// violation, on a graph built by hand.
func TestDialectLaneImports_SelfTest(t *testing.T) {
	m := func(p string) string { return modulePath + "/" + p }
	g := map[string]map[string]bool{
		"internal/facts":           {"fmt": true, "gopkg.in/yaml.v3": true, "os/exec": true},
		"internal/psreader":        {"strings": true, m("internal/facts"): true, m("internal/pathnorm"): true},
		"internal/policy":          {m("internal/facts"): true},
		"internal/policy/sub":      {m("internal/psreader"): true},
		"internal/policyx":         {m("internal/psreader"): true}, // not under internal/policy
		"internal/assembly":        {m("internal/psreader"): true},
		"internal/psreader/nested": {"os/exec": true}, // a subpackage is its own key
	}
	got := laneViolations(g, laneImportRules, laneForbiddenImporters)
	want := []string{
		"internal/facts imports gopkg.in/yaml.v3",
		"internal/facts imports os/exec",
		"internal/policy/sub imports internal/psreader",
		"internal/psreader imports " + m("internal/pathnorm"),
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("violations:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
