package archtest

import (
	"fmt"
	"go/parser"
	"sort"
	"strings"
	"testing"
)

// coreLayer is the decision engine and the pure packages it is built from.
// A core package may import only other core packages, plus the standard
// library and third-party modules. Everything else in this module sits above
// the core and may depend on it, never the reverse: the CLI, config loading,
// logging, auth, the enterprise features and the build tooling.
//
// This is what lets an enterprise feature (an org blocklist, DLP, the overlay
// of #4315) be added without touching the engine: the engine cannot reach the
// feature, so the feature has to plug in above it.
//
// Why a closed list rather than a blocklist of enterprise packages: what the
// core must not reach includes every package that does not exist yet, such as
// the next enterprise feature. That set is not enumerable, so the closed list
// is the right default here (CLAUDE.md, "invert an allowlist when the
// not-allowed set is ENUMERABLE"). A new package stays outside the core until
// someone adds it here on purpose.
var coreLayer = map[string]string{
	"internal/analyzer":           "the staged analyzer pipeline",
	"internal/guardian":           "heuristic analyzer stage",
	"internal/policy":             "shell rule engine and pack loading",
	"internal/policy/remediation": "BLOCK self-help text; the managed fact is passed in (#4321)",
	"internal/mcp":                "MCP tool-call evaluator and proxy message handler",
	"internal/mcp/scenarios":      "MCP self-test scenarios",
	"internal/normalize":          "command normalisation: paths and destination domains",
	"internal/shellparse":         "shell AST",
	"internal/datalabel":          "data-label matching engine",
	"internal/pathnorm":           "path normalisation",
	"internal/mountspec":          "container mount parsing",
	"internal/execenv":            "execution-context facts",
	"internal/regexlit":           "regex literal matching",
	"internal/seqmatch":           "sequence matching",
	"internal/unicode":            "unicode smuggling scan",
	"internal/redact":             "secret redaction",
	"packs":                       "embedded rule packs (data the engine loads)",
}

// knownLayerViolations are edges that break the rule today. Each one names the
// issue that removes it. The list may only shrink: an entry whose edge no
// longer exists fails the test, so the PR that fixes an edge must delete its
// line here too.
var knownLayerViolations = map[[2]string]string{}

// importGraph maps a module package to the module packages it imports.
type importGraph map[string]map[string]bool

func buildImportGraph(t *testing.T) importGraph {
	t.Helper()
	g := importGraph{}
	for _, f := range moduleFiles(t, moduleRoot(t), parser.ImportsOnly) {
		if g[f.pkg] == nil {
			g[f.pkg] = map[string]bool{}
		}
		for _, imp := range internalImports(f.file) {
			g[f.pkg][imp.rel] = true
		}
	}
	return g
}

// layeringViolations returns the edges from a core package to a package
// outside the core that are not known exceptions, and the known exceptions
// whose edge is gone.
func layeringViolations(g importGraph, core map[string]string, known map[[2]string]string) (violations, stale []string) {
	for from, imports := range g {
		if _, isCore := core[from]; !isCore {
			continue
		}
		for to := range imports {
			if _, ok := core[to]; ok {
				continue
			}
			if _, ok := known[[2]string{from, to}]; ok {
				continue
			}
			violations = append(violations, from+" -> "+to)
		}
	}
	for edge, why := range known {
		if !g[edge[0]][edge[1]] {
			stale = append(stale, fmt.Sprintf("%s -> %s (%s)", edge[0], edge[1], why))
		}
	}
	sort.Strings(violations)
	sort.Strings(stale)
	return violations, stale
}

func TestCoreImportsOnlyCore(t *testing.T) {
	g := buildImportGraph(t)
	violations, stale := layeringViolations(g, coreLayer, knownLayerViolations)
	for _, v := range violations {
		t.Errorf("core package imports a package above the core: %s\n"+
			"  The engine must not depend on the CLI, config, logging, auth or enterprise features.\n"+
			"  Pass the fact in from the caller instead (see #4315). If the imported package really\n"+
			"  is pure engine code, add it to coreLayer with a one-line reason.", v)
	}
	for _, s := range stale {
		t.Errorf("known layering violation no longer exists, delete it from knownLayerViolations: %s", s)
	}
}

// TestOnlyCommandsImportCLI: internal/cli is the application layer, holding
// flag parsing, hook I/O and os.Exit. Only the cmd/ binaries may import it.
func TestOnlyCommandsImportCLI(t *testing.T) {
	g := buildImportGraph(t)
	for from, imports := range g {
		if imports["internal/cli"] && !strings.HasPrefix(from, "cmd/") {
			t.Errorf("%s imports internal/cli; only cmd/ binaries may", from)
		}
	}
}

// TestImportGraph_Denominator guards against a vacuous pass: a walker that
// parsed nothing, or a core list naming packages that do not exist, would
// make the layering test green and meaningless.
func TestImportGraph_Denominator(t *testing.T) {
	g := buildImportGraph(t)
	if len(g) < 20 {
		t.Fatalf("import graph has %d packages, want >= 20: the walker is not seeing the module", len(g))
	}
	for _, edge := range [][2]string{
		{"internal/policy", "internal/analyzer"},
		{"internal/cli", "internal/enterprise"},
		{"internal/mcp", "internal/policy"},
	} {
		if !g[edge[0]][edge[1]] {
			t.Errorf("control edge %s -> %s not found: the import parser is broken", edge[0], edge[1])
		}
	}
	for pkg := range coreLayer {
		if _, ok := g[pkg]; !ok {
			t.Errorf("coreLayer names %q, which has no non-test Go files: fix or delete the entry", pkg)
		}
	}
}

// TestLayeringViolations_SelfTest proves the checker reports what it should,
// on a graph built by hand.
func TestLayeringViolations_SelfTest(t *testing.T) {
	core := map[string]string{"a": "", "b": ""}
	g := importGraph{
		"a":   {"b": true, "ent": true, "cli": true},
		"b":   {},
		"cli": {"a": true, "ent": true}, // above the core: may import anything
	}
	known := map[[2]string]string{
		{"a", "cli"}:  "pinned",
		{"b", "gone"}: "fixed already",
	}
	violations, stale := layeringViolations(g, core, known)
	if got, want := strings.Join(violations, ","), "a -> ent"; got != want {
		t.Errorf("violations = %q, want %q", got, want)
	}
	if len(stale) != 1 || !strings.HasPrefix(stale[0], "b -> gone") {
		t.Errorf("stale = %q, want the b -> gone exception", stale)
	}
}
