package archtest

import (
	"go/parser"
	"strconv"
	"strings"
	"testing"
)

// stdlibOnly are packages that may import nothing but the standard library:
// not this module's other packages, and no third-party module.
var stdlibOnly = map[string]string{
	// ADR-001: the routing table decides which lanes read a tool call. It
	// knows harness and tool names, never a grammar or a rule, so every entry
	// point can link it and no lane can reach back into it (#4245).
	"internal/route": "tool-call routing table (ADR-001)",
	// #4785: every evaluating package checks the hook's stop flag in its hot
	// loops, so the flag can depend on nothing they could depend on.
	"internal/abandon": "the hook's evaluation stop flag (#4785)",
}

// isStdlib reports whether an import path names a standard-library package:
// the go command's own rule, a first path element with no dot. "C" (cgo) is
// not a package of the standard library.
func isStdlib(path string) bool {
	first, _, _ := strings.Cut(path, "/")
	return path != "C" && !strings.Contains(first, ".")
}

func TestStdlibOnlyPackages(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range moduleFiles(t, moduleRoot(t), parser.ImportsOnly) {
		if _, ok := stdlibOnly[f.pkg]; !ok {
			continue
		}
		seen[f.pkg] = true
		for _, spec := range f.file.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatalf("%s: unreadable import %s", f.rel, spec.Path.Value)
			}
			if !isStdlib(p) {
				t.Errorf("%s imports %q; %s may import only the standard library (%s)", f.rel, p, f.pkg, stdlibOnly[f.pkg])
			}
		}
	}
	for pkg := range stdlibOnly {
		if !seen[pkg] {
			t.Errorf("stdlibOnly names %q, which has no non-test Go files: fix or delete the entry", pkg)
		}
	}
}

// TestIsStdlib_SelfTest: the predicate must refuse this module, third-party
// modules and cgo, or TestStdlibOnlyPackages passes on anything.
func TestIsStdlib_SelfTest(t *testing.T) {
	for path, want := range map[string]bool{
		"slices":                        true,
		"net/http":                      true,
		"encoding/json":                 true,
		modulePath + "/internal/policy": false,
		"github.com/spf13/cobra":        false,
		"gopkg.in/yaml.v3":              false,
		"mvdan.cc/sh/v3/syntax":         false,
		"C":                             false,
	} {
		if got := isStdlib(path); got != want {
			t.Errorf("isStdlib(%q) = %v, want %v", path, got, want)
		}
	}
}
