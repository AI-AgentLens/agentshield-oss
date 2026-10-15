package mcp

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// #4255: splitPath was O(depth²) — it walked the path backwards with
// filepath.Split, re-Cleaned the remaining directory each step and prepended
// each component — and matchGlobLiteral calls it once per path-glob rule, so
// one 4,000-character path cost ~15 s of evaluation. The linear version must
// return EXACTLY what the old walk returned for every input: a component that
// differs is a glob that matches differently, and a missed match is a silent
// fail-open. The old implementation is kept here, verbatim, as the reference.

func splitPathQuadraticReference(p string) []string {
	p = filepath.Clean(p)
	if p == "/" || p == "." {
		return nil
	}
	var parts []string
	for {
		dir, file := filepath.Split(p)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		dir = filepath.Clean(dir)
		if dir == p || dir == "." {
			break
		}
		p = dir
	}
	return parts
}

var splitPathEdgeCases = []string{
	"", ".", "..", "/", "//", "///", "/..", "/../..", "../x", "../../x/y", "./x", "x/./y",
	"a", "a/", "a//b", "/a", "/a/", "//a//b/", "/a/./b/../c", "/a/b/../../..",
	"~", "~/", "~/.ssh/id_rsa", "$HOME/.aws/credentials", "/home/user/.ssh/id_rsa",
	"https://example.com", "https://example.com/x/y", "s3://bucket/key", "file:///etc/passwd",
	`C:\Users\dev\.ssh\id_rsa`, "C:/Users/dev/.ssh", `\\host\share\f`, "%USERPROFILE%/.aws",
	"a b/c d", "/tmp/x\x00y", "/usr/lib/node_modules/.bin", "**/x", "/a/*/b", "...", "/.../a",
	"/\u00e9t\u00e9/\u65e5\u672c", "/a/\u200b/b",
}

func TestSplitPathMatchesQuadraticReference(t *testing.T) {
	// The 3000-value floor is sized to the full packs' fixtures; the community
	// packs carry about 2,300.
	ossbuild.SkipPremiumSized(t)
	check := func(p string) bool {
		got, want := splitPath(p), splitPathQuadraticReference(p)
		if len(got) == 0 && len(want) == 0 {
			return true // nil and empty are the same for every caller
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("splitPath(%q) = %q, reference %q", p, got, want)
			return false
		}
		return true
	}
	for _, p := range splitPathEdgeCases {
		check(p)
	}
	for _, depth := range []int{1, 2, 3, 10, 100, 500} {
		check("/" + strings.Repeat("d/", depth) + "f")
		check(strings.Repeat("d/", depth) + "f")
		check("/" + strings.Repeat("a/../", depth) + ".ssh/id_rsa")
	}

	// Every string value carried by every inline fixture of every loaded
	// pack: thousands of real path, URL and prose arguments.
	ev := newTestMCPEvaluator(t)
	values := 0
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch x := v.(type) {
		case string:
			values++
			check(x)
		case map[string]interface{}:
			for _, y := range x {
				walk(y)
			}
		case []interface{}:
			for _, y := range x {
				walk(y)
			}
		}
	}
	collect := func(tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for _, tc := range append(append([]MCPTestCase{}, tests.TP...), tests.TN...) {
			if args, err := tc.ResolvedArgs(); err == nil {
				walk(map[string]interface{}(args))
			}
		}
	}
	for _, r := range ev.policy.Rules {
		collect(r.Tests)
	}
	for _, r := range ev.policy.StructuralRules {
		collect(r.Tests)
	}
	if values < 3000 {
		t.Fatalf("only %d fixture values compared — extraction stopped matching (floor 3000)", values)
	}
	t.Logf("splitPath agrees with the reference on %d edge cases and %d fixture values", len(splitPathEdgeCases), values)
}

// FuzzSplitPathMatchesQuadraticReference: `go test -fuzz` explores further;
// the seed corpus runs as an ordinary test on every CI run.
func FuzzSplitPathMatchesQuadraticReference(f *testing.F) {
	for _, p := range splitPathEdgeCases {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, want := splitPath(p), splitPathQuadraticReference(p)
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("splitPath(%q) = %q, reference %q", p, got, want)
		}
	})
}

// TestSplitPathIsLinear: at depth 20,000 the quadratic walk takes seconds per
// call; the linear split takes about a millisecond. The 250 ms budget leaves a
// wide margin on a loaded CI runner while still failing the quadratic version
// by an order of magnitude.
func TestSplitPathIsLinear(t *testing.T) {
	p := "/" + strings.Repeat("d/", 20000) + "f"
	start := time.Now()
	parts := splitPath(p)
	elapsed := time.Since(start)
	if len(parts) != 20001 {
		t.Fatalf("got %d components, want 20001", len(parts))
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("splitPath at depth 20,000 took %v (budget 250ms) — quadratic again? (#4255)", elapsed)
	}
}

// TestDeepPathEvaluationBudget is the end-to-end version on the shipped
// packs: a depth-2,000 path through every path-glob rule. On main before
// #4255 this took ~15 s.
func TestDeepPathEvaluationBudget(t *testing.T) {
	ev := newTestMCPEvaluator(t)
	p := "/" + strings.Repeat("d/", 2000) + "file.txt"
	for _, call := range []struct{ tool, key string }{{"read_file", "path"}, {"Read", "file_path"}} {
		start := time.Now()
		ev.EvaluateToolCall(call.tool, map[string]interface{}{call.key: p})
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("%s of a depth-2,000 path took %v (budget 3s; ~15 s when splitPath was quadratic, #4255)", call.tool, elapsed)
		}
	}
}
