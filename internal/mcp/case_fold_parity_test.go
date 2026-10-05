package mcp

import (
	"fmt"
	"hash/fnv"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp/scenarios"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// MCP half of the #4194 fitness function. A file tool's path argument with
// its letter case changed names the same file on APFS/NTFS, so it must decide
// no lower than its canonical spelling. The issue measured
// `/Users/<u>/.SSH/id_rsa` at AUDIT (no rule) against a three-rule BLOCK for
// the lower-case spelling.
//
// Probes: every tool-call scenario and every MCP pack inline TP (community and
// premium, rules and structural rules) whose arguments carry a home-rooted
// path. Variants re-case the part after the home root three ways, as the shell
// sweep does (internal/analyzer/case_fold_parity_test.go).

var mcpCaseFoldHomeTok = regexp.MustCompile(`(~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/Users/[^/\s]+|/var/root|/root)/[A-Za-z0-9._/+@,:=%-]+`)

var mcpCaseFoldVariants = []struct {
	name string
	fn   func(string) string
}{
	{"upper", func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if c >= 'a' && c <= 'z' {
				b[i] = c - ('a' - 'A')
			}
		}
		return string(b)
	}},
	{"title", func(s string) string {
		segs := strings.Split(s, "/")
		for i := range segs {
			segs[i] = mcpUpperFirst(segs[i])
		}
		return strings.Join(segs, "/")
	}},
	{"one", func(s string) string {
		seg, rest, found := strings.Cut(s, "/")
		if found {
			return mcpUpperFirst(seg) + "/" + rest
		}
		return mcpUpperFirst(seg)
	}},
}

func mcpUpperFirst(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'a' && c <= 'z' {
			return s[:i] + string(c-('a'-'A')) + s[i+1:]
		}
	}
	return s
}

// mcpCaseVariant re-cases every home-rooted path in every string value;
// changed reports whether anything moved.
func mcpCaseVariant(v interface{}, fn func(string) string) (out interface{}, changed bool) {
	switch t := v.(type) {
	case string:
		res := mcpCaseFoldHomeTok.ReplaceAllStringFunc(t, func(tok string) string {
			root := mcpCaseFoldHomeTok.FindStringSubmatch(tok)[1]
			return root + "/" + fn(tok[len(root)+1:])
		})
		return res, res != t
	case map[string]interface{}:
		m := make(map[string]interface{}, len(t))
		for k, x := range t {
			y, c := mcpCaseVariant(x, fn)
			m[k] = y
			changed = changed || c
		}
		return m, changed
	case []interface{}:
		a := make([]interface{}, len(t))
		for i, x := range t {
			y, c := mcpCaseVariant(x, fn)
			a[i] = y
			changed = changed || c
		}
		return a, changed
	}
	return v, false
}

type mcpCaseFoldProbe struct {
	id, tool string
	args     map[string]interface{}
}

func mcpCaseFoldProbes(t *testing.T) []mcpCaseFoldProbe {
	t.Helper()
	var out []mcpCaseFoldProbe
	seen := map[string]bool{}
	add := func(id, tool string, args map[string]interface{}) {
		if tool == "" || len(args) == 0 {
			return
		}
		if _, changed := mcpCaseVariant(args, func(s string) string { return s + "\x00" }); !changed {
			return // no home-rooted path anywhere in the arguments
		}
		key := tool + "|" + fmt.Sprint(args)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, mcpCaseFoldProbe{id, tool, args})
	}
	for _, s := range scenarios.AllScenarios() {
		add(s.ID, s.ToolName, s.Arguments)
	}
	addTests := func(id string, tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for i, tc := range tests.TP {
			args, err := tc.ResolvedArgs()
			if err != nil {
				t.Fatalf("%s TP-%d: %v", id, i+1, err)
			}
			add(fmt.Sprintf("%s/TP-%d", id, i+1), tc.Tool, args)
		}
	}
	for _, r := range append(loadAllMCPRules(t), loadAllPremiumMCPRules(t)...) {
		addTests(r.ID, r.Tests)
	}
	for _, r := range append(loadAllMCPStructuralRules(t), loadAllPremiumMCPStructuralRules(t)...) {
		addTests(r.ID, r.Tests)
	}
	return out
}

// mcpCaseFoldKnownGaps is the residual, keyed "<probe id>|<variant>": a path
// whose canonical spelling carries a VENDOR's capitals — Jupyter's
// `~/Library/Jupyter`, JetBrains' `IntelliJIdea2024.1`, Homebrew's
// `Library/Taps/…/Formula`, Claude Code's `CLAUDE.md` — matched by a regex
// predicate written in that case (args_match pattern_any,
// argument_regex_patterns). The folded reading folds glob patterns on both
// sides, so mixed-case GLOBS are closed; a regex cannot be folded that way.
// None of these is a credential path: they are persistence and supply-chain
// rules. Same class, and the same open decision, as the shell sweep's
// caseFoldKnownGaps. Ratchet DOWN: 10 of 4,166 variants at measurement
// (2026-10-05); the as-written pass leaks 3,545.
var mcpCaseFoldKnownGaps = map[string]bool{
	"MCP-TN-057|upper":      true,
	"MCP-TP-1424-006|upper": true,
	"MCP-TP-783|upper":      true,
	"mcp-persist-block-ide-extension-dir-write/TP-5|upper": true,
	"mcp-persist-block-jupyter-extension-write/TP-5|upper": true,
	"mcp-persist-block-jupyter-extension-write/TP-6|upper": true,
	"mcp-persist-block-jupyter-kernel-write/TP-5|upper":    true,
	"mcp-persist-block-jupyter-kernel-write/TP-6|one":      true,
	"mcp-persist-block-jupyter-kernel-write/TP-6|title":    true,
	"mcp-persist-block-jupyter-kernel-write/TP-6|upper":    true,
}

func TestMCPCaseFoldCredentialPathParity(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	// asWritten is the pre-#4194 verdict: the same rule pass with no folded
	// reading. It is both the positive control (it must leak) and the floor
	// the production verdict may never fall below (raise-only).
	asWritten := func(tool string, args map[string]interface{}) policy.Decision {
		return ev.evaluateArguments(tool, args, "", nil, false).Decision
	}
	probes := mcpCaseFoldProbes(t)
	var unexpected, relaxed []string
	stillOpen := map[string]bool{}
	evaluated, blockCanon, offLeaks := 0, 0, 0
	for _, p := range probes {
		canon := ev.EvaluateToolCall(p.tool, p.args).Decision
		// An MCP evaluation costs ~5ms and the package already runs for
		// minutes, so every probe gets the upper-case variant and one probe in
		// four the other two as well — chosen by a hash of the probe id, so
		// adding a fixture never reshuffles which variants the others get
		// (the known-gap keys below stay stable).
		h := fnv.New32a()
		h.Write([]byte(p.id))
		allVariants := h.Sum32()%4 == 0
		for vi, v := range mcpCaseFoldVariants {
			if vi > 0 && !allVariants {
				continue
			}
			va, changed := mcpCaseVariant(p.args, v.fn)
			if !changed {
				continue
			}
			args := va.(map[string]interface{})
			evaluated++
			if canon == policy.DecisionBlock {
				blockCanon++
			}
			key := p.id + "|" + v.name
			got := ev.EvaluateToolCall(p.tool, args).Decision
			if decisionSeverity(got) < decisionSeverity(canon) {
				if mcpCaseFoldKnownGaps[key] {
					stillOpen[key] = true
				} else {
					unexpected = append(unexpected, fmt.Sprintf("%s: %s -> %s : %s %v", key, canon, got, p.tool, args))
				}
			}
			off := asWritten(p.tool, args)
			if decisionSeverity(off) < decisionSeverity(canon) {
				offLeaks++
			}
			if decisionSeverity(got) < decisionSeverity(off) {
				relaxed = append(relaxed, fmt.Sprintf("%s: %s -> %s", key, off, got))
			}
		}
	}
	if evaluated < 3000 {
		t.Fatalf("MCP case-fold sweep evaluated only %d variants (floor 3000) — the probe extraction stopped matching", evaluated)
	}
	t.Logf("MCP case-fold parity: %d probes, %d variants (%d of BLOCK canonicals); %d unexpected leaks, %d pinned; fold OFF leaked %d; %d relaxed",
		len(probes), evaluated, blockCanon, len(unexpected), len(stillOpen), offLeaks, len(relaxed))
	if offLeaks < blockCanon/2 {
		t.Errorf("positive control too weak: the as-written reading lowered only %d of %d variants — the sweep may no longer see the #4194 bypass", offLeaks, blockCanon)
	}
	if len(relaxed) > 0 {
		t.Errorf("the folded reading LOWERED %d verdict(s) below the as-written pass — the raise-only construction is broken:\n  %s", len(relaxed), strings.Join(relaxed, "\n  "))
	}
	if len(unexpected) > 0 {
		sort.Strings(unexpected)
		t.Errorf("%d MCP case variant(s) decided lower than the canonical spelling (#4194):\n  %s", len(unexpected), strings.Join(unexpected, "\n  "))
	}
	for key := range mcpCaseFoldKnownGaps {
		if !stillOpen[key] {
			t.Errorf("known gap %q no longer leaks — remove it (ratchet down)", key)
		}
	}
}

// TestFoldPathArgumentsDoesNotMutate: the folded reading works on a copy. The
// proxy forwards the caller's arguments verbatim, so folding them in place
// would rewrite the tool call the server receives.
func TestFoldPathArgumentsDoesNotMutate(t *testing.T) {
	in := map[string]interface{}{
		"path":  "/Users/U/.Cfg/X",
		"paths": []interface{}{"/Users/U/A", map[string]interface{}{"p": "~/B"}},
		"n":     3.0,
	}
	before := fmt.Sprint(in)
	out, ok := foldPathArguments(in)
	if !ok {
		t.Fatal("expected a fold")
	}
	if fmt.Sprint(in) != before {
		t.Fatalf("input mutated: %v", in)
	}
	if out["path"] != "/Users/u/.cfg/x" || out["n"] != 3.0 {
		t.Fatalf("unexpected fold: %v", out)
	}
	if _, ok := foldPathArguments(map[string]interface{}{"path": "/already/lower", "n": 1.0}); ok {
		t.Fatal("nothing to fold must report false so the second pass is skipped")
	}
}
