package mcp

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// #4387, MCP side: on macOS /etc, /var and /tmp are symlinks into /private,
// so a tool call naming `/private/etc/shadow` reads `/etc/shadow`. The
// argument rules are authored against the short spelling. The fix is a fourth
// argument reading under the raise-only construction of #4194 and #4243.

// mcpAliasOpener / mcpAliasEnd mirror the shell ratchet's variant generator
// (internal/analyzer/private_alias_parity_test.go), kept local so the
// generator does not share the production canonicalizer's blind spots.
func mcpAliasOpener(c byte) bool { return strings.IndexByte(" \t\n'\"=:@,{(<>|;&`", c) >= 0 }
func mcpAliasEnd(c byte) bool    { return strings.IndexByte("/ \t\n'\"),;&|<>`}", c) >= 0 }

// mcpAliasRoots are the roots production reads short; /tmp is the third
// macOS alias and is deliberately not read short (pathnorm.CanonicalPrivateAlias).
var mcpAliasRoots = []string{"etc", "var"}

// mcpAliasVariant inserts `/private` before every anchored root segment of
// roots in s; "" when s has none.
func mcpAliasVariant(s string, roots []string) string {
	var b strings.Builder
	last, n := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] != '/' || (i > 0 && !mcpAliasOpener(s[i-1])) {
			continue
		}
		for _, root := range roots {
			end := i + 1 + len(root)
			if strings.HasPrefix(s[i+1:], root) && (end == len(s) || mcpAliasEnd(s[end])) {
				b.WriteString(s[last:i])
				b.WriteString("/private")
				last = i
				n++
				break
			}
		}
	}
	if n == 0 {
		return ""
	}
	b.WriteString(s[last:])
	return b.String()
}

// mcpAliasArgs rewrites every string value of args with mcpAliasVariant.
func mcpAliasArgs(args map[string]interface{}, roots []string) (map[string]interface{}, bool) {
	return mapArgumentStrings(args, func(s string) string { return mcpAliasVariant(s, roots) })
}

type mcpAliasProbe struct {
	id, tool string
	args     map[string]interface{}
}

// mcpAliasProbes is every inline TP of every MCP rule section that carries
// tests, whose arguments name an anchored system path.
func mcpAliasProbes(t *testing.T, ev *PolicyEvaluator, roots []string) []mcpAliasProbe {
	t.Helper()
	var out []mcpAliasProbe
	add := func(id string, tests *MCPRuleTest) {
		if tests == nil {
			return
		}
		for i, tc := range tests.TP {
			if tc.Tool == "" {
				continue
			}
			args, err := tc.ResolvedArgs()
			if err != nil {
				continue
			}
			if _, ok := mcpAliasArgs(args, roots); !ok {
				continue
			}
			out = append(out, mcpAliasProbe{fmt.Sprintf("%s/TP-%d", id, i+1), tc.Tool, args})
		}
	}
	p := ev.policy
	for _, r := range p.Rules {
		add(r.ID, r.Tests)
	}
	for _, r := range p.StructuralRules {
		add(r.ID, r.Tests)
	}
	for _, r := range p.SemanticRules {
		add(r.ID, r.Tests)
	}
	for _, r := range p.ValueLimits {
		add(r.ID, r.Tests)
	}
	return out
}

// mcpAliasKnownGaps is the residual the reading does not close, by probe id.
// Ratchet DOWN: an entry that stops leaking fails the test until removed.
var mcpAliasKnownGaps = map[string]bool{}

// TestPrivateAliasReading_ShippedMCPPacks is the MCP ratchet: the /private
// spelling of a system path in a BLOCKing tool call must BLOCK too.
func TestPrivateAliasReading_ShippedMCPPacks(t *testing.T) {
	t.Parallel()
	ev := newTestMCPEvaluator(t)
	probes := mcpAliasProbes(t, ev, mcpAliasRoots)
	evaluated := 0
	stillOpen := map[string]bool{}
	var leaks []string
	for _, p := range probes {
		base := ev.EvaluateToolCall(p.tool, p.args)
		if base.Decision != policy.DecisionBlock {
			continue
		}
		variant, _ := mcpAliasArgs(p.args, mcpAliasRoots)
		evaluated++
		got := ev.EvaluateToolCall(p.tool, variant)
		if got.Decision == policy.DecisionBlock {
			continue
		}
		if mcpAliasKnownGaps[p.id] {
			stillOpen[p.id] = true
			continue
		}
		leaks = append(leaks, fmt.Sprintf("%s: %s BLOCK -> %s %v : %v", p.id, p.tool, got.Decision, got.TriggeredRules, variant))
	}
	if evaluated < 1 {
		t.Fatalf("private-alias MCP sweep evaluated %d BLOCKing probes of %d — vacuous, not clean", evaluated, len(probes))
	}
	t.Logf("private-alias MCP sweep: %d probes with a system path, %d BLOCK, %d leaked", len(probes), evaluated, len(leaks))
	if len(leaks) > 0 {
		sort.Strings(leaks)
		t.Errorf("%d BLOCKing MCP tool call(s) decided lower with the macOS /private spelling of the same path (#4387):\n%s",
			len(leaks), strings.Join(leaks, "\n"))
	}
	for id := range mcpAliasKnownGaps {
		if !stillOpen[id] {
			t.Errorf("known gap %q no longer leaks — remove it from mcpAliasKnownGaps (ratchet down)", id)
		}
	}
}

// TestPrivateAliasReading_RaisesShortRule pins the mechanism with an inline
// rule, independent of pack churn: a rule authored against the short
// spelling fires on the /private spelling through the new reading only (the
// as-written pass is the positive control).
func TestPrivateAliasReading_RaisesShortRule(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
structural_rules:
  - id: t-short-path
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - '^/etc/agent-test\.conf$'
    decision: BLOCK
    reason: test
`)
	for _, v := range []string{"/private" + "/etc/agent-test.conf", "/PRIVATE" + "/etc/agent-test.conf", "/private" + "/ETC/agent-test.conf"} {
		args := map[string]interface{}{"path": v}
		if got := ev.evaluateArguments("read_file", args, "", nil, false).Decision; got == policy.DecisionBlock {
			t.Fatalf("positive control: the as-written reading already BLOCKs %q", v)
		}
		if got := ev.EvaluateToolCall("read_file", args); got.Decision != policy.DecisionBlock || got.TriggeredRules[0] != "t-short-path" {
			t.Errorf("%q: got %s %v, want BLOCK by t-short-path", v, got.Decision, got.TriggeredRules)
		}
	}
}

// TestPrivateAliasReading_KeepsLiteralPrivateRules is the additive guard: a
// rule authored against the /private spelling (several shipped MCP packs carry
// such alternatives) matches only the as-written reading, and the short
// reading must not displace it.
func TestPrivateAliasReading_KeepsLiteralPrivateRules(t *testing.T) {
	ev := windowsSlashEvaluator(t, `
defaults:
  decision: AUDIT
structural_rules:
  - id: t-literal-private
    match:
      tool_name_regex: ".*"
      args_match:
        path:
          pattern_any:
            - '^/private/etc/agent-test\.conf$'
    decision: BLOCK
    reason: test
`)
	args := map[string]interface{}{"path": "/private" + "/etc/agent-test.conf"}
	short, ok := privateAliasArguments(args)
	if !ok {
		t.Fatal("expected the alias to be rewritten")
	}
	if got := ev.evaluateArguments("read_file", short, "", nil, false).Decision; got == policy.DecisionBlock {
		t.Fatalf("control: the short reading alone must not BLOCK (it is what a replacing rewrite would lose)")
	}
	if got := ev.EvaluateToolCall("read_file", args); got.Decision != policy.DecisionBlock || got.TriggeredRules[0] != "t-literal-private" {
		t.Errorf("literal /private rule lost: got %s %v", got.Decision, got.TriggeredRules)
	}
}

// TestPrivateAliasArguments_CopyAndScope: nested values are reached, the
// input is never mutated (the proxy forwards the caller's arguments
// verbatim), and non-alias values are left alone.
func TestPrivateAliasArguments_CopyAndScope(t *testing.T) {
	alias := "/private" + "/var/db/x"
	in := map[string]interface{}{
		"path": alias,
		"list": []interface{}{"/private" + "/var/tmp/a", map[string]interface{}{"p": "file://" + "/private" + "/etc/b"}},
		"n":    3.0,
	}
	before := fmt.Sprint(in)
	out, ok := privateAliasArguments(in)
	if !ok {
		t.Fatal("expected a rewrite")
	}
	if fmt.Sprint(in) != before {
		t.Fatalf("input mutated: %v", in)
	}
	want := map[string]interface{}{
		"path": "/var/db/x",
		"list": []interface{}{"/var/tmp/a", map[string]interface{}{"p": "file:///etc/b"}},
		"n":    3.0,
	}
	if fmt.Sprint(out) != fmt.Sprint(want) {
		t.Fatalf("got  %v\nwant %v", out, want)
	}
	for _, v := range []string{"/workspace/private/etc/x", "/private/etcetera", "/etc/hosts", "private/etc", "/private/tmp/a"} {
		if _, ok := privateAliasArguments(map[string]interface{}{"v": v}); ok {
			t.Errorf("%q must not be rewritten (not the alias)", v)
		}
	}
}
