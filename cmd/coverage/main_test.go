package main

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/rulecount"
)

func fixtureReport(t *testing.T) *rulecount.Report {
	t.Helper()
	r, err := rulecount.Count("../../internal/rulecount/testdata/packs")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func rows(n int, matchType string) []flatRule {
	out := make([]flatRule, n)
	for i := range out {
		out[i] = flatRule{ID: "r", MatchType: matchType, Kingdom: "k"}
	}
	return out
}

// Fixture corpus: 6 shell, 7 mcp. Blocked tools and Go intercepts in the
// catalog do not count toward either.
func TestReconcile_AgreesWhenCatalogMatchesCount(t *testing.T) {
	r := fixtureReport(t)
	mcp := append(rows(7, "mcp_rule"), rows(2, matchBlockedTool)...)
	mcp = append(mcp, rows(2, matchGoIntercept)...)
	if err := reconcile(rows(6, "regex"), mcp, r); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_FailsWhenCatalogSkipsASection(t *testing.T) {
	r := fixtureReport(t)
	// The pre-2026-09-28 shape: semantic_rules not parsed, blocked tools counted.
	mcp := append(rows(6, "mcp_rule"), rows(2, matchBlockedTool)...)
	err := reconcile(rows(6, "regex"), mcp, r)
	if err == nil || !strings.Contains(err.Error(), "6 MCP YAML rules but rulecount says 7") {
		t.Fatalf("want a 6 vs 7 disagreement, got %v", err)
	}
	if err := reconcile(rows(5, "regex"), rows(7, "mcp_rule"), r); err == nil {
		t.Fatal("terminal disagreement must be refused")
	}
}

// The Summary reads its totals from the count, not from len(catalog), and
// says what the non-rule rows are.
func TestSummary_ComesFromRulecount(t *testing.T) {
	r := fixtureReport(t)
	mcp := append(rows(7, "mcp_rule"), rows(2, matchBlockedTool)...)
	mcp = append(mcp, rows(2, matchGoIntercept)...)
	out := generateReport(rows(6, "regex"), mcp, nil, r)
	for _, want := range []string{
		"| Terminal rules (community 3 + premium 3) | 6 |",
		"| MCP rules (community 5 + premium 2) | 7 |",
		"| Total rules | 13 |",
		"| Unique rule ids | 12 |",
		"| Rule ids defined more than once | 1 |",
		"| MCP blocked tools (enforcement, not rules) | 2 |",
		"| Go-implemented MCP intercepts (enforcement, not rules) | 2 |",
		rulecount.Definition,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q\n%s", want, out[:strings.Index(out, "## Runtime")])
		}
	}
}

// A kingdom heading counts rules the same way the Summary does, and says
// what the other rows are — it can no longer read "(11 rules)" over 7 rules,
// 2 blocked tools and 2 intercepts.
func TestKingdomHeading_ExcludesEnforcementRowsFromRuleCount(t *testing.T) {
	mcp := append(rows(7, "mcp_rule"), rows(2, matchBlockedTool)...)
	mcp = append(mcp, rows(2, matchGoIntercept)...)
	if got, want := kingdomHeading("k", mcp), "k (7 rules + 4 enforcement entries — blocked tools / Go intercepts, not counted as rules)"; got != want {
		t.Errorf("heading = %q, want %q", got, want)
	}
	if got, want := kingdomHeading("k", rows(3, "regex")), "k (3 rules)"; got != want {
		t.Errorf("heading = %q, want %q", got, want)
	}
	// Headings across the whole report sum to the Summary's MCP total.
	r := fixtureReport(t)
	out := generateReport(rows(6, "regex"), mcp, nil, r)
	if !strings.Contains(out, "### k (7 rules + 4 enforcement entries") {
		t.Errorf("report heading missing\n%s", out)
	}
}
