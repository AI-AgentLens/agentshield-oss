package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestUncategorizedRules_PolicyAndPacks: rules without a taxonomy node are
// found in both the local policy file and the on-disk packs; categorized rules
// are not reported.
func TestUncategorizedRules_PolicyAndPacks(t *testing.T) {
	dir := t.TempDir()
	pol := writePolicyFile(t, dir, "policy.yaml", `version: "0.1"
rules:
  - id: "co-block-prod-db"
    match:
      command_regex: "psql.*prod"
    decision: "BLOCK"
    reason: "no category"
  - id: "co-block-prod-db-mapped"
    taxonomy: "credential-exposure/database-access/database-credential-access"
    match:
      command_regex: "mysql.*prod"
    decision: "BLOCK"
    reason: "has a category"
`)
	packs := filepath.Join(dir, "packs")
	if err := os.MkdirAll(packs, 0o755); err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, packs, "co-acme.yaml", `name: "Acme"
rules:
  - id: "co-audit-deploy"
    match:
      command_regex: "^acmectl\\s+deploy\\b"
    decision: "AUDIT"
    reason: "no category"
  - id: "co-audit-deploy-mapped"
    taxonomy: "governance-risk/ai-governance-gap/agent-autonomous-production-deployment"
    match:
      command_regex: "^acmectl\\s+release\\b"
    decision: "AUDIT"
    reason: "has a category"
  - id: "co-allow-acmectl-status"
    match:
      command_regex: "^acmectl\\s+status\\b"
    decision: "ALLOW"
    reason: "an allow is not evidence"
`)
	// A shipped pack rule (no co- prefix) the user can't edit: not reported.
	writePolicyFile(t, packs, "terminal-safety-advanced.yaml", `name: "Shipped"
rules:
  - id: "ts-sem-block-high-risk"
    match:
      semantic:
        risk_min: critical
    decision: "BLOCK"
    reason: "shipped catch-all"
`)

	got := uncategorizedRules(pol, packs)
	slices.Sort(got)
	want := []string{"co-audit-deploy", "co-block-prod-db"}
	if !slices.Equal(got, want) {
		t.Fatalf("uncategorizedRules = %v, want %v", got, want)
	}
}

// TestUncategorizedRules_MissingFiles: no policy file and no packs dir is not
// an error and reports nothing.
func TestUncategorizedRules_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	if got := uncategorizedRules(filepath.Join(dir, "none.yaml"), filepath.Join(dir, "no-packs")); len(got) != 0 {
		t.Fatalf("uncategorizedRules = %v, want none", got)
	}
}

func TestListSome(t *testing.T) {
	if got := listSome([]string{"a", "b"}, 5); got != "a, b" {
		t.Errorf("listSome(2 of 5) = %q", got)
	}
	if got := listSome([]string{"a", "b", "c"}, 2); got != "a, b and 1 more" {
		t.Errorf("listSome(3 of 2) = %q", got)
	}
}

// TestPrintShellResult_NoTaxonomyNote: the note appears only when rules fired
// and none of them named a taxonomy node.
func TestPrintShellResult_NoTaxonomyNote(t *testing.T) {
	const note = "maps to no compliance control"
	cases := []struct {
		name string
		r    policy.EvalResult
		want bool
	}{
		{"rule without taxonomy", policy.EvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"co-block-prod-db"}}, true},
		{"rule with taxonomy", policy.EvalResult{Decision: policy.DecisionBlock, TriggeredRules: []string{"co-block-prod-db"},
			TaxonomyRefs: []string{"credential-exposure/database-access/database-credential-access"}}, false},
		{"no rule fired", policy.EvalResult{Decision: policy.DecisionAllow}, false},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		printShellResult(&buf, c.r)
		if got := strings.Contains(buf.String(), note); got != c.want {
			t.Errorf("%s: note shown = %v, want %v\n%s", c.name, got, c.want, buf.String())
		}
	}
}

// TestCheckPolicy_UncategorizedRuleHasNoTaxonomyRefs pins the engine fact the
// note relies on: a rule with no taxonomy contributes no taxonomy ref.
func TestCheckPolicy_UncategorizedRuleHasNoTaxonomyRefs(t *testing.T) {
	home := withFakeHomeForCheck(t)
	pol := writePolicyFile(t, home, "rule.yaml", `version: "0.1"
defaults:
  decision: "ALLOW"
rules:
  - id: "co-block-acmectl-wipe"
    decision: "BLOCK"
    reason: "no category"
    match:
      command_regex: "^acmectl\\s+wipe\\b"
`)
	r, err := evaluateShellCommand("acmectl wipe all", pol)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.TriggeredRules, "co-block-acmectl-wipe") || len(r.TaxonomyRefs) != 0 {
		t.Fatalf("want the rule to fire with no taxonomy refs; got rules=%v taxonomy=%v", r.TriggeredRules, r.TaxonomyRefs)
	}
}
