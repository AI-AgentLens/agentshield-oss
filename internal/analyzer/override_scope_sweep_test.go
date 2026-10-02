package analyzer_test

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// overrideEarners maps each taxonomy that has a structural or semantic ALLOW
// override to one harmless statement that earns it, and the override rule
// the statement must trigger on its own (the positive control).
var overrideEarners = map[string]struct{ stmt, rule string }{
	"destructive-ops/disk-ops/disk-overwrite":                {"dd if=/dev/zero of=/tmp/agentshield-sweep.img count=0", "st-allow-dd-to-file"},
	"destructive-ops/fs-destruction/system-directory-delete": {"rm -rf /tmp/agentshield-sweep-dir", "ts-allow-rm-tmp"},
	"data-exfiltration/network-egress/dns-tunneling":         {"dig _dmarc.example.com TXT", "sem-allow-dns-safe"},
	"reconnaissance/network-discovery/dns-lookup":            {"dig _dmarc.example.com TXT", "sem-allow-dns-safe-recon"},
}

func decisionRankForSweep(d string) int {
	switch d {
	case "BLOCK":
		return 3
	case "REQUIRE_APPROVAL":
		return 2
	case "AUDIT":
		return 1
	}
	return 0
}

// TestOverrideCannotSilenceAnotherStatement is the fitness function for #4000.
// An ALLOW override is keyed by taxonomy, not statement, so it must never
// lower the decision of a DIFFERENT statement in the same command. For every
// BLOCKing corpus TP whose taxonomy has an override, append that override's
// own harmless statement on a new line and require the decision not to drop.
func TestOverrideCannotSilenceAnotherStatement(t *testing.T) {
	engine := newPipelineEngine(t)

	// Positive control: each earner must earn its override on its own, or
	// the sweep below proves nothing.
	for tax, e := range overrideEarners {
		got := engine.Evaluate(e.stmt, nil)
		if !containsRule(got.TriggeredRules, e.rule) {
			t.Fatalf("control: %q (%s) did not trigger %s (got %s %v); the sweep would be vacuous",
				e.stmt, tax, e.rule, got.Decision, got.TriggeredRules)
		}
	}

	probes, lowered := 0, 0
	for _, tc := range testdata.AllTestCases() {
		if tc.Classification != "TP" || tc.ExpectedDecision != "BLOCK" {
			continue
		}
		e, ok := overrideEarners[tc.TaxonomyRef]
		if !ok {
			continue
		}
		bare := engine.Evaluate(tc.Command, nil)
		if bare.Decision != "BLOCK" {
			continue // the TP's own grader owns that
		}
		probes++
		combined := tc.Command + "\n" + e.stmt
		got := engine.Evaluate(combined, nil)
		if decisionRankForSweep(string(got.Decision)) < decisionRankForSweep(string(bare.Decision)) {
			lowered++
			t.Errorf("%s: appending the %s earner lowered %s to %s (%v)\n  command: %q",
				tc.ID, e.rule, bare.Decision, got.Decision, got.TriggeredRules, combined)
		}
	}
	if probes < 20 {
		t.Fatalf("only %d probes; the TP population or the taxonomy map is broken, not clean", probes)
	}
	t.Logf("override scope sweep: %d probes over %d override taxonomies, %d lowered", probes, len(overrideEarners), lowered)
}

func containsRule(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}
