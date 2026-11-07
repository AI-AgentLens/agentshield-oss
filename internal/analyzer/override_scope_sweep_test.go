package analyzer_test

import (
	"regexp"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
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

// dnsSafeOverrideRules are the rules that carry the DNS-safe override: the two
// semantic rules and the premium pack rule keyed on their intent.
var dnsSafeOverrideRules = []string{"sem-allow-dns-safe", "sem-allow-dns-safe-recon", "ts-sem-allow-dns-safe"}

// dnsToolWord finds the first dig/nslookup/host word in command position.
var dnsToolWord = regexp.MustCompile("(?:^|[\\s;&|(`])(?:dig|nslookup|host)(\\s+)")

// insertDNSEarnerOperand inserts the DNS-safe earner's name as an extra
// operand right after the first dig/nslookup/host word, or reports false when
// the command has none.
func insertDNSEarnerOperand(command string) (string, bool) {
	loc := dnsToolWord.FindStringSubmatchIndex(command)
	if loc == nil {
		return "", false
	}
	at := loc[3] // end of the whitespace after the tool word
	return command[:at] + "_dmarc.example.com " + command[at:], true
}

// TestOverrideCannotSilenceAnotherOperand is the same-segment sibling of
// TestOverrideCannotSilenceAnotherStatement (#4594). The DNS-safe override
// vouches for a whole dig/nslookup/host invocation, so one security-record
// operand must never earn it for an invocation that also queries another
// name. For every BLOCKing corpus TP with a dig/nslookup/host word, insert the
// earner's name as an extra operand of that word, and require that the
// decision does not drop and that no DNS-safe override rule is cited.
func TestOverrideCannotSilenceAnotherOperand(t *testing.T) {
	// The probe floor is sized to the premium DNS BLOCK rules
	// (ne-block-dns-exfil-var-indirect, ne-block-dns-zone-transfer): the OSS
	// tree leaves 10 probes, which would trip it.
	ossbuild.SkipPremiumSized(t)
	engine := newPipelineEngine(t)

	// Positive controls. The earner earns the override on its own, and the
	// inserted operand does not void it by itself: inserted into a lookup
	// whose operands are all safe, the override is still earned. Without the
	// second, a broken insertion would pass the sweep below for the wrong
	// reason.
	if got := engine.Evaluate("dig _dmarc.example.com TXT", nil); !containsRule(got.TriggeredRules, "sem-allow-dns-safe") {
		t.Fatalf("control: the earner did not trigger sem-allow-dns-safe (got %s %v)", got.Decision, got.TriggeredRules)
	}
	safe, ok := insertDNSEarnerOperand("dig _spf.example.com TXT")
	if !ok {
		t.Fatal("control: insertion found no dig word")
	}
	if got := engine.Evaluate(safe, nil); !containsRule(got.TriggeredRules, "sem-allow-dns-safe") {
		t.Fatalf("control: %q lost the override (got %s %v); the sweep would be vacuous", safe, got.Decision, got.TriggeredRules)
	}

	probes, lowered, cited := 0, 0, 0
	for _, tc := range testdata.AllTestCases() {
		if tc.Classification != "TP" || tc.ExpectedDecision != "BLOCK" {
			continue
		}
		variant, ok := insertDNSEarnerOperand(tc.Command)
		if !ok {
			continue
		}
		bare := engine.Evaluate(tc.Command, nil)
		if bare.Decision != "BLOCK" {
			continue // the TP's own grader owns that
		}
		probes++
		got := engine.Evaluate(variant, nil)
		if decisionRankForSweep(string(got.Decision)) < decisionRankForSweep(string(bare.Decision)) {
			lowered++
			t.Errorf("%s: inserting the earner's name lowered %s to %s (%v)\n  command: %q",
				tc.ID, bare.Decision, got.Decision, got.TriggeredRules, variant)
			continue
		}
		for _, rule := range dnsSafeOverrideRules {
			if containsRule(got.TriggeredRules, rule) {
				cited++
				t.Errorf("%s: the receipt cites %s for a command that also queries another name (%s %v)\n  command: %q",
					tc.ID, rule, got.Decision, got.TriggeredRules, variant)
				break
			}
		}
	}
	if probes < 15 {
		t.Fatalf("only %d probes; the TP population or the insertion is broken, not clean", probes)
	}
	t.Logf("same-invocation override sweep: %d probes, %d lowered, %d citing the override", probes, lowered, cited)
}

func containsRule(rules []string, id string) bool {
	for _, r := range rules {
		if r == id {
			return true
		}
	}
	return false
}
