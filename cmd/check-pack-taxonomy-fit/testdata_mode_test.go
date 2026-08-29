package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
)

// TestTestdataGroupKey pins the ID -> group-key derivation against the exact
// #3336 motivating example: PKGPUB and PKGPUB-SUDO are siblings that share a
// naive prefix but were correctly split into two testdata blocks with two
// different (one wrong, one right) TaxonomyRefs. A grouping key that merged
// them back into one group would have hidden the very defect this gate
// exists to catch.
func TestTestdataGroupKey(t *testing.T) {
	cases := []struct{ id, want string }{
		{"TP-PKGPUB-001", "PKGPUB"},
		{"TP-PKGPUB-SUDO-001", "PKGPUB-SUDO"},
		{"FN-FSDESTR-002", "FSDESTR"},
		{"TP-ANSIC-SPLIT-003", "ANSIC-SPLIT"},
		{"solo", "solo"},
		{"TP-X-001", "X"},
	}
	for _, c := range cases {
		if got := testdataGroupKey(c.id); got != c.want {
			t.Errorf("testdataGroupKey(%q) = %q, want %q", c.id, got, c.want)
		}
	}
}

// TestLoadTestdataRefsExcludesNonTP — a TN case is deliberately unlike its
// node (the benign command a real rule must not fire on), so scoring it the
// same way as a positive assertion would manufacture misfits out of the
// fixture's own design. Only Classification == "TP" cases may vote.
func TestLoadTestdataRefsExcludesNonTP(t *testing.T) {
	refs, nRules, err := loadTestdataRefs()
	if err != nil {
		t.Fatal(err)
	}

	wantRules := 0
	wantIDs := map[string]bool{}
	for _, tc := range testdata.AllTestCases() {
		if tc.Classification == "TP" && tc.TaxonomyRef != "" {
			wantRules++
			wantIDs[tc.ID] = true
		}
	}
	if nRules != wantRules {
		t.Errorf("loadTestdataRefs nRules = %d, want %d (TP cases with a TaxonomyRef)", nRules, wantRules)
	}

	seenIDs := map[string]bool{}
	for _, rs := range refs {
		for _, r := range rs {
			for _, rule := range r.Rules {
				seenIDs[rule.ID] = true
			}
		}
	}
	for id := range seenIDs {
		if !wantIDs[id] {
			t.Errorf("loadTestdataRefs included non-TP or ref-less case %q", id)
		}
	}
	if len(seenIDs) != len(wantIDs) {
		t.Errorf("loadTestdataRefs surfaced %d case IDs, want %d", len(seenIDs), len(wantIDs))
	}
}

// TestLoadTestdataRefsDeterminism mirrors TestDeterminism for the pack-side
// loader: same corpus in, same grouping out, on every run.
func TestLoadTestdataRefsDeterminism(t *testing.T) {
	first, _, err := loadTestdataRefs()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		got, _, err := loadTestdataRefs()
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("run %d: loadTestdataRefs is not deterministic", i)
		}
	}
}

// TestTestdataModeEmptyTaxonomyIsAnError — the -testdata gate must be able to
// fail the same way the pack-side gate does (CLAUDE.md, "Gates must be able
// to fail", #3130): an empty taxonomy tree is a broken invocation, not a
// clean corpus.
func TestTestdataModeEmptyTaxonomyIsAnError(t *testing.T) {
	if _, err := analyze(t.TempDir(), "unused", testGenericDF, testRuleGenericDF, testAltMinOverlap, true, false); err == nil {
		t.Error("empty taxonomy dir returned no error in -testdata mode")
	} else if !strings.Contains(err.Error(), "cannot vouch") {
		t.Errorf("unhelpful error for empty taxonomy: %v", err)
	}
}
