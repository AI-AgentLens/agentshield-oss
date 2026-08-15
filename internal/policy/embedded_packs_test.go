package policy

import (
	"testing"
)

// TestLoadEmbeddedShellPacks_HasRules is a fitness function: it asserts that
// the binary always ships with a meaningful set of community shell rules
// baked in. If someone regresses the //go:embed directive in packs/packs.go
// (e.g. by narrowing the glob or deleting a pack file), this test fires loud
// and early — well before a release tarball ships with empty protection.
//
// Threshold: the floor tracks the real number rather than sitting an order of
// magnitude below it. It used to be 100 against ~819 actually embedded, which
// meant 87% of the community rule set could vanish and this test still passed
// — verified by mutation 2026-07-28: cutting both packs down to 4 rules total
// was caught, but any loss short of ~88% was not. A gate with 8x of slack is
// not measuring the invariant it claims ("the binary always ships with a
// meaningful set of community shell rules baked in"), it is measuring that the
// embed directive still resolves at all.
//
// Ratchet UP as the community set grows; lowering it is a deliberate scope
// change that belongs in the commit message.
const minEmbeddedCommunityRules = 700

func TestLoadEmbeddedShellPacks_HasRules(t *testing.T) {
	base := DefaultPolicy()
	merged, infos, err := LoadEmbeddedShellPacks(base)
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks failed: %v", err)
	}

	if len(infos) == 0 {
		t.Fatal("no embedded shell packs found — the //go:embed directive in packs/packs.go may have regressed")
	}

	if len(merged.Rules) <= len(base.Rules) {
		t.Fatalf("embedded packs added no rules: base=%d merged=%d", len(base.Rules), len(merged.Rules))
	}

	addedRules := len(merged.Rules) - len(base.Rules)
	if addedRules < minEmbeddedCommunityRules {
		t.Errorf("embedded shell packs contributed only %d rules (expected >= %d) — check packs/community/*.yaml",
			addedRules, minEmbeddedCommunityRules)
	}
	t.Logf("embedded community shell rules: %d (floor %d)", addedRules, minEmbeddedCommunityRules)
}

// TestLoadEmbeddedShellPacks_ExpectedPacks asserts that the specific community
// shell pack files we depend on are present. If one of these is ever renamed
// or removed intentionally, update the list — the test makes the change
// explicit rather than silent.
func TestLoadEmbeddedShellPacks_ExpectedPacks(t *testing.T) {
	_, infos, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("LoadEmbeddedShellPacks failed: %v", err)
	}

	found := make(map[string]bool)
	for _, info := range infos {
		found[info.Name] = true
	}

	// These are the packs we rely on for baseline coverage at the time of
	// writing. Match against the YAML "name:" field as surfaced by the loader.
	expected := []string{"Terminal Safety", "Secrets & PII Protection"}
	for _, e := range expected {
		if !found[e] {
			t.Errorf("expected embedded pack %q not found; loaded: %v", e, packNames(infos))
		}
	}
}

func packNames(infos []PackInfo) []string {
	names := make([]string, 0, len(infos))
	for _, i := range infos {
		names = append(names, i.Name)
	}
	return names
}

// TestLoadEmbeddedShellPacks_NoDiskTouch verifies the loader works without any
// ~/.agentshield/packs/ directory — the whole point of the embed is to remove
// the disk dependency that broke Linuxbrew onboarding.
func TestLoadEmbeddedShellPacks_NoDiskTouch(t *testing.T) {
	// No setup. No tmpdir. No filesystem at all. If this test passes, the
	// engine genuinely has zero runtime dependency on disk packs.
	merged, _, err := LoadEmbeddedShellPacks(DefaultPolicy())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(merged.Rules) == 0 {
		t.Fatal("merged policy has no rules — embed failed to contribute")
	}
}
