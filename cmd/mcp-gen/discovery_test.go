package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A gate ships with a test that makes it FAIL (CLAUDE.md → "Gates must be able
// to fail (#3130)"). The floor in discovery.go exists because a scan that
// found nothing was indistinguishable from a scan with nothing to do for 96
// days (#3359), so these tests are split into two halves that fail for
// different reasons:
//
//   - mechanism  — synthetic trees with a small testSources floor, proving the
//     guard trips on empty / thin / renamed directories.
//   - configuration — the real repo tree with the real shellPackSources,
//     proving the floor is pointed at directories that actually exist and that
//     the shipped numbers clear it.
//
// Both are required. A correct mechanism aimed at the wrong directory is
// exactly the bug this file guards, and a correct directory list with an
// unfalsifiable floor is the other half of it.

// testSources mirrors the real shape (one required, one optional) with floors
// small enough to express in a few lines of fixture.
var testSources = []packSource{
	{Dir: filepath.Join("packs", "community"), Required: true, MinPacks: 2, MinRules: 3},
	{Dir: filepath.Join("packs", "premium"), Required: false, MinPacks: 2, MinRules: 3},
}

// writePack writes a syntactically valid shell pack carrying nRules rules.
func writePack(t *testing.T, dir, name string, nRules int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	var b strings.Builder
	b.WriteString("version: \"0.1\"\nname: " + strings.TrimSuffix(name, ".yaml") + "\n")
	if nRules == 0 {
		b.WriteString("rules: []\n")
	} else {
		b.WriteString("rules:\n")
		for i := 0; i < nRules; i++ {
			fmt.Fprintf(&b, "- id: %s-%03d\n  match:\n    command_regex: \"/etc/shadow\"\n"+
				"  decision: BLOCK\n  reason: fixture\n", strings.TrimSuffix(name, ".yaml"), i)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// healthyTree builds a root that clears testSources on both sources.
func healthyTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writePack(t, filepath.Join(root, "packs", "community"), "terminal-safety.yaml", 3)
	writePack(t, filepath.Join(root, "packs", "community"), "secrets-pii.yaml", 2)
	writePack(t, filepath.Join(root, "packs", "premium"), "network-egress.yaml", 3)
	writePack(t, filepath.Join(root, "packs", "premium"), "supply-chain.yaml", 2)
	return root
}

// ---------------------------------------------------------------------------
// Mechanism: the guard must be able to fail.
// ---------------------------------------------------------------------------

func TestDiscoveryFloorAcceptsHealthyTree(t *testing.T) {
	// The control. Without this the failing cases below could pass for the
	// wrong reason (a guard that rejects everything is not a guard).
	res, err := DiscoverShellPacks(healthyTree(t), testSources)
	if err != nil {
		t.Fatalf("healthy tree rejected: %v", err)
	}
	if got := len(res.Packs); got != 4 {
		t.Errorf("packs = %d, want 4", got)
	}
	if got := res.TotalRules(); got != 10 {
		t.Errorf("rules = %d, want 10", got)
	}
}

func TestDiscoveryFloorRejectsEmptyRequiredDir(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "packs", "community"), 0o755); err != nil {
		t.Fatal(err)
	}
	writePack(t, filepath.Join(root, "packs", "premium"), "a.yaml", 3)
	writePack(t, filepath.Join(root, "packs", "premium"), "b.yaml", 3)

	_, err := DiscoverShellPacks(root, testSources)
	if err == nil {
		t.Fatal("empty packs/community accepted — the floor cannot fail, " +
			"which is the #3359 defect itself")
	}
	if !strings.Contains(err.Error(), "packs/community") {
		t.Errorf("error should name the failing source, got: %v", err)
	}
}

func TestDiscoveryFloorRejectsMissingRequiredDir(t *testing.T) {
	root := t.TempDir()
	writePack(t, filepath.Join(root, "packs", "premium"), "a.yaml", 3)
	writePack(t, filepath.Join(root, "packs", "premium"), "b.yaml", 3)

	_, err := DiscoverShellPacks(root, testSources)
	if err == nil {
		t.Fatal("absent packs/community accepted; a required source that vanished " +
			"must be fatal, not an empty work queue")
	}
}

func TestDiscoveryFloorRejectsPresentButEmptyOptionalDir(t *testing.T) {
	// The subtle half. "Optional" means the directory may be ABSENT — not that
	// a directory which exists may yield nothing. A premium/ that is present
	// and unreadable-by-the-scan is precisely the regression shape.
	root := healthyTree(t)
	for _, n := range []string{"network-egress.yaml", "supply-chain.yaml"} {
		if err := os.Remove(filepath.Join(root, "packs", "premium", n)); err != nil {
			t.Fatal(err)
		}
	}

	_, err := DiscoverShellPacks(root, testSources)
	if err == nil {
		t.Fatal("present-but-empty packs/premium accepted — optional was read as " +
			"'may be empty', which reopens #3359 on the premium half")
	}
	if !strings.Contains(err.Error(), "packs/premium") {
		t.Errorf("error should name the failing source, got: %v", err)
	}
}

func TestDiscoveryFloorRejectsPacksWithNoRules(t *testing.T) {
	// Pack count alone is not the denominator: a directory of empty packs
	// clears MinPacks and still feeds the classifier nothing.
	root := t.TempDir()
	writePack(t, filepath.Join(root, "packs", "community"), "a.yaml", 0)
	writePack(t, filepath.Join(root, "packs", "community"), "b.yaml", 0)

	_, err := DiscoverShellPacks(root, testSources)
	if err == nil {
		t.Fatal("two rule-less packs accepted; the floor must cover rules, not just files")
	}
	if !strings.Contains(err.Error(), "0 rules") {
		t.Errorf("error should report the rule count, got: %v", err)
	}
}

func TestDiscoveryToleratesAbsentOptionalDir(t *testing.T) {
	// The OSS tree: scripts/publish-oss.sh strips packs/premium/ while
	// cmd/mcp-gen ships. Community alone must be a clean run.
	root := t.TempDir()
	writePack(t, filepath.Join(root, "packs", "community"), "a.yaml", 3)
	writePack(t, filepath.Join(root, "packs", "community"), "b.yaml", 2)

	res, err := DiscoverShellPacks(root, testSources)
	if err != nil {
		t.Fatalf("OSS-shaped tree rejected: %v", err)
	}
	if len(res.Packs) != 2 {
		t.Errorf("packs = %d, want 2", len(res.Packs))
	}
	var premium *sourceCount
	for i := range res.Sources {
		if strings.HasSuffix(res.Sources[i].Dir, "premium") {
			premium = &res.Sources[i]
		}
	}
	if premium == nil || premium.Present {
		t.Errorf("absent premium source should be recorded as not present: %+v", premium)
	}
	if !strings.Contains(res.Summary(), "absent") {
		t.Errorf("summary should say premium is absent, got:\n%s", res.Summary())
	}
}

func TestDiscoverySkipsMCPSubdirAndDisabledPacks(t *testing.T) {
	// MCP packs are this generator's OUTPUT domain. Recursing into them would
	// feed generated MCP rules back in as shell rules, and `_`-prefixed files
	// are the repo's disabled-pack convention — the engine ignores them, so
	// the generator must too.
	root := healthyTree(t)
	writePack(t, filepath.Join(root, "packs", "community", "mcp"), "mcp-generated.yaml", 50)
	writePack(t, filepath.Join(root, "packs", "community"), "_legacy.yaml", 50)

	res, err := DiscoverShellPacks(root, testSources)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.TotalRules(); got != 10 {
		t.Errorf("rules = %d, want 10 — an mcp/ or _disabled pack leaked into discovery", got)
	}
	for _, s := range res.Sources {
		for _, f := range s.Files {
			if strings.Contains(filepath.ToSlash(f), "/mcp/") {
				t.Errorf("MCP pack discovered as a shell pack: %s", f)
			}
			if strings.HasPrefix(filepath.Base(f), "_") {
				t.Errorf("disabled pack discovered: %s", f)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Configuration: the real tree, the real floors.
// ---------------------------------------------------------------------------

// TestDiscoveryFloorRejectsThePre3359Layout replays the exact bug. Before this
// fix main.go scanned `packs/`, which the OSS pack split (5899f2ad) left
// holding only directories. The old loader returned an empty slice and the
// generator exited 0 with "No new rules to generate."; the floor must turn the
// same scan into a non-zero exit.
func TestDiscoveryFloorRejectsThePre3359Layout(t *testing.T) {
	root := findProjectRoot()
	pre3359 := []packSource{{
		Dir: "packs", Required: true,
		MinPacks: shellPackSources[0].MinPacks, MinRules: shellPackSources[0].MinRules,
	}}

	_, err := DiscoverShellPacks(root, pre3359)
	if err == nil {
		t.Fatal("scanning packs/ (the pre-#3359 target) produced no error; " +
			"the generator would silently no-op again")
	}
	if !strings.Contains(err.Error(), "0 packs") {
		t.Errorf("error should report the empty denominator, got: %v", err)
	}
	t.Logf("guard correctly rejects the shipped regression: %v", err)
}

// TestDiscoveryFloorHoldsOnRealTree is the live gate. cmd/... is in the CI test
// list, so this runs on every PR — the floor is enforced continuously rather
// than only when a human happens to type `make mcp-gen` (CLAUDE.md → "Gates
// nobody runs").
func TestDiscoveryFloorHoldsOnRealTree(t *testing.T) {
	root := findProjectRoot()

	res, err := DiscoverShellPacks(root, shellPackSources)
	if err != nil {
		t.Fatalf("shell-pack discovery is broken on this tree: %v", err)
	}
	t.Logf("discovered:\n%s", res.Summary())

	// Assert the denominator, not only the absence of an error.
	if len(res.Packs) == 0 || res.TotalRules() == 0 {
		t.Fatalf("vacuous discovery: %d packs / %d rules", len(res.Packs), res.TotalRules())
	}

	// Every source declared present must have cleared its own floor; a total
	// that clears while one source contributes nothing is the renamed-directory
	// case hiding behind a healthy sibling.
	for i, s := range res.Sources {
		if !s.Present {
			continue
		}
		if s.Packs < shellPackSources[i].MinPacks || s.Rules < shellPackSources[i].MinRules {
			t.Errorf("%s below floor: %d packs / %d rules", s.Dir, s.Packs, s.Rules)
		}
	}

	// Classification must survive the round trip. Discovery finding packs that
	// yield zero candidates would be the same vacuum one stage downstream.
	if got := len(ClassifyRules(res.Packs)); got == 0 {
		t.Error("discovery found packs but classification produced 0 candidates")
	}
}
