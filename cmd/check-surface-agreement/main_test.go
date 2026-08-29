package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Synthetic corpus helpers. The check has no thresholds that scale with corpus
// size, so a handful of files is a faithful miniature — unlike the fit gates,
// whose fractions collapse on a small corpus.
// ---------------------------------------------------------------------------

// shellRule and mcpRule emit the two pack shapes. Terminal packs put `- id:` at
// column 0 and MCP packs indent it under a rule-bearing key; the scanner has to
// cope with both, and CLAUDE.md records that assuming one anchor is how the
// corpus got miscounted by 1,173 rules.
func shellRule(id, node string) string {
	return "- id: " + id + "\n  taxonomy: " + node + "\n  decision: BLOCK\n"
}

func mcpRule(id, node string) string {
	return "  - id: " + id + "\n    taxonomy: \"" + node + "\"\n    decision: \"BLOCK\"\n"
}

// writeCorpus lays out a packs/ tree: shell packs at packs/, MCP packs under
// packs/mcp/ so surfaceOf classifies them by path.
func writeCorpus(t *testing.T, shell, mcp string) string {
	t.Helper()
	root := t.TempDir()
	packs := filepath.Join(root, "packs")
	if err := os.MkdirAll(filepath.Join(packs, "mcp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if shell != "" {
		if err := os.WriteFile(filepath.Join(packs, "terminal-safety.yaml"), []byte(shell), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if mcp != "" {
		if err := os.WriteFile(filepath.Join(packs, "mcp", "mcp-persistence.yaml"), []byte("rules:\n"+mcp), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return packs
}

func run(t *testing.T, packs string) ([]flag_, int, int) {
	t.Helper()
	corpus, total, err := scanPacks(packs)
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	flags, both := analyse(corpus)
	return flags, both, total
}

// ---------------------------------------------------------------------------
// The test that makes the gate fail (#3130: a gate that cannot go red is worse
// than no gate, because a green check still gets counted as proof).
// ---------------------------------------------------------------------------

// TestGateDetectsDivergence is the positive control. It reproduces the exact
// defect this check was written for — the real python-pth-write divergence, in
// miniature — and asserts the check goes red on it.
func TestGateDetectsDivergence(t *testing.T) {
	packs := writeCorpus(t,
		shellRule("ts-block-python-pth-write", "persistence-evasion/shell-init/python-pth-persistence"),
		mcpRule("mcp-persist-block-python-pth-write", "persistence-evasion/shell-startup/shell-profile-backdoor"),
	)
	flags, both, total := run(t, packs)

	if total != 2 {
		t.Fatalf("scanned %d refs, want 2 — the scanner missed a pack shape", total)
	}
	if both != 1 {
		t.Fatalf("stems on both surfaces = %d, want 1 — stem normalisation failed to pair the two rules", both)
	}
	if len(flags) != 1 {
		t.Fatalf("flags = %d, want 1: the gate did not detect a known-divergent pair", len(flags))
	}
	if flags[0].Stem != "python-pth-write" {
		t.Errorf("stem = %q, want %q", flags[0].Stem, "python-pth-write")
	}
	want := "python-pth-write :: persistence-evasion/shell-init/python-pth-persistence :: persistence-evasion/shell-startup/shell-profile-backdoor"
	if got := flags[0].key(); got != want {
		t.Errorf("baseline key = %q, want %q", got, want)
	}
}

// TestGateAcceptsAgreement is the negative control: the same pair, once the MCP
// rule is corrected, must go green. Without this, a check that flags
// unconditionally would pass the test above.
func TestGateAcceptsAgreement(t *testing.T) {
	packs := writeCorpus(t,
		shellRule("ts-block-python-pth-write", "persistence-evasion/shell-init/python-pth-persistence"),
		mcpRule("mcp-persist-block-python-pth-write", "persistence-evasion/shell-init/python-pth-persistence"),
	)
	flags, both, _ := run(t, packs)
	if both != 1 {
		t.Fatalf("stems on both surfaces = %d, want 1", both)
	}
	if len(flags) != 0 {
		t.Fatalf("flags = %d, want 0: agreeing surfaces must not be flagged (%+v)", len(flags), flags)
	}
}

// TestPartialOverlapIsNotDivergence pins the deliberate looseness: a stem
// spread over several nodes is a divergence only when the surfaces agree on
// NONE of them. Tightening this to set equality would flag every rule family
// where one surface covers an extra variant, which is ordinary, not a defect.
func TestPartialOverlapIsNotDivergence(t *testing.T) {
	packs := writeCorpus(t,
		shellRule("ts-block-cred-read", "credential-exposure/a/one")+
			shellRule("ts-block-cred-read-alt", "credential-exposure/a/two"),
		mcpRule("mcp-sec-block-cred-read", "credential-exposure/a/one"),
	)
	flags, _, _ := run(t, packs)
	if len(flags) != 0 {
		t.Fatalf("flags = %d, want 0: overlapping node sets are not a divergence (%+v)", len(flags), flags)
	}
}

// TestSingleSurfaceStemIsInvisible states a scope limit as a test rather than
// only in prose: a detection that exists on one surface cannot disagree with
// anything, and must not be counted in the denominator either.
func TestSingleSurfaceStemIsInvisible(t *testing.T) {
	packs := writeCorpus(t, shellRule("ts-block-only-here", "some/node/here"), "")
	flags, both, total := run(t, packs)
	if total != 1 {
		t.Fatalf("total = %d, want 1", total)
	}
	if both != 0 || len(flags) != 0 {
		t.Fatalf("both=%d flags=%d, want 0/0", both, len(flags))
	}
}

// ---------------------------------------------------------------------------
// Normalisation — the part that, if it over-strips, invents pairs that were
// never the same detection and produces false flags.
// ---------------------------------------------------------------------------

func TestStemOf(t *testing.T) {
	cases := []struct{ in, want string }{
		// The real prefixes in use, stripped to the same stem.
		{"ts-block-python-pth-write", "python-pth-write"},
		{"mcp-persist-block-python-pth-write", "python-pth-write"},
		{"sc-block-cargo-config-write", "cargo-config-write"},
		{"mcp-sc-block-cargo-config-write", "cargo-config-write"},
		{"ts-audit-docker-host-redirect", "docker-host-redirect"},
		{"mcp-recon-block-dev-kmem-access", "dev-kmem-access"},
		// The MCP packs pair many rules as `-key-arg` variants; both collapse
		// onto the base stem so a divergence is reported once, not twice.
		{"mcp-privesc-block-git-allow-protocol-ext", "git-allow-protocol-ext"},
		{"mcp-privesc-block-git-allow-protocol-ext-key-arg", "git-allow-protocol-ext"},
		// Language suffixes strip repeatedly, not just once.
		{"ts-block-thing-arg-py", "thing"},
		// A rule with no recognised prefix keeps its whole id — under-stripping
		// costs coverage, over-stripping costs correctness.
		{"custom-detector-name", "custom-detector-name"},
	}
	for _, c := range cases {
		if got := stemOf(c.in); got != c.want {
			t.Errorf("stemOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestStemOfDoesNotCollapseDistinctDetections is the guard against the failure
// mode that would make this gate untrustworthy: two genuinely different
// detections normalising onto one stem would report a divergence that is
// really just a name collision.
func TestStemOfDoesNotCollapseDistinctDetections(t *testing.T) {
	pairs := [][2]string{
		{"ts-block-python-pth-write", "ts-block-python-pth-tee"},
		{"mcp-recon-block-dev-mem-access", "mcp-recon-block-dev-kmem-access"},
		{"sc-block-gemrc-write", "sc-block-gem-sources-add"},
	}
	for _, p := range pairs {
		if a, b := stemOf(p[0]), stemOf(p[1]); a == b {
			t.Errorf("stemOf collapsed distinct detections %q and %q onto %q", p[0], p[1], a)
		}
	}
}

func TestSurfaceOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"packs/premium/mcp/mcp-persistence.yaml", "mcp"},
		{"packs/community/mcp/mcp-safety.yaml", "mcp"},
		{"packs/premium/mcp-package-registry-redirect.yaml", "mcp"}, // named, not nested
		{"packs/community/terminal-safety.yaml", "shell"},
		{"packs/premium/supply-chain.yaml", "shell"},
	}
	for _, c := range cases {
		if got := surfaceOf(c.in); got != c.want {
			t.Errorf("surfaceOf(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Baseline mechanics
// ---------------------------------------------------------------------------

func TestBaselineParsingIgnoresCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.txt")
	body := "# a header comment\n\n" +
		"stem-one :: a/b/c :: d/e/f\n" +
		"stem-two :: g/h/i :: j/k/l   # trailing verdict note\n" +
		"   \n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := loadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("parsed %d entries, want 2: %+v", len(got), got)
	}
	if !got["stem-one :: a/b/c :: d/e/f"] || !got["stem-two :: g/h/i :: j/k/l"] {
		t.Errorf("entries not parsed as expected: %+v", got)
	}
}

func TestMissingBaselineIsEmptyNotAnError(t *testing.T) {
	got, err := loadBaseline(filepath.Join(t.TempDir(), "nope.txt"))
	if err != nil {
		t.Fatalf("missing baseline should not error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want empty, got %+v", got)
	}
}

// TestLiveBaselineMatchesLiveCorpus keeps the shipped baseline honest. It is
// the same contract the file's own header states: every listed divergence must
// still exist (no STALE), and no unlisted one may (no new). Running it here
// means a pack edit that changes a taxonomy ref fails in `go test` too, not
// only in the CI step.
func TestLiveBaselineMatchesLiveCorpus(t *testing.T) {
	corpus, total, err := scanPacks("../../packs")
	if err != nil {
		t.Fatalf("scan live packs: %v", err)
	}
	// Assert a floor on the denominator. A transform that silently yields zero
	// candidates makes "0 divergences" read as success — the vacuous-probe
	// shape this repo has shipped before.
	if total < 1000 {
		t.Fatalf("scanned only %d taxonomy refs from packs/ — expected thousands; the scan is broken, not the corpus clean", total)
	}
	flags, both := analyse(corpus)
	if both < 10 {
		t.Fatalf("only %d stems on both surfaces — stem normalisation is broken", both)
	}

	baseline, err := loadBaseline("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range flags {
		seen[f.key()] = true
		if !baseline[f.key()] {
			t.Errorf("NEW divergence not in baseline:\n  %s", f.key())
		}
	}
	for k := range baseline {
		if !seen[k] {
			t.Errorf("STALE baseline entry — the surfaces now agree, delete this line:\n  %s", k)
		}
	}
}

// TestVacuousScanIsDetectable pins the #3130 lesson at the unit level: an empty
// result must be distinguishable from a clean one. main() turns this into a
// hard exit 2; here we assert the signal it keys on is actually zero.
func TestVacuousScanIsDetectable(t *testing.T) {
	_, total, err := scanPacks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("total = %d, want 0 for an empty tree", total)
	}
}
