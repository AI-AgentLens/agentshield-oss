package main

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// Synthetic corpus helpers.
// ---------------------------------------------------------------------------

func writeMCPPack(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	full := "rules:\n" + body
	if err := os.WriteFile(filepath.Join(dir, name), []byte(full), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readOnlyRule(id string) string {
	return "  - id: " + id + "\n" +
		"    taxonomy: \"credential-exposure/api-keys/thing\"\n" +
		"    match:\n" +
		"      tool_name_any: [\"read_file\", \"cat_file\"]\n" +
		"      argument_patterns:\n" +
		"        path: \"**/.thing/token\"\n" +
		"    decision: \"BLOCK\"\n" +
		"    reason: \"blocked\"\n"
}

func symmetricRule(id string) string {
	return "  - id: " + id + "\n" +
		"    taxonomy: \"credential-exposure/api-keys/thing\"\n" +
		"    match:\n" +
		"      tool_name_any: [\"read_file\", \"write_file\"]\n" +
		"      argument_patterns:\n" +
		"        path: \"**/.thing/token\"\n" +
		"    decision: \"BLOCK\"\n" +
		"    reason: \"blocked\"\n"
}

// ---------------------------------------------------------------------------
// The test that makes the gate fail (#3130).
// ---------------------------------------------------------------------------

// TestGateFlagsReadOnlyCredentialRule is the positive control: it reproduces
// the real #3513/#3524 shape — a credential-exposure rule that lists only
// read-family tools — and asserts the gate catches it.
func TestGateFlagsReadOnlyCredentialRule(t *testing.T) {
	dir := t.TempDir()
	writeMCPPack(t, dir, "mcp-secrets.yaml", readOnlyRule("mcp-sec-block-thing-token-read"))

	findings, examined, err := scanPacks([]string{dir})
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	if examined != 1 {
		t.Fatalf("examined = %d, want 1", examined)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1: the gate did not detect a read-only credential rule", len(findings))
	}
	if findings[0].Rule != "mcp-sec-block-thing-token-read" {
		t.Errorf("flagged rule = %q, want %q", findings[0].Rule, "mcp-sec-block-thing-token-read")
	}
}

// TestGateAcceptsReadWriteSymmetricRule is the negative control: the same
// rule, once tool_name_any carries a write-family tool, must go green.
// Without this, a gate that flags unconditionally would pass the test above.
func TestGateAcceptsReadWriteSymmetricRule(t *testing.T) {
	dir := t.TempDir()
	writeMCPPack(t, dir, "mcp-secrets.yaml", symmetricRule("mcp-sec-block-thing-token-read"))

	findings, examined, err := scanPacks([]string{dir})
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	if examined != 1 {
		t.Fatalf("examined = %d, want 1", examined)
	}
	if len(findings) != 0 {
		t.Fatalf("findings = %d, want 0: a read+write symmetric rule must not be flagged (%+v)", len(findings), findings)
	}
}

// TestGateIgnoresNonCredentialTaxonomy pins the scope limit: write access
// under a different kingdom (e.g. destructive-ops) is not this gate's
// question — check-rule-coverage and the others own that.
func TestGateIgnoresNonCredentialTaxonomy(t *testing.T) {
	dir := t.TempDir()
	body := "  - id: mcp-ts-block-thing-read\n" +
		"    taxonomy: \"destructive-ops/file-system/thing-delete\"\n" +
		"    match:\n" +
		"      tool_name_any: [\"read_file\"]\n" +
		"      argument_patterns:\n" +
		"        path: \"**/thing\"\n" +
		"    decision: \"BLOCK\"\n" +
		"    reason: \"blocked\"\n"
	writeMCPPack(t, dir, "mcp-safety.yaml", body)

	findings, examined, err := scanPacks([]string{dir})
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	if examined != 0 || len(findings) != 0 {
		t.Fatalf("examined=%d findings=%d, want 0/0 for a non-credential-exposure rule", examined, len(findings))
	}
}

// TestGateIgnoresNonPathBasedRule pins the other scope limit: a rule that
// matches on tool name alone, or on an argument other than `path`, has
// nothing for a read/write asymmetry to mean.
func TestGateIgnoresNonPathBasedRule(t *testing.T) {
	dir := t.TempDir()
	body := "  - id: mcp-sec-block-thing-url\n" +
		"    taxonomy: \"credential-exposure/api-keys/thing\"\n" +
		"    match:\n" +
		"      tool_name_any: [\"read_file\"]\n" +
		"      argument_patterns:\n" +
		"        url: \"https://evil.example/**\"\n" +
		"    decision: \"BLOCK\"\n" +
		"    reason: \"blocked\"\n"
	writeMCPPack(t, dir, "mcp-secrets.yaml", body)

	findings, examined, err := scanPacks([]string{dir})
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	if examined != 0 || len(findings) != 0 {
		t.Fatalf("examined=%d findings=%d, want 0/0 for a non-path-based rule", examined, len(findings))
	}
}

// TestGateIgnoresDisabledPacks mirrors the `_`-prefix disabled-pack
// convention used across the rest of the repo's pack tooling.
func TestGateIgnoresDisabledPacks(t *testing.T) {
	dir := t.TempDir()
	writeMCPPack(t, dir, "_mcp-secrets-disabled.yaml", readOnlyRule("mcp-sec-block-thing-token-read"))

	findings, examined, err := scanPacks([]string{dir})
	if err != nil {
		t.Fatalf("scanPacks: %v", err)
	}
	if examined != 0 || len(findings) != 0 {
		t.Fatalf("examined=%d findings=%d, want 0/0 — disabled pack must be skipped", examined, len(findings))
	}
}

// ---------------------------------------------------------------------------
// Baseline mechanics
// ---------------------------------------------------------------------------

func TestBaselineParsingIgnoresCommentsAndBlanks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline.txt")
	body := "# a header comment\n\n" +
		"mcp-sec-block-rule-one\n" +
		"mcp-sec-block-rule-two   # reviewed, genuinely read-only\n" +
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
	if !got["mcp-sec-block-rule-one"] || !got["mcp-sec-block-rule-two"] {
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

// TestLiveBaselineMatchesLiveCorpus keeps the shipped baseline honest: every
// listed finding must still exist (no STALE) and no unlisted one may (no
// new). Running it here means a pack edit that reintroduces the asymmetry
// fails `go test` too, not only the CI step.
func TestLiveBaselineMatchesLiveCorpus(t *testing.T) {
	dirs := []string{"../../packs/community/mcp", "../../packs/premium/mcp"}
	findings, examined, err := scanPacks(dirs)
	if err != nil {
		t.Fatalf("scan live packs: %v", err)
	}
	// Assert a floor on the denominator (#3130): a scan that silently
	// examines 0 rules must not be mistaken for a symmetric corpus.
	if examined < 100 {
		t.Fatalf("examined only %d credential-exposure/* path-based rules — expected hundreds; the scan is broken, not the corpus clean", examined)
	}

	baseline, err := loadBaseline("baseline.txt")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range findings {
		seen[f.key()] = true
		if !baseline[f.key()] {
			t.Errorf("NEW asymmetric rule not in baseline: %s [%s]", f.Rule, f.File)
		}
	}
	for k := range baseline {
		if !seen[k] {
			t.Errorf("STALE baseline entry — %s is no longer flagged, delete this line", k)
		}
	}
}

// TestVacuousScanIsDetectable pins the #3130 lesson at the unit level: an
// empty tree must produce 0 examined, not be silently treated as "clean".
func TestVacuousScanIsDetectable(t *testing.T) {
	_, examined, err := scanPacks([]string{t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if examined != 0 {
		t.Fatalf("examined = %d, want 0 for an empty tree", examined)
	}
}
