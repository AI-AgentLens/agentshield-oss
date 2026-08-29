package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestEmitMCPPackNeverDropsExistingRules pins the fix for #3367: a bare
// re-run of the generator, with a candidate set that no longer includes
// a previously-shipped id, must not erase that id from the pack on disk.
// Before this fix EmitMCPPack rewrote the file wholesale from the current
// candidate list every run — a classifier fix, a corpus change, or a
// tightened dedup routinely shrinks that list, and the difference was
// silently deleted from a pack every community user's binary embeds.
func TestEmitMCPPackNeverDropsExistingRules(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	first := []Candidate{
		{
			SourceRule: ShellRule{ID: "protected-path-old-vendor", Decision: "BLOCK"},
			Category:   "path-read",
			Paths:      []string{"**/.old-vendor-secret"},
			ToolNames:  ReadTools,
			Decision:   "BLOCK",
			Reason:     "old vendor secret",
		},
	}
	if err := EmitMCPPack(first, outPath); err != nil {
		t.Fatalf("first EmitMCPPack: %v", err)
	}

	// Second run: a totally different, non-overlapping candidate set — the
	// shape of "the old rule's shell source no longer classifies, or dedup
	// now excludes it for an unrelated reason."
	second := []Candidate{
		{
			SourceRule: ShellRule{ID: "protected-path-new-vendor", Decision: "BLOCK"},
			Category:   "path-read",
			Paths:      []string{"**/.new-vendor-secret"},
			ToolNames:  ReadTools,
			Decision:   "BLOCK",
			Reason:     "new vendor secret",
		},
	}
	if err := EmitMCPPack(second, outPath); err != nil {
		t.Fatalf("second EmitMCPPack: %v", err)
	}

	got, err := loadMCPGenPack(outPath)
	if err != nil {
		t.Fatalf("loadMCPGenPack: %v", err)
	}
	ids := map[string]bool{}
	for _, r := range got.Rules {
		ids[r.ID] = true
	}
	if !ids["mcp-gen-protected-path-old-vendor"] {
		t.Error("rule from the first run must survive a second run with a disjoint candidate set")
	}
	if !ids["mcp-gen-protected-path-new-vendor"] {
		t.Error("rule from the second run must be present")
	}
	if len(got.Rules) != 2 {
		t.Errorf("got %d rules, want 2 (union of both runs)", len(got.Rules))
	}
}

// TestEmitMCPPackDoesNotDuplicateReemittedCandidate pins the other half:
// re-proposing a candidate whose id is already on disk (e.g. dedup fails to
// exclude it, or a caller passes the full candidate set instead of only the
// net-new ones) must not create a duplicate id in the pack.
func TestEmitMCPPackDoesNotDuplicateReemittedCandidate(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-repeat", Decision: "BLOCK"},
		Category:   "path-read",
		Paths:      []string{"**/.repeat-secret"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if err := EmitMCPPack([]Candidate{c}, outPath); err != nil {
		t.Fatalf("first EmitMCPPack: %v", err)
	}
	if err := EmitMCPPack([]Candidate{c}, outPath); err != nil {
		t.Fatalf("second EmitMCPPack: %v", err)
	}

	got, err := loadMCPGenPack(outPath)
	if err != nil {
		t.Fatalf("loadMCPGenPack: %v", err)
	}
	count := 0
	for _, r := range got.Rules {
		if r.ID == "mcp-gen-protected-path-repeat" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("got %d copies of the re-emitted rule id, want exactly 1", count)
	}
}

// TestEmitMCPPackFirstRunOnMissingFile confirms a missing output file (the
// very first run in a fresh checkout) is not an error and produces exactly
// the candidate set, not an empty pack.
func TestEmitMCPPackFirstRunOnMissingFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-first-ever", Decision: "BLOCK"},
		Category:   "path-read",
		Paths:      []string{"**/.first-secret"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if err := EmitMCPPack([]Candidate{c}, outPath); err != nil {
		t.Fatalf("EmitMCPPack on missing file: %v", err)
	}
	got, err := loadMCPGenPack(outPath)
	if err != nil {
		t.Fatalf("loadMCPGenPack: %v", err)
	}
	if len(got.Rules) != 1 || got.Rules[0].ID != "mcp-gen-protected-path-first-ever" {
		t.Fatalf("got %+v, want exactly the one candidate", got.Rules)
	}
}

// TestLoadMCPGenPackRefusesUnparseableExistingFile pins the fail-safe: a
// present-but-corrupt output file must error rather than be silently
// treated as empty, which would make the next EmitMCPPack call believe
// there was nothing to preserve and quietly delete every rule it held.
func TestLoadMCPGenPackRefusesUnparseableExistingFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")
	if err := os.WriteFile(outPath, []byte("rules:\n  - id: [this is not valid yaml for a rule list\n"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := loadMCPGenPack(outPath); err == nil {
		t.Error("loadMCPGenPack must error on an unparseable existing file, not silently treat it as empty")
	}
}

// TestEmitMCPPackOutputParsesAsValidMCPRuleSet is a light smoke test that
// the merged output is still well-formed YAML that reconstitutes correctly
// after a merge round-trip (guards against a marshal-shape regression).
func TestEmitMCPPackOutputParsesAsValidMCPRuleSet(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-smoke", Decision: "BLOCK"},
		Category:   "path-read",
		Paths:      []string{"**/.smoke-secret"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if err := EmitMCPPack([]Candidate{c}, outPath); err != nil {
		t.Fatalf("EmitMCPPack: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "# Auto-generated by cmd/mcp-gen") {
		t.Error("output must keep the auto-generated header comment")
	}
	var pack MCPGenPack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		t.Fatalf("output is not valid YAML: %v", err)
	}
	if len(pack.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(pack.Rules))
	}
}
