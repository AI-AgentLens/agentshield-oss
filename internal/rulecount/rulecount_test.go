package rulecount

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixture corpus under testdata/packs is small enough to count by hand,
// and mixes the two indentation styles found in the real corpus (shell packs
// put `- id:` at column 0, MCP packs indent it under the key) so a
// text-anchored counter would get it wrong on purpose.
//
//	community/shell-col0.yaml     2 shell  (sh-a, sh-b)
//	community/shell-labels.yaml   1 shell  (sh-lab-1; its data_labels entry is NOT a rule)
//	community/_disabled.yaml      0        (disabled)
//	community/README.md           0        (not YAML)
//	community/mcp/mcp-indented    5 mcp    (one per id-bearing section; 2 blocked_tools NOT counted)
//	premium/shell-premium.yaml    2 shell  (sh-p1, sh-p2)
//	premium/shell-yml.yml         1 shell  (the disk loader accepts .yml for premium)
//	premium/mcp/mcp-premium.yaml  2 mcp    (mcp-p1 defined twice — an intra-file duplicate)
func TestCount_FixtureCorpus(t *testing.T) {
	r, err := Count("testdata/packs")
	if err != nil {
		t.Fatal(err)
	}
	c := r.Counts
	if c.Shell != (TierCounts{Community: 3, Premium: 3, Total: 6}) {
		t.Errorf("shell = %+v", c.Shell)
	}
	if c.MCP != (TierCounts{Community: 5, Premium: 2, Total: 7}) {
		t.Errorf("mcp = %+v", c.MCP)
	}
	if c.Total != 13 {
		t.Errorf("total = %d, want 13", c.Total)
	}
	if c.UniqueIDs != 12 {
		t.Errorf("unique_ids = %d, want 12 (mcp-p1 is defined twice)", c.UniqueIDs)
	}
	if c.Definition != Definition {
		t.Errorf("definition not stamped")
	}
	if got := r.Duplicates["mcp-p1"]; got != 2 {
		t.Errorf("duplicates[mcp-p1] = %d, want 2; all: %v", got, r.Duplicates)
	}
	if len(r.Duplicates) != 1 {
		t.Errorf("duplicates = %v, want exactly mcp-p1", r.Duplicates)
	}
	// Every id-bearing section of the MCP fixture contributed exactly one entry.
	bySection := map[string]int{}
	for _, e := range r.Entries {
		if e.Surface == MCP && e.Tier == Community {
			bySection[e.Section]++
		}
	}
	for _, s := range IDBearingSections {
		if bySection[s] != 1 {
			t.Errorf("section %s counted %d, want 1", s, bySection[s])
		}
	}
	for _, e := range r.Entries {
		if e.ID == "never-counted" {
			t.Errorf("disabled pack was counted: %+v", e)
		}
		if e.ID == "label-not-a-rule" {
			t.Errorf("a data_labels entry was counted as a rule: %+v", e)
		}
	}
	// The .yml premium pack is counted: dropping .yml support must fail here.
	found := false
	for _, e := range r.Entries {
		if e.ID == "sh-yml-1" && e.Tier == Premium && e.Surface == Shell {
			found = true
		}
	}
	if !found {
		t.Error("premium/shell-yml.yml was not counted — the disk loader accepts .yml")
	}
}

// A sixth id-bearing key is refused by name. This is the test that fails when
// the key list and a fixture disagree: to add a section you must add it to
// IDBearingSections, and a fixture carrying it must then count — there is no
// path where a new section is silently counted or silently skipped.
func TestParse_UnknownIDBearingSectionIsRefused(t *testing.T) {
	raw := []byte("name: x\nrules:\n  - id: a\nfuture_rules:\n  - id: b\n")
	_, err := Parse(raw, "x.yaml")
	if err == nil || !strings.Contains(err.Error(), `"future_rules"`) {
		t.Fatalf("want error naming future_rules, got %v", err)
	}
}

// data_labels carry an id (policy.DataLabel), both loaders merge them, and
// they are NOT rules: a pack carrying them counts only its rules, without
// error. (An earlier revision refused them as unknown, which would have made
// the release generator fail on a legitimate pack.)
func TestParse_DataLabelsCountOnlyTheRules(t *testing.T) {
	raw := []byte("name: x\nrules:\n  - id: a\ndata_labels:\n  - id: pii-ssn\n    name: SSN\n")
	got, err := Parse(raw, "x.yaml")
	if err != nil {
		t.Fatalf("data_labels must not be an error: %v", err)
	}
	if len(got) != 1 || got[0].ID != "a" {
		t.Fatalf("want exactly rule a, got %+v", got)
	}
}

// Each per-directory selection rule, by name. Community and premium/mcp are
// embedded via *.yaml globs; premium shell is loaded from disk by LoadPacks.
func TestLoaded_MatchesEachLoadersFileSelection(t *testing.T) {
	cases := []struct {
		name    string
		surface Surface
		tier    Tier
		want    bool
	}{
		{"terminal-safety.yaml", Shell, Community, true},
		{"terminal-safety.yml", Shell, Community, false}, // embed glob is *.yaml
		{"_disabled.yaml", Shell, Community, false},
		{"README.md", Shell, Community, false},
		{"mcp-secrets.yaml", MCP, Community, true},
		{"mcp-secrets.yml", MCP, Community, false},
		{"mcp-sentinel.yaml", MCP, Premium, true},
		{"mcp-sentinel.yml", MCP, Premium, false},
		{"network-egress.yaml", Shell, Premium, true},
		{"network-egress.yml", Shell, Premium, true}, // IsYAMLFile
		{"Network-Egress.YAML", Shell, Premium, true},
		{"_network-egress.yaml", Shell, Premium, false},
		{"mcp-flat.yaml", Shell, Premium, false}, // LoadPacks skips flat mcp-* (#2219)
		{"notes.txt", Shell, Premium, false},
	}
	for _, c := range cases {
		if got := Loaded(c.name, c.surface, c.tier); got != c.want {
			t.Errorf("Loaded(%q, %s, %s) = %v, want %v", c.name, c.surface, c.tier, got, c.want)
		}
	}
}

// End to end on a temp root: a community .yml and a flat premium mcp-*.yaml
// hold rules but are not loaded by Shield, so they are not counted.
func TestCount_UnloadedFilesAreNotCounted(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("community/real.yaml", "rules:\n- id: c-real\n")
	write("community/ghost.yml", "rules:\n- id: c-ghost\n")
	write("premium/real.yaml", "rules:\n- id: p-real\n")
	write("premium/also.yml", "rules:\n- id: p-yml\n")
	write("premium/mcp-flat.yaml", "rules:\n- id: p-mcp-flat\n")
	r, err := Count(root)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, e := range r.Entries {
		ids[e.ID] = true
	}
	for id, want := range map[string]bool{"c-real": true, "c-ghost": false, "p-real": true, "p-yml": true, "p-mcp-flat": false} {
		if ids[id] != want {
			t.Errorf("%s counted=%v, want %v", id, ids[id], want)
		}
	}
	if r.Counts.Total != 3 {
		t.Errorf("total = %d, want 3", r.Counts.Total)
	}
}

func TestParse_ListsWithoutIDsAreIgnored(t *testing.T) {
	raw := []byte("blocked_tools:\n  - run_shell\nblocked_resources:\n  - \"file:///opt/x\"\nrules:\n  - id: a\n    taxonomy: t\n")
	got, err := Parse(raw, "x.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "a" || got[0].Taxonomy != "t" || got[0].Section != "rules" {
		t.Fatalf("got %+v", got)
	}
}

func TestParse_ItemWithoutIDInRuleSectionIsAnError(t *testing.T) {
	raw := []byte("rules:\n  - id: a\n  - decision: BLOCK\n")
	if _, err := Parse(raw, "x.yaml"); err == nil || !strings.Contains(err.Error(), "rules[1] has no id") {
		t.Fatalf("want rules[1] has no id, got %v", err)
	}
}

func TestParse_MalformedYAMLIsAnError(t *testing.T) {
	if _, err := Parse([]byte("rules: [\n"), "bad.yaml"); err == nil {
		t.Fatal("malformed YAML must not count as zero rules")
	}
}

func TestCount_EmptyCorpusIsRefused(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "community"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Count(root); err == nil || !strings.Contains(err.Error(), "vacuous") {
		t.Fatalf("want vacuous-zero refusal, got %v", err)
	}
}

func TestCollect_MissingDirIsNotAnError(t *testing.T) {
	got, err := Collect(filepath.Join(t.TempDir(), "absent"), Shell, Premium)
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v, %v", got, err)
	}
}

// Both indentation styles yield the same entries; the count is a property of
// the YAML structure, not of the author's whitespace.
func TestParse_IndentationStyleDoesNotMatter(t *testing.T) {
	col0 := []byte("rules:\n- id: a\n- id: b\n")
	indented := []byte("rules:\n  - id: a\n  - id: b\n")
	a, err := Parse(col0, "a.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(indented, "b.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 2 || len(b) != 2 || a[0].ID != b[0].ID || a[1].ID != b[1].ID {
		t.Fatalf("col0=%+v indented=%+v", a, b)
	}
}

// The real corpus must satisfy the invariants the definition states, so this
// package cannot drift into a definition the packs do not fit.
func TestCount_RealCorpusInvariants(t *testing.T) {
	r, err := Count("../../packs")
	if err != nil {
		t.Fatal(err)
	}
	c := r.Counts
	if c.Shell.Community+c.Shell.Premium != c.Shell.Total || c.MCP.Community+c.MCP.Premium != c.MCP.Total || c.Shell.Total+c.MCP.Total != c.Total {
		t.Errorf("arithmetic does not add up: %+v", c)
	}
	dupExtra := 0
	for _, n := range r.Duplicates {
		dupExtra += n - 1
	}
	if c.Total-dupExtra != c.UniqueIDs {
		t.Errorf("total %d - extra definitions %d != unique_ids %d", c.Total, dupExtra, c.UniqueIDs)
	}
	if c.Shell.Community == 0 || c.MCP.Community == 0 {
		t.Errorf("community tier counted zero on a surface: %+v", c)
	}
}
