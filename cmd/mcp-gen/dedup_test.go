package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

func TestDecisionRank(t *testing.T) {
	cases := []struct {
		decision string
		want     int
	}{
		{"BLOCK", 2},
		{"block", 2},
		{"REQUIRE_APPROVAL", 2},
		{"AUDIT", 1},
		{"audit", 1},
		{"ALLOW", 0},
		{"", 0},
		{"garbage", 0},
	}
	for _, c := range cases {
		if got := decisionRank(c.decision); got != c.want {
			t.Errorf("decisionRank(%q) = %d, want %d", c.decision, got, c.want)
		}
	}
	if decisionRank("BLOCK") <= decisionRank("AUDIT") {
		t.Error("BLOCK must outrank AUDIT")
	}
	if decisionRank("AUDIT") <= decisionRank("ALLOW") {
		t.Error("AUDIT must outrank ALLOW")
	}
}

// synthCoveringPolicy builds a minimal existing MCP policy that BLOCKs
// read/write access anywhere under a home-anchored .aws directory — the
// shape a hand-authored rule actually ships (see mcp-sec-block-aws-access),
// spelled differently from the **/.aws/** glob mcp-gen's own
// classifyProtectedPaths would derive from a shell rule's protected_paths.
func synthCoveringPolicy() *mcp.MCPPolicy {
	return &mcp.MCPPolicy{
		Rules: []mcp.MCPRule{
			{
				ID: "existing-block-aws-access",
				Match: mcp.MCPMatch{
					ToolNameAny: []string{"read_file", "write_file", "cat_file", "create_file"},
					ArgumentPatterns: map[string]string{
						"path": "/home/*/.aws/**",
					},
				},
				Decision: "BLOCK",
			},
			{
				ID: "existing-audit-dotenv",
				Match: mcp.MCPMatch{
					ToolNameAny: []string{"read_file"},
					ArgumentPatterns: map[string]string{
						"path": "/home/*/.env",
					},
				},
				Decision: "AUDIT",
			},
		},
	}
}

func TestCoverageChecker_CoversDifferentlySpelledPattern(t *testing.T) {
	cc := NewCoverageChecker(synthCoveringPolicy())

	// Textually this glob (**/.aws/**) does not match the existing rule's
	// pattern (/home/*/.aws/**) as a string, but every concrete path it
	// would generate an example from is already BLOCKed by the existing
	// rule — this is exactly the gap #3464 reports.
	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-aws", Decision: "BLOCK"},
		Category:   "path-readwrite",
		Paths:      []string{"**/.aws/**"},
		ToolNames:  AllFileTools,
		Decision:   "BLOCK",
	}
	if !cc.Covers(c) {
		t.Error("expected coverage-based dedup to recognize **/.aws/** is already BLOCKed by /home/*/.aws/**")
	}
}

func TestCoverageChecker_WeakerExistingRuleDoesNotCover(t *testing.T) {
	cc := NewCoverageChecker(synthCoveringPolicy())

	// The existing dotenv rule is AUDIT-only; a candidate proposing BLOCK on
	// the same target is a strictly stronger detection and must NOT be
	// treated as already covered.
	c := Candidate{
		SourceRule: ShellRule{ID: "sec-block-dotenv-strict", Decision: "BLOCK"},
		Category:   "path-read",
		Paths:      []string{"/home/*/.env"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if cc.Covers(c) {
		t.Error("an AUDIT-only existing rule must not cover a candidate proposing BLOCK")
	}
}

func TestCoverageChecker_UncoveredPathIsNotCovered(t *testing.T) {
	cc := NewCoverageChecker(synthCoveringPolicy())

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-totally-new", Decision: "BLOCK"},
		Category:   "path-readwrite",
		Paths:      []string{"**/.totally-new-vendor/**"},
		ToolNames:  AllFileTools,
		Decision:   "BLOCK",
	}
	if cc.Covers(c) {
		t.Error("a path with no matching existing rule must not be reported as covered")
	}
}

func TestCoverageChecker_NoTargetsIsNeverCovered(t *testing.T) {
	cc := NewCoverageChecker(synthCoveringPolicy())
	c := Candidate{SourceRule: ShellRule{ID: "url-only-empty"}, Category: "url", Decision: "BLOCK"}
	if cc.Covers(c) {
		t.Error("a candidate with no path/URL targets has nothing to compare and must not be 'covered'")
	}
}

func TestCoverageChecker_NilCheckerNeverCovers(t *testing.T) {
	var cc *CoverageChecker
	c := Candidate{
		SourceRule: ShellRule{ID: "x"},
		Category:   "path-read",
		Paths:      []string{"**/.aws/**"},
		Decision:   "BLOCK",
	}
	if cc.Covers(c) {
		t.Error("nil CoverageChecker must fail safe to 'not covered', not panic or false-positive dedup")
	}
}

func TestDeduplicateCandidates_CoverageDropsDifferentlySpelledDuplicate(t *testing.T) {
	cc := NewCoverageChecker(synthCoveringPolicy())
	candidates := []Candidate{
		{
			SourceRule: ShellRule{ID: "protected-path-aws", Decision: "BLOCK"},
			Category:   "path-readwrite",
			Paths:      []string{"**/.aws/**"},
			ToolNames:  AllFileTools,
			Decision:   "BLOCK",
		},
		{
			SourceRule: ShellRule{ID: "protected-path-brand-new", Decision: "BLOCK"},
			Category:   "path-readwrite",
			Paths:      []string{"**/.brand-new-vendor/**"},
			ToolNames:  AllFileTools,
			Decision:   "BLOCK",
		},
	}

	got := DeduplicateCandidates(candidates, map[string]bool{}, map[string]bool{}, cc)
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1 (the AWS duplicate should be dropped): %+v", len(got), got)
	}
	if got[0].SourceRule.ID != "protected-path-brand-new" {
		t.Errorf("wrong candidate survived dedup: %s", got[0].SourceRule.ID)
	}
}

func TestDeduplicateCandidates_NilCoverageFallsBackToTextualOnly(t *testing.T) {
	// coverage == nil must not panic, and must preserve the pre-#3464
	// textual-only behavior exactly (existing callers/tests of the old
	// signature relied on this).
	candidates := []Candidate{
		{
			SourceRule: ShellRule{ID: "protected-path-aws", Decision: "BLOCK"},
			Category:   "path-readwrite",
			Paths:      []string{"**/.aws/**"},
			ToolNames:  AllFileTools,
			Decision:   "BLOCK",
		},
	}
	got := DeduplicateCandidates(candidates, map[string]bool{}, map[string]bool{}, nil)
	if len(got) != 1 {
		t.Fatalf("nil coverage checker must not drop candidates on its own: got %d, want 1", len(got))
	}
}

// TestLoadExistingMCPRulesSeesOwnGeneratedOutput pins the fix for #3367: a
// rule already shipped in mcp-generated.yaml — the generator's own output —
// must be visible to dedup like any other pack. Before this fix,
// LoadExistingMCPRules skipped that one file by name, so every rule living
// only there was permanently invisible to future runs and `-dry-run` kept
// reporting it as a "net new" gap forever, even though it was already
// enforced (verified live on the real corpus: 10 of 18 reported gaps were
// this).
func TestLoadExistingMCPRulesSeesOwnGeneratedOutput(t *testing.T) {
	dir := t.TempDir()
	pack := `rules:
  - id: mcp-gen-block-example
    match:
      tool_name_any: [read_file]
      argument_patterns:
        path: "**/.example-secret"
    decision: BLOCK
`
	if err := os.WriteFile(filepath.Join(dir, "mcp-generated.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	ids, patterns, err := LoadExistingMCPRules(dir)
	if err != nil {
		t.Fatalf("LoadExistingMCPRules: %v", err)
	}
	if !ids["mcp-gen-block-example"] {
		t.Error("rule id from mcp-generated.yaml must be visible to LoadExistingMCPRules, not skipped")
	}
	if !patterns["**/.example-secret"] {
		t.Error("path pattern from mcp-generated.yaml must be visible to LoadExistingMCPRules, not skipped")
	}
}

// TestLoadExistingMCPPolicySeesOwnGeneratedOutput is the CoverageChecker-path
// twin of TestLoadExistingMCPRulesSeesOwnGeneratedOutput: a differently-
// spelled candidate that the generated pack's rule already covers (#3464's
// coverage-based dedup) must be recognized as covered even when the only
// covering rule lives in mcp-generated.yaml itself.
func TestLoadExistingMCPPolicySeesOwnGeneratedOutput(t *testing.T) {
	dir := t.TempDir()
	pack := `rules:
  - id: mcp-gen-block-aws
    match:
      tool_name_any: [read_file, write_file]
      argument_patterns:
        path: "/home/*/.aws/**"
    decision: BLOCK
`
	if err := os.WriteFile(filepath.Join(dir, "mcp-generated.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	policy, err := LoadExistingMCPPolicy(dir)
	if err != nil {
		t.Fatalf("LoadExistingMCPPolicy: %v", err)
	}
	cc := NewCoverageChecker(policy)

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-aws", Decision: "BLOCK"},
		Category:   "path-readwrite",
		Paths:      []string{"**/.aws/**"},
		ToolNames:  AllFileTools,
		Decision:   "BLOCK",
	}
	if !cc.Covers(c) {
		t.Error("a candidate already covered by a rule living only in mcp-generated.yaml must be recognized as covered")
	}
}

// TestCoverageDedup_KnownDuplicatesFromIssue3464 replays the exact table
// from issue #3464: candidates the textual dedup false-flagged as "net new"
// because their glob spelling didn't match an existing rule's pattern
// string, even though the existing rule already BLOCKs (or, for the dotenv
// case, already decides) every path the candidate would generate. Run
// against the real shipped shell + MCP corpus so a regression in either the
// classifier or the coverage checker fails this test, not just a manual
// dry-run.
func TestCoverageDedup_KnownDuplicatesFromIssue3464(t *testing.T) {
	root := findProjectRoot()

	disc, err := DiscoverShellPacks(root, shellPackSources)
	if err != nil {
		t.Fatalf("shell-pack discovery failed: %v", err)
	}
	candidates := ClassifyRules(disc.Packs)
	if len(candidates) == 0 {
		t.Fatal("vacuous classification: 0 candidates from the real corpus")
	}

	mcpPacksDir := filepath.Join(root, "packs", "community", "mcp")
	existingIDs, existingPatterns, err := LoadExistingMCPRules(mcpPacksDir)
	if err != nil {
		t.Fatalf("LoadExistingMCPRules: %v", err)
	}
	existingPolicy, err := LoadExistingMCPPolicy(mcpPacksDir)
	if err != nil {
		t.Fatalf("LoadExistingMCPPolicy: %v", err)
	}
	cc := NewCoverageChecker(existingPolicy)

	netNew := DeduplicateCandidates(candidates, existingIDs, existingPatterns, cc)
	survivingIDs := map[string]bool{}
	for _, c := range netNew {
		survivingIDs[c.SourceRule.ID] = true
	}

	// Every one of these was documented in #3464 as already covered by a
	// specific existing rule. Coverage-based dedup must remove all of them.
	knownDuplicates := []string{
		"protected-path-ssh",
		"protected-path-aws",
		"protected-path-gnupg",
		"protected-path-config-gcloud",
		"protected-path-kube",
		"protected-path-pypirc",
		"protected-path-git-credentials",
		"protected-path-config-op",
		"protected-path-local-share-keyrings",
		"protected-path-gem-credentials",
		"protected-path-config-github-copilot",
		"protected-path-config-age",
		"protected-path-age",
		"protected-path-cargo-credentialstoml",
		"protected-path-gradle-gradleproperties",
	}
	for _, id := range knownDuplicates {
		if survivingIDs[id] {
			t.Errorf("candidate %q survived coverage dedup — expected it to be recognized as already covered", id)
		}
	}

	// protected-path-gem-credentials was moved into knownDuplicates above by
	// #3480: mcp-sec-block-gem-credentials's tool_name_any was read-only
	// (live-verified `agentshield mcp-eval --tool write_file --arg
	// path=/home/user/.gem/credentials` returned AUDIT, not BLOCK) until
	// #3480 extended it to the full AllFileTools family, matching the
	// candidate's own tool list. The per-direction coverage checker now
	// correctly recognizes it as covered on both directions.

	// Textual dedup alone left 47 net-new candidates on this corpus
	// (#3367). Coverage-based dedup must shrink that materially — a floor,
	// not an exact count, so the test doesn't pin every future rule add.
	if len(netNew) >= 47 {
		t.Errorf("coverage dedup made no difference: %d net-new candidates (textual-only baseline was 47)", len(netNew))
	}
	t.Logf("net-new candidates after coverage dedup: %d", len(netNew))
}
