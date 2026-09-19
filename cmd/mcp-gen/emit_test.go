package main

import (
	"os"
	"path/filepath"
	"reflect"
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
	if err := EmitMCPPack(first, nil, outPath); err != nil {
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
	if err := EmitMCPPack(second, nil, outPath); err != nil {
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
	if err := EmitMCPPack([]Candidate{c}, nil, outPath); err != nil {
		t.Fatalf("first EmitMCPPack: %v", err)
	}
	if err := EmitMCPPack([]Candidate{c}, nil, outPath); err != nil {
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
	if err := EmitMCPPack([]Candidate{c}, nil, outPath); err != nil {
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
	if err := EmitMCPPack([]Candidate{c}, nil, outPath); err != nil {
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

// TestEmitMCPPackWidensStaleToolCoverage pins the delivery half of #3589:
// dedup drops an already-shipped id before it reaches EmitMCPPack, so before
// this the generator was strictly additive and a classifier fix could never
// reach a rule already in the file. The reclassified set is what carries it.
func TestEmitMCPPackWidensStaleToolCoverage(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	// First run: the classifier's old, read-only answer ships.
	stale := Candidate{
		SourceRule: ShellRule{ID: "sec-audit-editor-target", Decision: "AUDIT"},
		Category:   "path-read",
		Paths:      []string{"/home/*/.openai"},
		ToolNames:  ReadTools,
		Decision:   "AUDIT",
		Reason:     "editor target",
	}
	if err := EmitMCPPack([]Candidate{stale}, nil, outPath); err != nil {
		t.Fatalf("first EmitMCPPack: %v", err)
	}

	// Second run: the classifier now recognises the editor verb, so the same
	// source rule classifies read+write. Dedup would drop it (id already
	// shipped), so it arrives only via the reclassified argument, and the
	// net-new candidate list is empty — the real shape of this fix's run.
	fixed := stale
	fixed.Category = "path-readwrite"
	fixed.ToolNames = AllFileTools
	if err := EmitMCPPack(nil, []Candidate{fixed}, outPath); err != nil {
		t.Fatalf("second EmitMCPPack: %v", err)
	}

	got, err := loadMCPGenPack(outPath)
	if err != nil {
		t.Fatalf("loadMCPGenPack: %v", err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	tools := got.Rules[0].Match.ToolNameAny
	for _, want := range AllFileTools {
		if !containsString(tools, want) {
			t.Errorf("widened rule is missing %q; got %v", want, tools)
		}
	}
	// The read tools it already shipped must survive, in place.
	if len(tools) < len(ReadTools) || tools[0] != ReadTools[0] {
		t.Errorf("existing read tools must be preserved in order; got %v", tools)
	}
}

// TestWidenToolCoverageNodeNeverRemovesTools is the safety half, on the
// yaml.Node write path EmitMCPPack actually uses. A classifier regression, a
// corpus edit, or a new isShellOnly exclusion can all make the current
// answer NARROWER than what shipped. Replacing would then silently delete
// protection from a pack every community user embeds — the #3367 failure
// mode in a new costume. Widening is union-only, so the worst case is an
// over-broad rule visible in the diff, never a silent hole.
func TestWidenToolCoverageNodeNeverRemovesTools(t *testing.T) {
	rulesNode := nodeRulesFromMCPGenRules(t, []MCPGenRule{{
		ID:    "mcp-gen-sec-shipped-broad",
		Match: MCPGenMatch{ToolNameAny: append([]string{}, AllFileTools...)},
	}})
	narrowed := Candidate{
		SourceRule: ShellRule{ID: "sec-shipped-broad"},
		Category:   "path-read",
		ToolNames:  ReadTools,
	}

	widenToolCoverageNode(rulesNode, []Candidate{narrowed})

	got := decodeRuleNode(t, rulesNode.Content[0])
	for _, want := range AllFileTools {
		if !containsString(got.Match.ToolNameAny, want) {
			t.Errorf("widenToolCoverageNode dropped %q — it must never remove a shipped tool; got %v",
				want, got.Match.ToolNameAny)
		}
	}
}

// TestWidenToolCoverageNodeSkipsRulesItDoesNotOwn covers the two skip cases.
// A rule with no tool_name_any matches EVERY tool, so writing a list in would
// narrow it; and an id the current classifier no longer produces has nothing
// to compare against and must be left exactly as it is on disk.
func TestWidenToolCoverageNodeSkipsRulesItDoesNotOwn(t *testing.T) {
	rulesNode := nodeRulesFromMCPGenRules(t, []MCPGenRule{
		{ID: "mcp-gen-sec-no-tool-list", Match: MCPGenMatch{
			ArgumentPatterns: map[string]string{"path": "/home/*/.openai"},
		}},
		{ID: "mcp-gen-sec-unclassified-now", Match: MCPGenMatch{
			ToolNameAny: append([]string{}, ReadTools...),
		}},
	})
	// Only names the FIRST rule's id; the second is no longer classified.
	reclassified := []Candidate{{
		SourceRule: ShellRule{ID: "sec-no-tool-list"},
		Category:   "path-readwrite",
		ToolNames:  AllFileTools,
	}}

	widenToolCoverageNode(rulesNode, reclassified)

	got0 := decodeRuleNode(t, rulesNode.Content[0])
	if len(got0.Match.ToolNameAny) != 0 {
		t.Errorf("a rule with no tool_name_any matches every tool; writing one in narrows it. got %v",
			got0.Match.ToolNameAny)
	}
	got1 := decodeRuleNode(t, rulesNode.Content[1])
	if len(got1.Match.ToolNameAny) != len(ReadTools) {
		t.Errorf("an id the classifier no longer produces must be untouched; got %v",
			got1.Match.ToolNameAny)
	}
}

// TestWidenToolCoverageNodeIsIdempotent — a second run over an
// already-widened file must be a no-op, or every regeneration would append
// duplicate tool names and the pack would grow without bound.
func TestWidenToolCoverageNodeIsIdempotent(t *testing.T) {
	rulesNode := nodeRulesFromMCPGenRules(t, []MCPGenRule{{
		ID:    "mcp-gen-sec-idem",
		Match: MCPGenMatch{ToolNameAny: append([]string{}, ReadTools...)},
	}})
	c := Candidate{
		SourceRule: ShellRule{ID: "sec-idem"},
		Category:   "path-readwrite",
		ToolNames:  AllFileTools,
	}

	widenToolCoverageNode(rulesNode, []Candidate{c})
	first := append([]string{}, decodeRuleNode(t, rulesNode.Content[0]).Match.ToolNameAny...)

	widenToolCoverageNode(rulesNode, []Candidate{c})
	second := decodeRuleNode(t, rulesNode.Content[0]).Match.ToolNameAny

	if !reflect.DeepEqual(first, second) {
		t.Errorf("widenToolCoverageNode is not idempotent:\n first: %v\nsecond: %v",
			first, second)
	}
}

// TestEmitMCPPackPreservesHandWrittenComments pins the fix for #3855: a
// regen that adds an unrelated new rule must not disturb a hand-written
// comment on a rule it never touches. Before this fix EmitMCPPack always
// re-marshaled the whole pack from a plain MCPGenPack struct, and plain
// struct marshaling has no concept of a comment bound to a specific field —
// every real (non-dry-run) regen silently deleted the `# Hand-edited
// (#3735): ...` rationale above the m2-settings.xml rule.
func TestEmitMCPPackPreservesHandWrittenComments(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	seed := `name: MCP Generated Rules (Shell-to-MCP)
description: test
version: "1.0.0"
author: AgentShield MCP Generator
generated: "2020-01-01T00:00:00Z"
rules:
    - id: mcp-gen-protected-path-commented
      # Hand-edited (#9999): explains why this rule is narrower than default.
      taxonomy: credential-exposure/config-file-access/protected-path
      match:
        tool_name_any:
            - read_file
            - cat_file
        argument_patterns_any:
            path:
                - /home/*/.commented-secret
      decision: BLOCK
      reason: '[MCP] Access to protected path ~/.commented-secret is blocked.'
`
	if err := os.WriteFile(outPath, []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}

	newCandidate := Candidate{
		SourceRule: ShellRule{ID: "protected-path-unrelated", Decision: "BLOCK"},
		Category:   "path-read",
		Paths:      []string{"**/.unrelated-secret"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if err := EmitMCPPack([]Candidate{newCandidate}, nil, outPath); err != nil {
		t.Fatalf("EmitMCPPack: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# Hand-edited (#9999)") {
		t.Errorf("hand-written comment did not survive a regen that never touched its rule; got:\n%s", data)
	}
	// The new rule must still land — this isn't just "change nothing".
	if !strings.Contains(string(data), "mcp-gen-protected-path-unrelated") {
		t.Errorf("new candidate must still be emitted alongside the preserved comment; got:\n%s", data)
	}
}

// TestEmitMCPPackPreservesCommentOnWidenedRule is the harder half: the
// comment must survive even when THIS run widens the exact rule it is
// attached to, because widenToolCoverageNode mutates that rule's
// tool_name_any sequence node in place rather than rebuilding the rule.
func TestEmitMCPPackPreservesCommentOnWidenedRule(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")

	seed := `name: MCP Generated Rules (Shell-to-MCP)
description: test
version: "1.0.0"
author: AgentShield MCP Generator
generated: "2020-01-01T00:00:00Z"
rules:
    - id: mcp-gen-sec-widen-commented
      # Hand-edited (#9998): kept narrow deliberately, see issue for why.
      taxonomy: credential-exposure/config-file-access/protected-path
      match:
        tool_name_any:
            - read_file
        argument_patterns:
            path: /home/*/.widen-secret
      decision: AUDIT
      reason: '[MCP] test'
`
	if err := os.WriteFile(outPath, []byte(seed), 0644); err != nil {
		t.Fatal(err)
	}

	widened := Candidate{
		SourceRule: ShellRule{ID: "sec-widen-commented"},
		Category:   "path-readwrite",
		ToolNames:  AllFileTools,
	}
	if err := EmitMCPPack(nil, []Candidate{widened}, outPath); err != nil {
		t.Fatalf("EmitMCPPack: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "# Hand-edited (#9998)") {
		t.Errorf("comment must survive on a rule this run WIDENS, not just leaves untouched; got:\n%s", data)
	}

	got, err := loadMCPGenPack(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(got.Rules))
	}
	for _, want := range AllFileTools {
		if !containsString(got.Rules[0].Match.ToolNameAny, want) {
			t.Errorf("widened rule missing %q; got %v", want, got.Rules[0].Match.ToolNameAny)
		}
	}
}

// TestEmitMCPPackRefusesUnparseableExistingFile is TestLoadMCPGenPackRefuses-
// UnparseableExistingFile's counterpart on the actual write path. EmitMCPPack
// stopped calling loadMCPGenPack for its own read when it moved to the
// yaml.Node tree — this pins the same fail-safe (never treat a corrupt file
// as empty) on loadMCPGenPackNode, the function it calls instead.
func TestEmitMCPPackRefusesUnparseableExistingFile(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "mcp-generated.yaml")
	if err := os.WriteFile(outPath, []byte("rules:\n  - id: [this is not valid yaml for a rule list\n"), 0644); err != nil {
		t.Fatal(err)
	}

	c := Candidate{
		SourceRule: ShellRule{ID: "protected-path-x"},
		Category:   "path-read",
		Paths:      []string{"**/.x-secret"},
		ToolNames:  ReadTools,
		Decision:   "BLOCK",
	}
	if err := EmitMCPPack([]Candidate{c}, nil, outPath); err == nil {
		t.Error("EmitMCPPack must error on an unparseable existing file, not silently treat it as empty")
	}
}

// nodeRulesFromMCPGenRules builds a yaml.Node "rules" sequence from a
// []MCPGenRule fixture the same way EmitMCPPack encodes a freshly-added rule
// (ruleNode.Encode), so the widenToolCoverageNode tests exercise the same
// node shape production code produces instead of hand-authored YAML.
func nodeRulesFromMCPGenRules(t *testing.T, rules []MCPGenRule) *yaml.Node {
	t.Helper()
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, r := range rules {
		n := &yaml.Node{}
		if err := n.Encode(r); err != nil {
			t.Fatalf("encode fixture rule %s: %v", r.ID, err)
		}
		seq.Content = append(seq.Content, n)
	}
	return seq
}

// decodeRuleNode round-trips a single rule node back into an MCPGenRule for
// assertions.
func decodeRuleNode(t *testing.T, n *yaml.Node) MCPGenRule {
	t.Helper()
	var r MCPGenRule
	if err := n.Decode(&r); err != nil {
		t.Fatalf("decode rule node: %v", err)
	}
	return r
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
