package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func writePack(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestCollectRules_UntaxedBlockDetection verifies the agentshield-oss#3118
// guardrail: a BLOCK rule with no taxonomy field is reported, an ALLOW rule
// with no taxonomy field is not, and a taxonomy'd BLOCK rule is not.
func TestCollectRules_UntaxedBlockDetection(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "sample.yaml", `
version: "0.1"
rules:
  - id: block-no-taxonomy
    decision: BLOCK
    match:
      command_regex: "danger"
  - id: allow-no-taxonomy
    decision: ALLOW
    match:
      command_regex: "safe"
  - id: block-with-taxonomy
    taxonomy: destructive-ops/fs-destruction/system-directory-delete
    decision: BLOCK
    match:
      command_regex: "rm"
  - id: block-lowercase-no-taxonomy
    decision: block
    match:
      command_regex: "danger2"
  - id: block-quoted-no-taxonomy
    decision: "BLOCK"
    match:
      command_regex: "danger3"
`)

	rules, untaxed, err := collectRules([]string{dir})
	if err != nil {
		t.Fatalf("collectRules: %v", err)
	}

	if _, ok := rules["destructive-ops/fs-destruction/system-directory-delete"]; !ok {
		t.Error("expected taxonomy'd rule to be collected in rules map")
	}

	// Case- and quote-insensitive: the guardrail must not be bypassable by
	// writing `decision: block` instead of `decision: BLOCK`.
	got := map[string]bool{}
	for _, r := range untaxed {
		got[r.ID] = true
	}
	want := []string{"block-no-taxonomy", "block-lowercase-no-taxonomy", "block-quoted-no-taxonomy"}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected untaxed BLOCK rule %q to be reported; got %+v", id, untaxed)
		}
	}
	if len(untaxed) != len(want) {
		t.Errorf("expected exactly %d untaxed BLOCK rules (ALLOW and taxonomy'd rules must not "+
			"be reported), got %d: %+v", len(want), len(untaxed), untaxed)
	}
}

// TestUntaxedBlockBaseline_AllowlistsExemption verifies that a rule ID listed
// in the untaxed-block baseline file is excluded from the failure set,
// mirroring how main() filters unallowedUntaxedBlocks.
func TestUntaxedBlockBaseline_AllowlistsExemption(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "untaxed-block-baseline.txt")
	if err := os.WriteFile(baselinePath, []byte("exempt-rule  # deliberate backstop\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("loadBaseline: %v", err)
	}

	untaxed := []untaxedBlockRule{
		{ID: "exempt-rule", Pack: "sample.yaml"},
		{ID: "not-exempt-rule", Pack: "sample.yaml"},
	}
	var unallowed []untaxedBlockRule
	for _, r := range untaxed {
		if !baseline[r.ID] {
			unallowed = append(unallowed, r)
		}
	}
	if len(unallowed) != 1 || unallowed[0].ID != "not-exempt-rule" {
		t.Errorf("expected only 'not-exempt-rule' to remain unallowed, got %+v", unallowed)
	}
}

// TestRealUntaxedBlockBaseline_MatchesRepoState is the ratchet: the real
// untaxed-block-baseline.txt must allowlist EXACTLY ts-sem-block-high-risk
// (agentshield-oss#3118). Growing the baseline requires editing this test,
// which is the sign-off checkpoint — a new untaxed BLOCK rule cannot slip in
// by quietly appending a line.
func TestRealUntaxedBlockBaseline_MatchesRepoState(t *testing.T) {
	baseline, err := loadBaseline("untaxed-block-baseline.txt")
	if err != nil {
		t.Fatalf("loadBaseline: %v", err)
	}
	if !baseline["ts-sem-block-high-risk"] {
		t.Error("expected ts-sem-block-high-risk to be allowlisted (see the exemption comment in " +
			"packs/premium/terminal-safety-advanced.yaml)")
	}
	if len(baseline) != 1 {
		ids := make([]string, 0, len(baseline))
		for id := range baseline {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		t.Errorf("untaxed-block baseline grew to %d entries: %v\n"+
			"Every entry is a BLOCK that produces no compliance attestation. Adding one requires "+
			"Gary + Kai sign-off — prefer a specific taxonomy ref, or split the rule per intent. "+
			"If the new exemption is genuinely architectural, update this test with the reasoning.",
			len(baseline), ids)
	}
}

// TestRepoHasNoUnallowedUntaxedBlockRules runs the #3118 guardrail over the
// real packs/ tree, so `go test ./...` catches a new untaxed BLOCK rule even
// when `make check-rule-coverage` is not run.
func TestRepoHasNoUnallowedUntaxedBlockRules(t *testing.T) {
	_, untaxed, err := collectRules([]string{"../../packs/community", "../../packs/premium"})
	if err != nil {
		t.Fatalf("collectRules: %v", err)
	}
	baseline, err := loadBaseline("untaxed-block-baseline.txt")
	if err != nil {
		t.Fatalf("loadBaseline: %v", err)
	}
	for _, r := range untaxed {
		if !baseline[r.ID] {
			t.Errorf("BLOCK rule %q in %s has no `taxonomy:` field — it is unattestable (#3118). "+
				"Add a specific taxonomy ref, split the rule per intent, or (last resort) "+
				"baseline it with reasoning.", r.ID, r.Pack)
		}
	}
}
