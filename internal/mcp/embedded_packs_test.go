package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestLoadEmbeddedMCPPacks_HasRules is a fitness function: ensures the binary
// ships with community MCP rules baked in. Guards against a //go:embed
// directive regression in packs/packs.go (the shell-pack equivalent lives in
// internal/policy/embedded_packs_test.go).
func TestLoadEmbeddedMCPPacks_HasRules(t *testing.T) {
	base := &MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}
	merged, infos, err := LoadEmbeddedMCPPacks(base)
	if err != nil {
		t.Fatalf("LoadEmbeddedMCPPacks failed: %v", err)
	}
	if len(infos) == 0 {
		t.Fatal("no embedded MCP packs found — //go:embed community/mcp/*.yaml regressed?")
	}

	totalRules := len(merged.Rules) + len(merged.ResourceRules) + len(merged.ValueLimits) +
		len(merged.StructuralRules) + len(merged.SemanticRules) + len(merged.DataLabels)
	// Community MCP packs contribute hundreds of rules; a floor of 50 catches a
	// broken embed without being fragile to additions/removals of individual rules.
	if totalRules < 50 {
		t.Errorf("embedded MCP packs contributed only %d total rules (expected >= 50)", totalRules)
	}
}

// TestLoadEmbeddedMCPPacks_SurvivesDiskLayer is the direct regression test for
// the bug we just fixed: when BOTH disk packs and embedded packs exist, the
// old call sites only loaded disk (or only fell back when disk was empty).
// That meant premium-pack users silently lost community MCP coverage.
//
// The invariant we're pinning here: after loading embedded + disk, the policy
// still contains the rules that embedded alone contributed. If someone rewrites
// the call-site code to overwrite instead of layer, this fires.
//
// This test simulates the layered-load pattern used in hook.go, scan.go,
// mcp_proxy.go, mcp_http_proxy.go, and mcp_eval.go.
func TestLoadEmbeddedMCPPacks_SurvivesDiskLayer(t *testing.T) {
	base := &MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}

	// Baseline: embedded-only rule count.
	embeddedOnly, embInfos, err := LoadEmbeddedMCPPacks(base)
	if err != nil {
		t.Fatalf("embedded load failed: %v", err)
	}
	if len(embInfos) == 0 {
		t.Skip("no embedded packs — skipping (another test will catch this)")
	}
	embeddedRuleCount := len(embeddedOnly.Rules)

	// Build a disk pack that adds a distinguishable rule.
	tmp := t.TempDir()
	diskPackYAML := `name: "Premium Test Pack"
version: "1.0.0"
rules:
  - id: disk-test-rule-001
    name: "Disk layer marker"
    tool_pattern: "test_tool_marker"
    decision: "BLOCK"
    reason: "Used by TestLoadEmbeddedMCPPacks_SurvivesDiskLayer to prove the disk layer was applied on top of the embedded layer."
`
	if err := os.WriteFile(filepath.Join(tmp, "premium-test.yaml"), []byte(diskPackYAML), 0o600); err != nil {
		t.Fatalf("writing disk pack: %v", err)
	}

	// Layered load — the exact pattern used by call sites.
	layered, _, _ := LoadEmbeddedMCPPacks(base)
	layered, diskInfos, err := LoadMCPPacks(tmp, layered)
	if err != nil {
		t.Fatalf("disk load failed: %v", err)
	}
	if len(diskInfos) != 1 {
		t.Fatalf("expected 1 disk pack loaded, got %d", len(diskInfos))
	}

	// Invariant 1: embedded rules must survive the disk layer.
	if len(layered.Rules) < embeddedRuleCount {
		t.Fatalf("layered policy has %d rules, embedded-only had %d — disk layer clobbered embedded rules",
			len(layered.Rules), embeddedRuleCount)
	}

	// Invariant 2: disk rule must be present.
	foundDisk := false
	for _, r := range layered.Rules {
		if r.ID == "disk-test-rule-001" {
			foundDisk = true
			break
		}
	}
	if !foundDisk {
		t.Fatal("disk rule disk-test-rule-001 not present in layered policy — disk layer never ran")
	}

	// Invariant 3: total rules = embedded + disk (nothing dropped).
	if want := embeddedRuleCount + 1; len(layered.Rules) != want {
		t.Errorf("layered rule count = %d, want %d (embedded=%d + disk=1)",
			len(layered.Rules), want, embeddedRuleCount)
	}
}
