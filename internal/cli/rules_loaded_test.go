package cli

import (
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Positive control: on a fresh install (empty $HOME) the count equals what
// the loaders produce for the embedded layer alone, computed here a second
// way; and it is in the thousands, not the ~9 files the old heartbeat sent.
func TestCountLoadedRules_FreshInstallEqualsEmbeddedLayer(t *testing.T) {
	withFakeHome(t)
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		t.Fatal(err)
	}

	shellPol, _, _ := policy.LoadEmbeddedShellPacks(policy.DefaultPolicy())
	mcpPol, _, _ := mcp.LoadEmbeddedMCPPacks(mcp.DefaultMCPPolicy())
	wantShell := len(shellPol.Rules)
	wantMCP := len(mcpPol.Rules) + len(mcpPol.StructuralRules) + len(mcpPol.ValueLimits) + len(mcpPol.ResourceRules) + len(mcpPol.SemanticRules)

	got := loadedRules(cfg)
	if got.Shell != wantShell || got.MCP != wantMCP {
		t.Fatalf("loaded = %+v, want shell %d mcp %d (embedded layer, counted independently)", got, wantShell, wantMCP)
	}
	if got.total() < 1000 {
		t.Fatalf("total %d is implausibly small for the embedded corpus — is a loader returning nothing?", got.total())
	}
	if got.total() != countLoadedRules(cfg) {
		t.Fatalf("countLoadedRules %d != loadedRules total %d", countLoadedRules(cfg), got.total())
	}
}

// Disk layers add exactly their rules: a shell pack with 2 and an MCP pack
// with 3 raise the count by 5 — and by 5 only, so a file is not a rule and
// blocked_tools are not rules.
func TestCountLoadedRules_DiskPacksAddTheirRules(t *testing.T) {
	home := withFakeHome(t)
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		t.Fatal(err)
	}
	before := loadedRules(cfg)

	writeFile(t, filepath.Join(home, ".agentshield", "packs", "custom.yaml"), `name: custom
version: "1.0.0"
rules:
  - id: custom-one
    match: {command_prefix: ["frobnicate --hard"]}
    decision: BLOCK
    reason: test
  - id: custom-two
    match: {command_prefix: ["frobnicate --soft"]}
    decision: AUDIT
    reason: test
`)
	writeFile(t, filepath.Join(home, ".agentshield", "mcp-packs", "custom-mcp.yaml"), `name: custom-mcp
version: 1.0.0
blocked_tools:
  - not_a_rule_tool
rules:
  - id: custom-mcp-one
    match: {tool_name_any: ["frob_tool"]}
    decision: BLOCK
    reason: test
structural_rules:
  - id: custom-mcp-two
    match: {tool_name_any: ["frob_tool"]}
    decision: AUDIT
    reason: test
value_limits:
  - id: custom-mcp-three
    match: {tool_name_any: ["frob_tool"]}
    decision: AUDIT
    reason: test
`)
	after := loadedRules(cfg)
	if after.Shell != before.Shell+2 {
		t.Errorf("shell: %d -> %d, want +2", before.Shell, after.Shell)
	}
	if after.MCP != before.MCP+3 {
		t.Errorf("mcp: %d -> %d, want +3 (blocked_tools must not count)", before.MCP, after.MCP)
	}
}
