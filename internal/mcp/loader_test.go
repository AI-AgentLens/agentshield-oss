package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

func TestLoadMCPPacks_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	base := DefaultMCPPolicy()

	result, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("expected 0 pack infos, got %d", len(infos))
	}
	// Result should be a clone of base, not the same pointer
	if result == base {
		t.Error("expected cloned policy, got same pointer")
	}
	if len(result.BlockedTools) != len(base.BlockedTools) {
		t.Errorf("expected %d blocked tools, got %d", len(base.BlockedTools), len(result.BlockedTools))
	}
}

func TestLoadMCPPacks_NonExistentDir(t *testing.T) {
	base := DefaultMCPPolicy()

	result, infos, err := LoadMCPPacks("/nonexistent/path/to/packs", base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("expected 0 pack infos, got %d", len(infos))
	}
	// Should return base unchanged
	if result != base {
		t.Error("expected base policy returned unchanged for nonexistent dir")
	}
}

func TestLoadMCPPacks_MergesBlockedTools(t *testing.T) {
	dir := t.TempDir()
	pack := `name: "Test Pack"
blocked_tools:
  - "evil_tool"
  - "run_shell"
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"run_shell", "execute_command"},
	}

	result, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 pack info, got %d", len(infos))
	}
	if infos[0].Name != "Test Pack" {
		t.Errorf("expected pack name 'Test Pack', got %q", infos[0].Name)
	}

	// run_shell should not be duplicated, evil_tool should be added
	if len(result.BlockedTools) != 3 {
		t.Errorf("expected 3 blocked tools (union), got %d: %v", len(result.BlockedTools), result.BlockedTools)
	}

	found := false
	for _, tool := range result.BlockedTools {
		if tool == "evil_tool" {
			found = true
		}
	}
	if !found {
		t.Error("expected 'evil_tool' in merged blocked tools")
	}
}

func TestLoadMCPPacks_MergesRules(t *testing.T) {
	dir := t.TempDir()
	pack := `name: "Rule Pack"
rules:
  - id: pack-rule-1
    match:
      tool_name: "dangerous_tool"
    decision: "BLOCK"
    reason: "Pack rule blocks this tool."
`
	if err := os.WriteFile(filepath.Join(dir, "rules.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{ID: "base-rule", Decision: policy.DecisionAudit},
		},
	}

	result, _, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Rules) != 2 {
		t.Fatalf("expected 2 rules (base + pack), got %d", len(result.Rules))
	}
	if result.Rules[0].ID != "base-rule" {
		t.Errorf("expected first rule to be base rule, got %q", result.Rules[0].ID)
	}
	if result.Rules[1].ID != "pack-rule-1" {
		t.Errorf("expected second rule to be pack rule, got %q", result.Rules[1].ID)
	}
}

func TestLoadMCPPacks_MergesValueLimits(t *testing.T) {
	dir := t.TempDir()
	max := 100.0
	pack := `name: "Limits Pack"
value_limits:
  - id: cap-amount
    tool_name_regex: "send_.*"
    argument: "amount"
    max: 100.0
    decision: "BLOCK"
    reason: "Transfer capped."
`
	if err := os.WriteFile(filepath.Join(dir, "limits.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	result, _, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.ValueLimits) != 1 {
		t.Fatalf("expected 1 value limit, got %d", len(result.ValueLimits))
	}
	if result.ValueLimits[0].ID != "cap-amount" {
		t.Errorf("expected value limit ID 'cap-amount', got %q", result.ValueLimits[0].ID)
	}
	if result.ValueLimits[0].Max == nil || *result.ValueLimits[0].Max != max {
		t.Errorf("expected max=100.0, got %v", result.ValueLimits[0].Max)
	}
}

func TestLoadMCPPacks_MergesResourceRules(t *testing.T) {
	dir := t.TempDir()
	pack := `name: "Resource Pack"
blocked_resources:
  - "file:///secret/**"

resource_rules:
  - id: block-mysql
    match:
      scheme: "mysql"
    decision: "BLOCK"
    reason: "No MySQL."
`
	if err := os.WriteFile(filepath.Join(dir, "resources.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults:         MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{"file:///root/.ssh/**"},
	}

	result, _, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.BlockedResources) != 2 {
		t.Errorf("expected 2 blocked resources, got %d: %v", len(result.BlockedResources), result.BlockedResources)
	}
	if len(result.ResourceRules) != 1 {
		t.Errorf("expected 1 resource rule, got %d", len(result.ResourceRules))
	}
}

func TestLoadMCPPacks_DisabledPack(t *testing.T) {
	dir := t.TempDir()
	pack := `name: "Disabled Pack"
blocked_tools:
  - "should_not_appear"
`
	if err := os.WriteFile(filepath.Join(dir, "_disabled.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	result, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("expected 1 pack info, got %d", len(infos))
	}
	if infos[0].Enabled {
		t.Error("expected pack to be disabled")
	}
	if len(result.BlockedTools) != 0 {
		t.Errorf("expected no blocked tools (disabled pack), got %v", result.BlockedTools)
	}
}

func TestLoadMCPPacks_MultiplePacks(t *testing.T) {
	dir := t.TempDir()
	safety := `name: "Safety"
blocked_tools:
  - "run_shell"
rules:
  - id: safety-1
    match:
      tool_name: "evil"
    decision: "BLOCK"
    reason: "evil."
`
	secrets := `name: "Secrets"
blocked_tools:
  - "steal_creds"
resource_rules:
  - id: sec-1
    match:
      scheme: "redis"
    decision: "BLOCK"
    reason: "no redis."
`
	if err := os.WriteFile(filepath.Join(dir, "safety.yaml"), []byte(safety), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(secrets), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	result, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 2 {
		t.Fatalf("expected 2 pack infos, got %d", len(infos))
	}
	if len(result.BlockedTools) != 2 {
		t.Errorf("expected 2 blocked tools, got %d: %v", len(result.BlockedTools), result.BlockedTools)
	}
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(result.Rules))
	}
	if len(result.ResourceRules) != 1 {
		t.Errorf("expected 1 resource rule, got %d", len(result.ResourceRules))
	}
}

func TestLoadMCPPacks_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Not a pack"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("some notes"), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	_, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("expected 0 pack infos (non-YAML skipped), got %d", len(infos))
	}
}

func TestLoadMCPPacks_DoesNotMutateBase(t *testing.T) {
	dir := t.TempDir()
	pack := `name: "Mutator"
blocked_tools:
  - "new_tool"
rules:
  - id: new-rule
    match:
      tool_name: "x"
    decision: "BLOCK"
    reason: "x."
`
	if err := os.WriteFile(filepath.Join(dir, "mutator.yaml"), []byte(pack), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"original"},
	}

	result, _, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Base should be unchanged
	if len(base.BlockedTools) != 1 || base.BlockedTools[0] != "original" {
		t.Errorf("base policy was mutated: %v", base.BlockedTools)
	}
	if len(base.Rules) != 0 {
		t.Errorf("base rules were mutated: %v", base.Rules)
	}

	// Result should have merged content
	if len(result.BlockedTools) != 2 {
		t.Errorf("expected 2 blocked tools in result, got %d", len(result.BlockedTools))
	}
	if len(result.Rules) != 1 {
		t.Errorf("expected 1 rule in result, got %d", len(result.Rules))
	}
}

func TestLoadMCPPacks_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("{{{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	base := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	result, infos, err := LoadMCPPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Invalid pack should still be reported but not merged
	if len(infos) != 1 {
		t.Fatalf("expected 1 pack info (even if invalid), got %d", len(infos))
	}
	if infos[0].Name != "bad" {
		t.Errorf("expected pack name 'bad', got %q", infos[0].Name)
	}
	// Policy should be untouched
	if len(result.BlockedTools) != 0 {
		t.Errorf("expected no blocked tools, got %v", result.BlockedTools)
	}
}
