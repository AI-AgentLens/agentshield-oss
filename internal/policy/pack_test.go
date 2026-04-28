package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPacks_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(infos) != 0 {
		t.Errorf("expected 0 pack infos, got %d", len(infos))
	}
	if len(result.Rules) != len(base.Rules) {
		t.Errorf("expected %d rules, got %d", len(base.Rules), len(result.Rules))
	}
}

func TestLoadPacks_NonExistentDir(t *testing.T) {
	base := DefaultPolicy()
	result, _, err := LoadPacks("/nonexistent/path/packs", base)
	if err != nil {
		t.Fatalf("unexpected error for non-existent dir: %v", err)
	}
	if len(result.Rules) != len(base.Rules) {
		t.Errorf("expected base rules unchanged")
	}
}

func TestLoadPacks_MergesRules(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	baseRuleCount := len(base.Rules)

	packYAML := `
name: "Test Pack"
description: "A test pack"
version: "1.0.0"
author: "Test"
rules:
  - id: "test-block-evil"
    match:
      command_exact: "evil-command"
    decision: "BLOCK"
    reason: "Evil command blocked by test pack"
  - id: "test-audit-stuff"
    match:
      command_prefix: ["suspicious "]
    decision: "AUDIT"
    reason: "Suspicious command"
`
	if err := os.WriteFile(filepath.Join(dir, "test-pack.yaml"), []byte(packYAML), 0644); err != nil {
		t.Fatal(err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(infos) != 1 {
		t.Fatalf("expected 1 pack info, got %d", len(infos))
	}
	if infos[0].Name != "Test Pack" {
		t.Errorf("expected pack name 'Test Pack', got %q", infos[0].Name)
	}
	if infos[0].RuleCount != 2 {
		t.Errorf("expected 2 rules in pack, got %d", infos[0].RuleCount)
	}
	if !infos[0].Enabled {
		t.Error("expected pack to be enabled")
	}

	expectedRules := baseRuleCount + 2
	if len(result.Rules) != expectedRules {
		t.Errorf("expected %d merged rules, got %d", expectedRules, len(result.Rules))
	}
}

func TestLoadPacks_DisabledPack(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	baseRuleCount := len(base.Rules)

	packYAML := `
name: "Disabled Pack"
rules:
  - id: "disabled-rule"
    match:
      command_exact: "should-not-apply"
    decision: "BLOCK"
    reason: "Should not be loaded"
`
	// Prefix with underscore to disable
	if err := os.WriteFile(filepath.Join(dir, "_disabled-pack.yaml"), []byte(packYAML), 0644); err != nil {
		t.Fatal(err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(infos) != 1 {
		t.Fatalf("expected 1 pack info, got %d", len(infos))
	}
	if infos[0].Enabled {
		t.Error("expected pack to be disabled")
	}

	// Rules should NOT be merged
	if len(result.Rules) != baseRuleCount {
		t.Errorf("disabled pack rules should not merge: expected %d, got %d", baseRuleCount, len(result.Rules))
	}
}

func TestLoadPacks_MergesProtectedPaths(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	basePathCount := len(base.Defaults.ProtectedPaths)

	packYAML := `
name: "Path Pack"
defaults:
  protected_paths:
    - "~/.npmrc"
    - "~/.pypirc"
    - "~/.ssh/**"
rules: []
`
	if err := os.WriteFile(filepath.Join(dir, "paths.yaml"), []byte(packYAML), 0644); err != nil {
		t.Fatal(err)
	}

	result, _, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ~/.ssh/** already exists in base, so only 2 new paths should be added
	expectedPaths := basePathCount + 2
	if len(result.Defaults.ProtectedPaths) != expectedPaths {
		t.Errorf("expected %d protected paths, got %d: %v",
			expectedPaths, len(result.Defaults.ProtectedPaths), result.Defaults.ProtectedPaths)
	}
}

func TestLoadPacks_MultiplePacks(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	baseRuleCount := len(base.Rules)

	pack1 := `
name: "Pack A"
rules:
  - id: "a-rule"
    match:
      command_exact: "cmd-a"
    decision: "BLOCK"
    reason: "Pack A rule"
`
	pack2 := `
name: "Pack B"
rules:
  - id: "b-rule-1"
    match:
      command_exact: "cmd-b1"
    decision: "AUDIT"
    reason: "Pack B rule 1"
  - id: "b-rule-2"
    match:
      command_exact: "cmd-b2"
    decision: "BLOCK"
    reason: "Pack B rule 2"
`
	if err := os.WriteFile(filepath.Join(dir, "a-pack.yaml"), []byte(pack1), 0644); err != nil {
		t.Fatalf("Failed to write a-pack.yaml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b-pack.yaml"), []byte(pack2), 0644); err != nil {
		t.Fatalf("Failed to write b-pack.yaml: %v", err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(infos) != 2 {
		t.Fatalf("expected 2 pack infos, got %d", len(infos))
	}

	expectedRules := baseRuleCount + 3
	if len(result.Rules) != expectedRules {
		t.Errorf("expected %d merged rules, got %d", expectedRules, len(result.Rules))
	}
}

func TestLoadPacks_DoesNotMutateBase(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	baseRuleCount := len(base.Rules)
	basePathCount := len(base.Defaults.ProtectedPaths)

	packYAML := `
name: "Mutation Test"
defaults:
  protected_paths:
    - "~/.extra/**"
rules:
  - id: "extra-rule"
    match:
      command_exact: "extra"
    decision: "BLOCK"
    reason: "Extra"
`
	if err := os.WriteFile(filepath.Join(dir, "mutation.yaml"), []byte(packYAML), 0644); err != nil {
		t.Fatalf("Failed to write mutation.yaml: %v", err)
	}

	if _, _, err := LoadPacks(dir, base); err != nil {
		t.Fatalf("LoadPacks failed: %v", err)
	}

	// Base should be unchanged
	if len(base.Rules) != baseRuleCount {
		t.Errorf("base rules were mutated: expected %d, got %d", baseRuleCount, len(base.Rules))
	}
	if len(base.Defaults.ProtectedPaths) != basePathCount {
		t.Errorf("base protected paths were mutated: expected %d, got %d", basePathCount, len(base.Defaults.ProtectedPaths))
	}
}
