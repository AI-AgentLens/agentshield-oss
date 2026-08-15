package policy

import (
	"os"
	"path/filepath"
	"strings"
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

// TestLoadPacks_MalformedPackRecordsError is the regression guard for issue
// #2188: a pack that fails to parse must NOT be silently dropped. The failure
// is recorded in PackInfo.LoadError, loading continues for the other packs, and
// FailedPacks surfaces exactly the broken one.
func TestLoadPacks_MalformedPackRecordsError(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()
	baseRuleCount := len(base.Rules)

	valid := `
name: "Good Pack"
rules:
  - id: "good-rule"
    match:
      command_exact: "good-cmd"
    decision: "BLOCK"
    reason: "ok"
`
	// Unquoted colon inside a scalar value — the exact shape from the #2188
	// reproducer. yaml.v3 returns a parse error for this (verified empirically).
	malformed := `
name: "Bad Pack"
rules:
  - id: "bad-rule"
    match:
      command_exact: "x"
    decision: "BLOCK"
    reason: docs: explain pip install git+https:// supply chain risks
`
	if err := os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(valid), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("LoadPacks should not hard-fail when one pack is malformed: %v", err)
	}

	// The good pack's rule must load; the bad pack contributes nothing.
	if len(result.Rules) != baseRuleCount+1 {
		t.Errorf("expected %d rules (base + good pack), got %d", baseRuleCount+1, len(result.Rules))
	}

	var good, bad *PackInfo
	for i := range infos {
		switch infos[i].Path {
		case filepath.Join(dir, "good.yaml"):
			good = &infos[i]
		case filepath.Join(dir, "bad.yaml"):
			bad = &infos[i]
		}
	}
	if good == nil {
		t.Fatal("good pack missing from infos")
	}
	if good.LoadError != nil {
		t.Errorf("good pack should have no LoadError, got %v", good.LoadError)
	}
	if bad == nil {
		t.Fatal("malformed pack vanished from infos — #2188 regression (silent swallow)")
	}
	if bad.LoadError == nil {
		t.Error("malformed pack must record LoadError, got nil — #2188 regression")
	}
	if bad.RuleCount != 0 {
		t.Errorf("malformed pack must report 0 rules, got %d", bad.RuleCount)
	}

	failed := FailedPacks(infos)
	if len(failed) != 1 {
		t.Fatalf("expected FailedPacks to return 1 pack, got %d", len(failed))
	}
	if failed[0].Path != filepath.Join(dir, "bad.yaml") {
		t.Errorf("FailedPacks returned wrong pack: %s", failed[0].Path)
	}
}

// TestLoadPacks_MalformedSubdirPackRecordsError covers the analyzer-type
// subdirectory load path (packs/regex/, packs/structural/, …) — the second of
// the three #2188 silent-swallow sites.
func TestLoadPacks_MalformedSubdirPackRecordsError(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()

	sub := filepath.Join(dir, "regex")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	// Tab indentation is a hard YAML lexer error.
	malformed := "name: Bad\nrules:\n\t- id: bad"
	if err := os.WriteFile(filepath.Join(sub, "bad.yaml"), []byte(malformed), 0644); err != nil {
		t.Fatal(err)
	}

	_, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("LoadPacks should not hard-fail on a malformed subdir pack: %v", err)
	}
	failed := FailedPacks(infos)
	if len(failed) != 1 {
		t.Fatalf("expected 1 failed subdir pack, got %d (infos=%+v)", len(failed), infos)
	}
	if failed[0].LoadError == nil {
		t.Error("subdir malformed pack must record LoadError — #2188 regression")
	}
}

// TestLoadPacks_SkipsMCPSubdir reproduces #2219: a `make deploy` (pre-fix) or a
// legacy install can leave MCP-protocol packs under ~/.agentshield/packs/mcp/.
// Those use the MCP schema (tool/args test cases) the terminal loader cannot
// parse — before the skip, LoadPacks recursed into mcp/ and surfaced a spurious
// "cannot unmarshal !!map into string" failure that #2188's loud reporting then
// flagged as degraded enforcement. The terminal loader must skip mcp/ entirely:
// no error, no FailedPacks entry, and no rules merged from it.
func TestLoadPacks_SkipsMCPSubdir(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()

	mcpDir := filepath.Join(dir, "mcp")
	if err := os.MkdirAll(mcpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// An MCP-schema pack: the `tests.tp[].args` map is what blows up the terminal
	// loader (it expects a string there). Mirrors packs/premium/mcp/*.yaml.
	mcpPack := "name: mcp-creds\n" +
		"rules:\n" +
		"  - id: block-creds\n" +
		"    match:\n" +
		"      tool_name: read_file\n" +
		"      argument_patterns:\n" +
		"        path: \"**/.e2b/**\"\n" +
		"    decision: BLOCK\n" +
		"    reason: blocked\n" +
		"    tests:\n" +
		"      tp:\n" +
		"        - tool: read_file\n" +
		"          args: {\"path\": \"/home/user/.e2b/config\"}\n"
	if err := os.WriteFile(filepath.Join(mcpDir, "mcp-creds.yaml"), []byte(mcpPack), 0644); err != nil {
		t.Fatal(err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("LoadPacks must not hard-fail when an mcp/ subdir is present: %v", err)
	}
	if failed := FailedPacks(infos); len(failed) != 0 {
		t.Errorf("mcp/ subdir must be skipped, not parsed as terminal packs — got %d failed pack(s): %+v (#2219 regression)", len(failed), failed)
	}
	for _, info := range infos {
		if strings.Contains(info.Path, filepath.Join("mcp", "")) || strings.Contains(info.Name, "mcp-creds") {
			t.Errorf("mcp/ pack leaked into terminal pack infos: %+v (#2219 regression)", info)
		}
	}
	// No rules from the mcp pack should have merged into the terminal policy.
	if len(result.Rules) != len(base.Rules) {
		t.Errorf("mcp/ subdir rules must not merge into terminal policy: base had %d rules, got %d", len(base.Rules), len(result.Rules))
	}
}

// TestLoadPacks_SkipsFlatMCPPack covers the flat-file half of #2219: an older
// `agentshield update` wrote MCP packs as mcp-*.yaml directly into packs/ (not a
// subdir). The terminal loader must skip them by name — no error, no spurious
// FailedPacks entry — while still loading the sibling terminal pack normally.
func TestLoadPacks_SkipsFlatMCPPack(t *testing.T) {
	dir := t.TempDir()
	base := DefaultPolicy()

	// MCP-schema pack flat in packs/ — would fail to parse as a terminal pack.
	mcpPack := "name: mcp-creds\n" +
		"rules:\n" +
		"  - id: block-creds\n" +
		"    match:\n" +
		"      tool_name: read_file\n" +
		"    decision: BLOCK\n" +
		"    reason: blocked\n" +
		"    tests:\n" +
		"      tp:\n" +
		"        - tool: read_file\n" +
		"          args: {\"path\": \"/x/.e2b/config\"}\n"
	if err := os.WriteFile(filepath.Join(dir, "mcp-creds.yaml"), []byte(mcpPack), 0644); err != nil {
		t.Fatal(err)
	}
	// A legitimate terminal pack sitting alongside it must still load.
	termPack := "name: term\nrules:\n  - id: t1\n    match:\n      command_regex: \"rm -rf /\"\n    decision: BLOCK\n    reason: r\n"
	if err := os.WriteFile(filepath.Join(dir, "terminal-x.yaml"), []byte(termPack), 0644); err != nil {
		t.Fatal(err)
	}

	result, infos, err := LoadPacks(dir, base)
	if err != nil {
		t.Fatalf("LoadPacks must not hard-fail on a flat mcp-*.yaml: %v", err)
	}
	if failed := FailedPacks(infos); len(failed) != 0 {
		t.Errorf("flat mcp-*.yaml must be skipped, not parsed — got %d failed pack(s): %+v (#2219 regression)", len(failed), failed)
	}
	for _, info := range infos {
		if strings.HasPrefix(strings.ToLower(info.Name), "mcp-") || strings.Contains(info.Path, "mcp-creds") {
			t.Errorf("flat mcp pack leaked into terminal infos: %+v (#2219 regression)", info)
		}
	}
	// The terminal pack's rule must have merged; the mcp pack's must not.
	if len(result.Rules) != len(base.Rules)+1 {
		t.Errorf("expected exactly the terminal pack's 1 rule merged: base %d, got %d", len(base.Rules), len(result.Rules))
	}
}

func TestFailedPacks_NoneFailed(t *testing.T) {
	infos := []PackInfo{{Name: "a", RuleCount: 3}, {Name: "b", RuleCount: 5}}
	if got := FailedPacks(infos); len(got) != 0 {
		t.Errorf("expected no failed packs, got %d", len(got))
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
