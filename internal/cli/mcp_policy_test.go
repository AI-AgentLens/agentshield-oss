package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// withFakeHome points $HOME at a temp dir and resets the package-level CLI
// flags that loadDeployedMCPPolicy reads through config.Load.
func withFakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	oldPolicyPath, oldLogPath, oldMode, oldMCPPolicyPath := policyPath, logPath, mode, mcpPolicyPath
	t.Cleanup(func() {
		policyPath, logPath, mode, mcpPolicyPath = oldPolicyPath, oldLogPath, oldMode, oldMCPPolicyPath
	})
	policyPath = ""
	logPath = ""
	mode = "enforce"
	mcpPolicyPath = ""

	return home
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func evalDecision(t *testing.T, p *mcp.MCPPolicy, tool string, args map[string]interface{}) policy.Decision {
	t.Helper()
	return mcp.NewPolicyEvaluator(p).EvaluateToolCall(tool, args).Decision
}

// TestLoadDeployedMCPPolicy_PolicyFileBlocksTool — happy path: a user policy
// at the default location (~/.agentshield/mcp-policy.yaml) blocks a tool.
func TestLoadDeployedMCPPolicy_PolicyFileBlocksTool(t *testing.T) {
	home := withFakeHome(t)
	writeFile(t, filepath.Join(home, ".agentshield", "mcp-policy.yaml"),
		"defaults:\n  decision: \"AUDIT\"\nblocked_tools:\n  - \"get_weather\"\n")

	loaded := loadDeployedMCPPolicy("")
	if d := evalDecision(t, loaded.Policy, "get_weather", map[string]interface{}{"location": "NYC"}); d != policy.DecisionBlock {
		t.Fatalf("get_weather decision = %s, want BLOCK", d)
	}
	if len(loaded.Warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", loaded.Warnings)
	}
}

// TestLoadDeployedMCPPolicy_NoPolicyFile_EmbeddedRulesEnforce — no user policy
// file, no disk packs. The embedded community packs (mcp-safety etc.) must
// still enforce; in particular `execute_command` is in the default blocklist.
// This locks in the property: a fresh install always has working protection.
func TestLoadDeployedMCPPolicy_NoPolicyFile_EmbeddedRulesEnforce(t *testing.T) {
	withFakeHome(t)

	loaded := loadDeployedMCPPolicy("")
	if len(loaded.Embedded) == 0 {
		t.Fatalf("expected embedded packs to be loaded, got 0")
	}
	if d := evalDecision(t, loaded.Policy, "execute_command", map[string]interface{}{"cmd": "ls"}); d != policy.DecisionBlock {
		t.Fatalf("execute_command decision = %s, want BLOCK (embedded default)", d)
	}
}

// TestLoadDeployedMCPPolicy_OverridePathWins — explicit --mcp-policy path
// takes precedence over ~/.agentshield/mcp-policy.yaml.
func TestLoadDeployedMCPPolicy_OverridePathWins(t *testing.T) {
	home := withFakeHome(t)
	writeFile(t, filepath.Join(home, ".agentshield", "mcp-policy.yaml"),
		"blocked_tools:\n  - \"get_weather\"\n")
	override := filepath.Join(home, "override-policy.yaml")
	writeFile(t, override, "blocked_tools:\n  - \"send_email\"\n")

	loaded := loadDeployedMCPPolicy(override)
	if loaded.PolicyPath != override {
		t.Fatalf("PolicyPath = %s, want override %s", loaded.PolicyPath, override)
	}
	if d := evalDecision(t, loaded.Policy, "send_email", nil); d != policy.DecisionBlock {
		t.Fatalf("send_email decision = %s, want BLOCK from override", d)
	}
	for _, t2 := range loaded.Policy.BlockedTools {
		if t2 == "get_weather" {
			t.Fatalf("override policy should not have inherited get_weather from default mcp-policy.yaml")
		}
	}
}

// TestLoadDeployedMCPPolicy_LegacyFallbackOnlyWhenNewEmpty — the legacy
// ~/.agentshield/packs/mcp directory must only be consulted when the new
// ~/.agentshield/mcp-packs directory is empty. Otherwise users with both
// directories populated would silently double-load policy.
func TestLoadDeployedMCPPolicy_LegacyFallbackOnlyWhenNewEmpty(t *testing.T) {
	home := withFakeHome(t)
	configDir := filepath.Join(home, ".agentshield")

	newPack := `name: new-pack
version: "1.0"
blocked_tools: ["new_only_tool"]
`
	legacyPack := `name: legacy-pack
version: "1.0"
blocked_tools: ["legacy_only_tool"]
`

	writeFile(t, filepath.Join(configDir, "mcp-packs", "new.yaml"), newPack)
	writeFile(t, filepath.Join(configDir, "packs", "mcp", "legacy.yaml"), legacyPack)

	loaded := loadDeployedMCPPolicy("")
	if len(loaded.Disk) != 1 || loaded.Disk[0].Name != "new-pack" {
		t.Fatalf("Disk packs = %+v, want exactly [new-pack]", loaded.Disk)
	}
	if len(loaded.LegacyDisk) != 0 {
		t.Fatalf("LegacyDisk = %+v, expected empty when new dir non-empty", loaded.LegacyDisk)
	}
	if d := evalDecision(t, loaded.Policy, "new_only_tool", nil); d != policy.DecisionBlock {
		t.Fatalf("new_only_tool decision = %s, want BLOCK", d)
	}
	if d := evalDecision(t, loaded.Policy, "legacy_only_tool", nil); d == policy.DecisionBlock {
		t.Fatalf("legacy_only_tool was BLOCKED — legacy pack must NOT load when new dir is populated")
	}

	if err := os.RemoveAll(filepath.Join(configDir, "mcp-packs")); err != nil {
		t.Fatalf("remove new packs dir: %v", err)
	}
	loaded = loadDeployedMCPPolicy("")
	if len(loaded.LegacyDisk) != 1 || loaded.LegacyDisk[0].Name != "legacy-pack" {
		t.Fatalf("LegacyDisk = %+v, want [legacy-pack] after new dir removed", loaded.LegacyDisk)
	}
	if d := evalDecision(t, loaded.Policy, "legacy_only_tool", nil); d != policy.DecisionBlock {
		t.Fatalf("legacy_only_tool decision = %s, want BLOCK from legacy fallback", d)
	}
}

// TestLoadDeployedMCPPolicy_MalformedPolicyFallsBackToEmbedded — a malformed
// user mcp-policy.yaml must NOT cause the loader to skip embedded community
// rules. This is the regression guard against fail-open in managed mode.
func TestLoadDeployedMCPPolicy_MalformedPolicyFallsBackToEmbedded(t *testing.T) {
	home := withFakeHome(t)
	// yaml.v3 errors on a sequence indicator after a mapping key, plus an
	// unclosed flow sequence. Verified manually that this triggers an error
	// from gopkg.in/yaml.v3 — without that, the test would silently pass on
	// the wrong path.
	writeFile(t, filepath.Join(home, ".agentshield", "mcp-policy.yaml"),
		"blocked_tools:\n  - \"send\"\n  bad_indent: [unclosed\n")

	loaded := loadDeployedMCPPolicy("")

	if len(loaded.Warnings) == 0 {
		t.Fatalf("expected a warning for malformed policy, got none")
	}
	foundParseWarning := false
	for _, w := range loaded.Warnings {
		if strings.Contains(w, "could not be parsed") {
			foundParseWarning = true
		}
	}
	if !foundParseWarning {
		t.Fatalf("warnings = %v, expected one mentioning 'could not be parsed'", loaded.Warnings)
	}

	if d := evalDecision(t, loaded.Policy, "execute_command", map[string]interface{}{"cmd": "ls"}); d != policy.DecisionBlock {
		t.Fatalf("execute_command decision = %s after malformed policy; want BLOCK from embedded fallback", d)
	}
}

// TestLoadDeployedMCPPolicy_LegacyDoesNotDuplicateEmbedded — issue #1628.
// When ~/.agentshield/mcp-packs is empty and ~/.agentshield/packs/mcp contains
// stale community packs (a pre-2026-04 install state), the legacy fallback
// must NOT re-merge them: the embedded layer is authoritative and re-merging
// produces duplicate rules with subtly different reason wording. This test
// plants a fake legacy pack with the same Name as a real embedded one and
// verifies the loader skips it.
func TestLoadDeployedMCPPolicy_LegacyDoesNotDuplicateEmbedded(t *testing.T) {
	home := withFakeHome(t)

	// First call: discover a real embedded pack name we can collide with.
	probe := loadDeployedMCPPolicy("")
	if len(probe.Embedded) == 0 {
		t.Skip("no embedded MCP packs in this binary")
	}
	embeddedName := probe.Embedded[0].Name

	legacyDir := filepath.Join(home, ".agentshield", "packs", "mcp")
	// Pack 1: collides with embedded — must be skipped.
	writeFile(t, filepath.Join(legacyDir, "stale.yaml"), `name: `+embeddedName+`
version: "0.0.1"
blocked_tools: ["sentinel_should_not_appear"]
`)
	// Pack 2: unique name — must load (proves the legacy path itself works).
	writeFile(t, filepath.Join(legacyDir, "user-custom.yaml"), `name: legacy-user-custom-pack
version: "1.0"
blocked_tools: ["sentinel_user_custom"]
`)

	loaded := loadDeployedMCPPolicy("")

	for _, p := range loaded.LegacyDisk {
		if p.Name == embeddedName {
			t.Fatalf("LegacyDisk includes pack %q that conflicts with embedded — should have been skipped", embeddedName)
		}
	}

	hasSentinel := false
	hasUserCustom := false
	for _, bt := range loaded.Policy.BlockedTools {
		if bt == "sentinel_should_not_appear" {
			hasSentinel = true
		}
		if bt == "sentinel_user_custom" {
			hasUserCustom = true
		}
	}
	if hasSentinel {
		t.Error("legacy stale pack's BlockedTool leaked into policy — dedupe failed")
	}
	if !hasUserCustom {
		t.Error("legacy user-custom pack should still load when its name doesn't collide")
	}
}
