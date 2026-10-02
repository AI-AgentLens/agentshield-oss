package cli

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Output shape of `pack list`: shell section as before, plus an MCP section
// (embedded and on-disk) with per-pack rule counts, plus the explicit label
// on a community shell pack that is loaded from both the binary and disk.
func TestRenderPackList_ShowsMCPAndLabelsDoubleLoadedShellPacks(t *testing.T) {
	embedded := []policy.PackInfo{
		{Name: "terminal-safety", Description: "Core shell rules", Version: "3.1.0", Author: "AI Agent Lens", Enabled: true, RuleCount: 500},
	}
	disk := []policy.PackInfo{
		{Name: "terminal-safety", Description: "Core shell rules", Version: "3.0.0", Author: "AI Agent Lens", Enabled: true, RuleCount: 480, Path: "/x/packs/terminal-safety.yaml"},
		{Name: "network-egress", Description: "Premium egress rules", Version: "1.2.0", Author: "AI Agent Lens", Enabled: true, RuleCount: 40, Path: "/x/packs/network-egress.yaml"},
		{Name: "broken", Enabled: true, Path: "/x/packs/broken.yaml", LoadError: errors.New("yaml: line 3: boom")},
	}
	mcpLoaded := &loadedMCPPolicy{
		Embedded: []mcp.MCPPackInfo{
			{Name: "mcp-safety", Version: "2.0.0", Enabled: true, RuleCount: 76},
			{Name: "mcp-secrets", Version: "2.0.0", Enabled: true, RuleCount: 452},
		},
		Disk: []mcp.MCPPackInfo{
			{Name: "mcp-custom", Version: "0.1.0", Enabled: true, RuleCount: 3, Path: "/x/mcp-packs/mcp-custom.yaml"},
		},
		PacksDir:  "/x/mcp-packs",
		LegacyDir: "/x/packs/mcp",
	}

	var out bytes.Buffer
	if err := renderPackList(&out, "/x/packs", embedded, disk, mcpLoaded); err != nil {
		t.Fatal(err)
	}
	got := out.String()

	for _, want := range []string{
		"Built-in (embedded) Policy Packs:",
		"Installed (on-disk) Policy Packs:",
		"v3.1.0 by AI Agent Lens  (500 rules)",
		"v3.0.0 by AI Agent Lens  (480 rules)",
		"also embedded in the binary",
		"FAILED to parse — 0 rules loaded",
		"Built-in (embedded) MCP Packs:",
		"mcp-safety                v2.0.0  (76 rules)",
		"mcp-secrets               v2.0.0  (452 rules)",
		"Installed (on-disk) MCP Packs:",
		"mcp-custom                v0.1.0  (3 rules)",
		"MCP packs directory: /x/mcp-packs",
		"blocked_tools are enforced but are not rules",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\n%s", want, got)
		}
	}
	// The label attaches to the duplicated pack only: once, and not to the
	// premium pack that has no embedded twin.
	if n := strings.Count(got, "also embedded in the binary"); n != 1 {
		t.Errorf("double-load label appears %d times, want exactly 1\n%s", n, got)
	}
	if strings.Contains(got, "Legacy (on-disk) MCP Packs") {
		t.Errorf("legacy section rendered with no legacy packs\n%s", got)
	}
	// Ordering: shell before MCP, embedded before on-disk within each.
	idx := func(s string) int { return strings.Index(got, s) }
	if !(idx("Built-in (embedded) Policy Packs:") < idx("Installed (on-disk) Policy Packs:") &&
		idx("Installed (on-disk) Policy Packs:") < idx("Built-in (embedded) MCP Packs:") &&
		idx("Built-in (embedded) MCP Packs:") < idx("Installed (on-disk) MCP Packs:")) {
		t.Errorf("sections out of order\n%s", got)
	}
}

func TestRenderPackList_LegacyMCPSectionOnlyWhenPresent(t *testing.T) {
	mcpLoaded := &loadedMCPPolicy{
		Embedded:   []mcp.MCPPackInfo{{Name: "mcp-safety", Enabled: true, RuleCount: 1}},
		LegacyDisk: []mcp.MCPPackInfo{{Name: "mcp-old", Enabled: true, RuleCount: 2, Path: "/x/packs/mcp/mcp-old.yaml"}},
		PacksDir:   "/x/mcp-packs",
		LegacyDir:  "/x/packs/mcp",
	}
	var out bytes.Buffer
	if err := renderPackList(&out, "/x/packs", nil, nil, mcpLoaded); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Legacy (on-disk) MCP Packs — /x/packs/mcp, loaded only because /x/mcp-packs is empty:") {
		t.Errorf("legacy section missing or mislabeled\n%s", out.String())
	}
}

func TestRenderPackList_NothingAtAll(t *testing.T) {
	var out bytes.Buffer
	if err := renderPackList(&out, "/x/packs", nil, nil, &loadedMCPPolicy{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No policy packs available.") {
		t.Errorf("empty-state message missing\n%s", out.String())
	}
}

// End to end against the real embedded layer plus a fake $HOME: the MCP
// section lists the embedded community packs with the five-family count, and
// a disk MCP pack shows up with its own count.
func TestPackList_RealEmbeddedLayerPlusDiskMCPPack(t *testing.T) {
	home := withFakeHome(t)
	writeFile(t, filepath.Join(home, ".agentshield", "mcp-packs", "mcp-custom.yaml"), `name: mcp-custom
version: "0.1.0"
blocked_tools:
  - not_a_rule_tool
rules:
  - id: custom-mcp-one
    match: {tool_name_any: ["frob_tool"]}
    decision: BLOCK
    reason: test
`)
	base := policy.DefaultPolicy()
	_, embedded, _ := policy.LoadEmbeddedShellPacks(base)
	_, disk, err := policy.LoadPacks(filepath.Join(home, ".agentshield", "packs"), base)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := renderPackList(&out, filepath.Join(home, ".agentshield", "packs"), embedded, disk, loadDeployedMCPPolicy("")); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "Built-in (embedded) MCP Packs:") || !strings.Contains(got, "MCP Secrets & Credentials") {
		t.Errorf("embedded MCP packs not listed\n%s", got)
	}
	// blocked_tools is not a rule: the disk pack has exactly one.
	if !strings.Contains(got, "mcp-custom                v0.1.0  (1 rules)") {
		t.Errorf("disk MCP pack missing or counted wrong (blocked_tools must not count)\n%s", got)
	}
}
