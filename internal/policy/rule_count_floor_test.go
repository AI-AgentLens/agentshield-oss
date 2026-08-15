package policy

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// TestEmbeddedPacks_RuleCountFloor is a per-pack fitness function that catches
// silent yaml.v3 parsing breakage — specifically the list-vs-map ambiguity
// where an unquoted colon in a YAML list entry causes yaml.v3 to parse the
// entire list as a map, silently dropping ALL entries without returning an error.
//
// This happened with terminal-safety.yaml (700+ rules silently disappeared).
// A single aggregate check (the existing >=100 test) would not catch a single
// pack losing all its rules if the other pack still contributed enough.
//
// Floors are set at ~80% of the rule count at time of writing (2026-05-04).
// If a pack legitimately shrinks, update the floor — the test makes the
// change explicit rather than silent.
//
// Ref: https://github.com/AI-AgentLens/agentshield-oss/issues/1673
func TestEmbeddedPacks_RuleCountFloor(t *testing.T) {
	// Per-file minimum rule counts for community shell packs.
	// Keys are bare filenames as returned by packs.ShellFiles().
	shellFloors := map[string]int{
		"terminal-safety.yaml": 560, // actual: ~711
		"secrets-pii.yaml":     80,  // actual: ~106
		"ci-context.yaml":      2,   // actual: 2 (issue #3291 CI-context tightening pack)
	}

	shellFiles := packs.ShellFiles()
	if len(shellFiles) == 0 {
		t.Fatal("packs.ShellFiles() returned no files — //go:embed community/*.yaml regressed?")
	}

	// Verify every expected pack file is present.
	for name := range shellFloors {
		if _, ok := shellFiles[name]; !ok {
			t.Errorf("expected shell pack %q not found in embedded files; available: %v",
				name, fileNames(shellFiles))
		}
	}

	// Check rule counts per shell pack.
	for name, data := range shellFiles {
		var pack Pack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			t.Errorf("failed to parse embedded shell pack %q: %v"+
				"\n  hint: yaml.v3 list-vs-map ambiguity? An unquoted colon in a YAML list entry "+
				"can cause the parser to silently treat the list as a map", name, err)
			continue
		}

		count := len(pack.Rules)
		floor, hasFloor := shellFloors[name]

		if hasFloor && count < floor {
			t.Errorf("shell pack %q has %d rules, expected >= %d"+
				"\n  hint: yaml.v3 can silently parse a YAML list entry with an unquoted colon as a map, "+
				"causing ALL rules in the file to disappear without any error. "+
				"If the drop is intentional, update the floor in this test.",
				name, count, floor)
		}

		// Log actual counts for visibility even when passing.
		t.Logf("shell pack %q: %d rules (floor: %d)", name, count, floor)

		if !hasFloor {
			t.Errorf("shell pack %q has no floor defined — add it to shellFloors in this test "+
				"(suggested floor: %d, which is ~80%% of current count %d)",
				name, int(float64(count)*0.8), count)
		}
	}
}

// TestEmbeddedMCPPacks_RuleCountFloor is the MCP-pack counterpart of
// TestEmbeddedPacks_RuleCountFloor. It guards against silent yaml.v3 parsing
// breakage in community MCP pack files.
//
// MCP packs have multiple rule types (rules, resource_rules, value_limits,
// structural_rules, semantic_rules, data_labels), so the floor covers total
// rule count across all types.
//
// Ref: https://github.com/AI-AgentLens/agentshield-oss/issues/1673
func TestEmbeddedMCPPacks_RuleCountFloor(t *testing.T) {
	// Per-file minimum total rule counts for community + premium MCP packs.
	// Keys are bare filenames as returned by packs.MCPFiles().
	mcpFloors := map[string]int{
		// Community MCP packs (always embedded).
		"mcp-safety.yaml":    65,  // actual: ~84
		"mcp-secrets.yaml":   360, // actual: ~452
		"mcp-generated.yaml": 15,  // actual: ~19

		// Premium MCP packs (included in full build, absent in OSS build).
		// The test handles missing premium packs gracefully — it only fails
		// if a pack IS present but below its floor.
		"mcp-sentinel.yaml":                    12, // actual: ~16
		"mcp-reconnaissance.yaml":              39, // actual: ~49
		"mcp-cloud-storage.yaml":               4,  // actual: ~6
		"mcp-response-integrity.yaml":          11, // actual: ~14
		"mcp-database-ops.yaml":                12, // actual: ~16
		"mcp-content-integrity.yaml":           24, // actual: ~31
		"mcp-llm-data-flow.yaml":               40, // actual: ~50
		"mcp-payment-creds.yaml":               8,  // actual: ~10
		"mcp-ide-workspace-trust.yaml":         5,  // actual: ~7
		"mcp-file-transfer.yaml":               6,  // actual: ~8
		"mcp-supply-chain-premium.yaml":        11, // actual: ~14
		"mcp-cloud-functions.yaml":             4,  // actual: ~6
		"mcp-devtool-creds.yaml":               107, // actual: ~134
		"mcp-governance.yaml":                  22, // actual: ~28
		"mcp-computer-use.yaml":                18, // actual: ~23
		"mcp-llm-inference.yaml":               8,  // actual: ~10
		"mcp-agent-platform-creds.yaml":        8,  // actual: ~11
		"mcp-social-media-weaponization.yaml":  3,  // actual: ~4
		"mcp-package-registry-redirect.yaml":   5,  // actual: ~7
		"mcp-vc-secret-weaponization.yaml":     7,  // actual: ~9
		"mcp-agentic-attacks.yaml":             4,  // actual: ~116 (post issue #2660)
		"mcp-persistence.yaml":                 36, // actual: ~46
		"mcp-knowledge-base.yaml":              4,  // actual: ~5
		"mcp-privilege-escalation.yaml":        26, // actual: ~33
		"mcp-excessive-agency.yaml":            4,  // actual: ~6
		"mcp-financial-weaponization.yaml":     4,  // actual: ~6
		"mcp-supply-chain.yaml":                31, // actual: ~39
		"mcp-financial.yaml":                   10, // actual: ~13
		"mcp-ticket-injection.yaml":            5,  // actual: 7 (premium pack, issue #1911)
		"mcp-calendar-event-prompt-injection.yaml":       4, // actual: 6 (premium pack, issue #2174)
		"mcp-llm-context-summarization-injection.yaml":   2, // actual: 3 (premium pack, issue #2175)
		"mcp-deepfake-auth-bypass.yaml":                          1, // actual: 2 (premium pack, issue #2234)
		"mcp-package-registry-metadata-injection.yaml":           4, // actual: 5 (premium pack, issue #2215)
		"mcp-oauth-consent.yaml":                                  3, // actual: 4 (premium pack, issue #2250)
		"mcp-payment-mandate-forgery.yaml":                        3, // actual: 4 (premium pack, issue #2271)
		"mcp-reasoning-monitor-evasion.yaml":                      1, // actual: 2 (premium pack, issue #2271)
		"mcp-agentic-browser-session-hijack.yaml":                 3, // actual: 4 (premium pack, issue #2272)
		"mcp-alt-path-arg-credential-access.yaml":                 5, // actual: 7 (premium pack, issue #2306)
		"mcp-messaging-channel-prompt-injection.yaml":             6, // actual: 8 (premium pack, issue #2535)
		"mcp-code-review-prompt-injection.yaml":                   4, // actual: 5 (premium pack, issue #2537)
		"mcp-sre-monitoring-integrity.yaml":                       3, // actual: 4 (premium pack, issue #2540)
		"mcp-merge-conflict-prompt-injection.yaml":                1, // actual: 1 (premium pack, issue #2545)
		"mcp-accessibility-tree-poisoning.yaml":                   4, // actual: 5 (premium pack, issue #2601)
		"mcp-ml-privacy-enforcement.yaml":                         1, // actual: 2 (premium pack, issue #2615)
		"mcp-build-script-injection.yaml":                         5, // actual: 7 (premium pack, issues #2647, #2658)
		"mcp-notebook-ci-hook-injection.yaml":                     3, // actual: 4 (premium pack, issue #2655)
		"mcp-cms-content-weaponization.yaml":                      5, // actual: 7 (premium pack, issues #2673, #2706)
		"mcp-iot-platform-weaponization.yaml":                     6, // actual: 8 (premium pack, issue #2704)
		"mcp-agentic-commerce-ranking-manipulation.yaml":          4, // actual: 5 (premium pack, issue #2909)
	}

	mcpFiles := packs.MCPFiles()
	if len(mcpFiles) == 0 {
		t.Fatal("packs.MCPFiles() returned no files — //go:embed community/mcp/*.yaml regressed?")
	}

	// We do NOT require all floors to be present — premium packs are absent in
	// the OSS build. We only check packs that ARE embedded.
	for name, data := range mcpFiles {
		var pack mcpPackForCounting
		if err := yaml.Unmarshal(data, &pack); err != nil {
			t.Errorf("failed to parse embedded MCP pack %q: %v"+
				"\n  hint: yaml.v3 list-vs-map ambiguity? An unquoted colon in a YAML list entry "+
				"can cause the parser to silently treat the list as a map", name, err)
			continue
		}

		count := pack.totalRules()
		floor, hasFloor := mcpFloors[name]

		if hasFloor && count < floor {
			t.Errorf("MCP pack %q has %d total rules, expected >= %d"+
				"\n  hint: yaml.v3 can silently parse a YAML list entry with an unquoted colon as a map, "+
				"causing ALL rules in the file to disappear without any error. "+
				"If the drop is intentional, update the floor in this test.",
				name, count, floor)
		}

		t.Logf("MCP pack %q: %d total rules (floor: %d)", name, count, floor)

		if !hasFloor {
			t.Errorf("MCP pack %q has no floor defined — add it to mcpFloors in this test "+
				"(suggested floor: %d, which is ~80%% of current count %d)",
				name, int(float64(count)*0.8), count)
		}
	}
}

// mcpPackForCounting is a lightweight struct that only cares about counting
// rule entries across all MCP rule types. Using a dedicated type avoids
// importing internal/mcp (which would create a circular dependency).
type mcpPackForCounting struct {
	Rules           []yaml.Node `yaml:"rules,omitempty"`
	ResourceRules   []yaml.Node `yaml:"resource_rules,omitempty"`
	ValueLimits     []yaml.Node `yaml:"value_limits,omitempty"`
	StructuralRules []yaml.Node `yaml:"structural_rules,omitempty"`
	SemanticRules   []yaml.Node `yaml:"semantic_rules,omitempty"`
	DataLabels      []yaml.Node `yaml:"data_labels,omitempty"`
	BlockedTools    []string    `yaml:"blocked_tools,omitempty"`
}

func (p *mcpPackForCounting) totalRules() int {
	return len(p.Rules) + len(p.ResourceRules) + len(p.ValueLimits) +
		len(p.StructuralRules) + len(p.SemanticRules) + len(p.DataLabels) +
		len(p.BlockedTools)
}

func fileNames(m map[string][]byte) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	return names
}

