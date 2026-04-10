package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/packs"
	"gopkg.in/yaml.v3"
)

// DefaultMCPPolicyFile is the filename for MCP-specific policy within ~/.agentshield/.
const DefaultMCPPolicyFile = "mcp-policy.yaml"

// DefaultMCPPacksDir is the subdirectory name for MCP packs within ~/.agentshield/.
const DefaultMCPPacksDir = "mcp-packs"

// MCPPack represents a single MCP policy pack loaded from YAML.
type MCPPack struct {
	Name             string              `yaml:"name"`
	Description      string              `yaml:"description"`
	Version          string              `yaml:"version"`
	Author           string              `yaml:"author"`
	BlockedTools     []string            `yaml:"blocked_tools,omitempty"`
	BlockedResources []string            `yaml:"blocked_resources,omitempty"`
	Rules            []MCPRule           `yaml:"rules,omitempty"`
	ResourceRules    []ResourceRule      `yaml:"resource_rules,omitempty"`
	ValueLimits      []ValueLimitRule    `yaml:"value_limits,omitempty"`
	StructuralRules  []MCPStructuralRule `yaml:"structural_rules,omitempty"`
	SemanticRules    []MCPSemanticRule   `yaml:"semantic_rules,omitempty"`
	DataLabels       []policy.DataLabel  `yaml:"data_labels,omitempty"`
}

// MCPPackInfo describes a loaded MCP pack for reporting.
type MCPPackInfo struct {
	Name        string
	Description string
	Version     string
	Author      string
	Enabled     bool
	Path        string
	RuleCount   int
}

// LoadMCPPolicy reads an MCP policy from the given YAML file path.
// If the file doesn't exist, returns a sensible default policy.
func LoadMCPPolicy(path string) (*MCPPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultMCPPolicy(), nil
		}
		return nil, err
	}

	var p MCPPolicy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}

	if p.Defaults.Decision == "" {
		p.Defaults.Decision = policy.DecisionAudit
	}

	return &p, nil
}

// DefaultMCPPolicy returns a minimal-footprint base policy.
//
// It intentionally contains only structural defaults and the most critical
// shell-execution blocked-tool names. All substantive security rules live in
// packs/community/mcp/*.yaml (mcp-safety.yaml, mcp-secrets.yaml, mcp-financial.yaml)
// — embedded into the binary via packs.MCPFiles() — and are merged on top of
// this policy at startup.
//
// Why no rules here?
//   - Rules defined as Go structs are harder to audit, review, and update
//     than YAML files in packs/.
//   - The three rules previously hardcoded here (/etc writes, .ssh, .aws)
//     were a weaker subset of what the packs provide (missed /usr, /var,
//     .gnupg, .kube, .gcloud, etc.), creating false confidence.
//   - Keeping rules in one place (packs/) avoids silent drift between the
//     Go defaults and the YAML definitions.
//
// MCP packs are embedded into the binary via packs.MCPFiles() (see
// packs/packs.go, which uses //go:embed community/mcp/*.yaml) and exposed to
// this package through setup_mcp.go.
func DefaultMCPPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		// Minimal shell-execution blocklist: last-resort guard for users who
		// have not yet run `agentshield setup mcp` to install the full packs.
		// mcp-safety.yaml extends this list with run_bash, run_code, etc.
		BlockedTools: []string{
			"execute_command",
			"run_shell",
			"run_terminal_command",
			"shell_exec",
		},
	}
}

// LoadMCPPacks reads all .yaml files from packsDir and merges them into base.
// Blocked tools and blocked resources are unioned; rules, resource rules, and
// value limits are appended. Packs prefixed with underscore are disabled.
// Returns the merged policy, pack metadata, and any error.
func LoadMCPPacks(packsDir string, base *MCPPolicy) (*MCPPolicy, []MCPPackInfo, error) {
	var infos []MCPPackInfo

	entries, err := os.ReadDir(packsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return base, nil, nil
		}
		return nil, nil, err
	}

	// Clone base policy so we don't mutate it
	result := cloneMCPPolicy(base)

	for _, entry := range entries {
		if entry.IsDir() || !isYAMLExt(entry.Name()) {
			continue
		}

		path := filepath.Join(packsDir, entry.Name())
		baseName := strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name()))
		enabled := !strings.HasPrefix(baseName, "_")

		pack, err := loadMCPPack(path)
		if err != nil {
			infos = append(infos, MCPPackInfo{
				Name:    baseName,
				Enabled: enabled,
				Path:    path,
			})
			continue
		}

		ruleCount := len(pack.Rules) + len(pack.ResourceRules) + len(pack.ValueLimits) + len(pack.BlockedTools) + len(pack.StructuralRules) + len(pack.SemanticRules) + len(pack.DataLabels)
		info := MCPPackInfo{
			Name:        pack.Name,
			Description: pack.Description,
			Version:     pack.Version,
			Author:      pack.Author,
			Enabled:     enabled,
			Path:        path,
			RuleCount:   ruleCount,
		}
		if info.Name == "" {
			info.Name = baseName
		}
		infos = append(infos, info)

		if !enabled {
			continue
		}

		mergeMCPPack(result, pack)
	}

	return result, infos, nil
}

// LoadEmbeddedMCPPacks loads MCP packs from the embedded packs.MCPFiles() into
// the base policy. Used as a fallback when no packs are installed on disk.
func LoadEmbeddedMCPPacks(base *MCPPolicy) (*MCPPolicy, []MCPPackInfo, error) {
	embeddedFiles := packs.MCPFiles()
	if len(embeddedFiles) == 0 {
		return base, nil, nil
	}

	result := cloneMCPPolicy(base)
	var infos []MCPPackInfo

	for name, data := range embeddedFiles {
		baseName := strings.TrimSuffix(name, filepath.Ext(name))

		var pack MCPPack
		if err := yaml.Unmarshal(data, &pack); err != nil {
			continue
		}

		ruleCount := len(pack.Rules) + len(pack.ResourceRules) + len(pack.ValueLimits) + len(pack.BlockedTools) + len(pack.StructuralRules) + len(pack.SemanticRules) + len(pack.DataLabels)
		info := MCPPackInfo{
			Name:      pack.Name,
			Version:   pack.Version,
			Enabled:   true,
			Path:      "(embedded)",
			RuleCount: ruleCount,
		}
		if info.Name == "" {
			info.Name = baseName
		}
		infos = append(infos, info)

		mergeMCPPack(result, &pack)
	}

	return result, infos, nil
}

func loadMCPPack(path string) (*MCPPack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pack MCPPack
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("failed to parse MCP pack %s: %w", path, err)
	}

	return &pack, nil
}

// mergeMCPPack merges a pack's contents into the target policy.
// Blocked tools and resources are unioned; rules, resource rules,
// and value limits are appended.
func mergeMCPPack(target *MCPPolicy, pack *MCPPack) {
	// Union blocked tools
	existing := make(map[string]bool)
	for _, t := range target.BlockedTools {
		existing[t] = true
	}
	for _, t := range pack.BlockedTools {
		if !existing[t] {
			target.BlockedTools = append(target.BlockedTools, t)
		}
	}

	// Union blocked resources
	existingRes := make(map[string]bool)
	for _, r := range target.BlockedResources {
		existingRes[r] = true
	}
	for _, r := range pack.BlockedResources {
		if !existingRes[r] {
			target.BlockedResources = append(target.BlockedResources, r)
		}
	}

	// Append rules, resource rules, value limits, structural rules, semantic rules
	target.Rules = append(target.Rules, pack.Rules...)
	target.ResourceRules = append(target.ResourceRules, pack.ResourceRules...)
	target.ValueLimits = append(target.ValueLimits, pack.ValueLimits...)
	target.StructuralRules = append(target.StructuralRules, pack.StructuralRules...)
	target.SemanticRules = append(target.SemanticRules, pack.SemanticRules...)
	target.DataLabels = append(target.DataLabels, pack.DataLabels...)
}

// cloneMCPPolicy creates a shallow copy of the policy with copied slices.
func cloneMCPPolicy(p *MCPPolicy) *MCPPolicy {
	c := &MCPPolicy{
		Defaults: p.Defaults,
	}
	c.BlockedTools = append(c.BlockedTools, p.BlockedTools...)
	c.BlockedResources = append(c.BlockedResources, p.BlockedResources...)
	c.Rules = append(c.Rules, p.Rules...)
	c.ResourceRules = append(c.ResourceRules, p.ResourceRules...)
	c.ValueLimits = append(c.ValueLimits, p.ValueLimits...)
	c.StructuralRules = append(c.StructuralRules, p.StructuralRules...)
	c.SemanticRules = append(c.SemanticRules, p.SemanticRules...)
	c.DataLabels = append(c.DataLabels, p.DataLabels...)
	return c
}

func isYAMLExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
