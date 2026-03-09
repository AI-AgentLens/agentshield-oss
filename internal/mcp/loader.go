package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// DefaultMCPPolicyFile is the filename for MCP-specific policy within ~/.agentshield/.
const DefaultMCPPolicyFile = "mcp-policy.yaml"

// DefaultMCPPacksDir is the subdirectory name for MCP packs within ~/.agentshield/.
const DefaultMCPPacksDir = "mcp-packs"

// MCPPack represents a single MCP policy pack loaded from YAML.
type MCPPack struct {
	Name             string           `yaml:"name"`
	Description      string           `yaml:"description"`
	Version          string           `yaml:"version"`
	Author           string           `yaml:"author"`
	BlockedTools     []string         `yaml:"blocked_tools,omitempty"`
	BlockedResources []string         `yaml:"blocked_resources,omitempty"`
	Rules            []MCPRule        `yaml:"rules,omitempty"`
	ResourceRules    []ResourceRule   `yaml:"resource_rules,omitempty"`
	ValueLimits      []ValueLimitRule `yaml:"value_limits,omitempty"`
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

// DefaultMCPPolicy returns a reasonable default MCP security policy.
// Blocks known-dangerous tool patterns and audits everything else.
func DefaultMCPPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{
			"execute_command",
			"run_shell",
			"run_terminal_command",
			"shell_exec",
		},
		Rules: []MCPRule{
			{
				ID: "block-write-sensitive-paths",
				Match: MCPMatch{
					ToolNameAny:      []string{"write_file", "create_file", "edit_file"},
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "File write to system directories is blocked.",
			},
			{
				ID: "block-ssh-access",
				Match: MCPMatch{
					ToolNameAny: []string{"read_file", "write_file", "cat_file", "create_file"},
					ArgumentPatterns: map[string]string{
						"path": "**/.ssh/**",
					},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Access to SSH key directories is blocked.",
			},
			{
				ID: "block-credential-access",
				Match: MCPMatch{
					ToolNameAny: []string{"read_file", "write_file", "cat_file", "create_file"},
					ArgumentPatterns: map[string]string{
						"path": "**/.aws/**",
					},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Access to cloud credential directories is blocked.",
			},
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

		ruleCount := len(pack.Rules) + len(pack.ResourceRules) + len(pack.ValueLimits) + len(pack.BlockedTools)
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

	// Append rules, resource rules, value limits
	target.Rules = append(target.Rules, pack.Rules...)
	target.ResourceRules = append(target.ResourceRules, pack.ResourceRules...)
	target.ValueLimits = append(target.ValueLimits, pack.ValueLimits...)
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
	return c
}

func isYAMLExt(name string) bool {
	ext := strings.ToLower(filepath.Ext(name))
	return ext == ".yaml" || ext == ".yml"
}
