package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

// loadedMCPPolicy is the merged MCP policy used by both `mcp-eval` and the
// Claude Code hook. The loader is fail-safe by design: soft errors (malformed
// user policy YAML, unreadable disk packs dir) are recorded as Warnings rather
// than returned, so embedded community rules always still enforce. This
// matters in managed/fail-closed mode — silently dropping the embedded layer
// because of a parse error in the user's mcp-policy.yaml would be a regression.
type loadedMCPPolicy struct {
	Policy     *mcp.MCPPolicy
	Embedded   []mcp.MCPPackInfo
	Disk       []mcp.MCPPackInfo
	LegacyDisk []mcp.MCPPackInfo
	PolicyPath string
	PacksDir   string
	LegacyDir  string
	Warnings   []string
}

// loadDeployedMCPPolicy assembles the runtime MCP policy from, in order:
//   1. user MCP policy file (overridePolicyPath, or ~/.agentshield/mcp-policy.yaml)
//   2. embedded community MCP packs (always available)
//   3. disk MCP packs from ~/.agentshield/mcp-packs (deployed by `setup mcp`)
//   4. legacy disk packs from ~/.agentshield/packs/mcp — only when (3) is empty
//
// The function always returns a usable policy. Callers should log Warnings.
func loadDeployedMCPPolicy(overridePolicyPath string) *loadedMCPPolicy {
	loaded := &loadedMCPPolicy{}

	configDir, warn := resolveAgentShieldConfigDir()
	if warn != "" {
		loaded.Warnings = append(loaded.Warnings, warn)
	}

	policyFile := overridePolicyPath
	if policyFile == "" && configDir != "" {
		policyFile = filepath.Join(configDir, mcp.DefaultMCPPolicyFile)
	}
	loaded.PolicyPath = policyFile

	mcpPolicy := mcp.DefaultMCPPolicy()
	if policyFile != "" {
		if loadedPolicy, err := mcp.LoadMCPPolicy(policyFile); err != nil {
			loaded.Warnings = append(loaded.Warnings,
				fmt.Sprintf("MCP policy %s could not be parsed (%v); falling back to embedded community rules", policyFile, err))
		} else {
			mcpPolicy = loadedPolicy
		}
	}

	mcpPolicy, loaded.Embedded, _ = mcp.LoadEmbeddedMCPPacks(mcpPolicy)

	// Build a set of pack names already loaded from embedded so disk-layer
	// fallbacks don't re-merge stale copies of the same pack — root cause of
	// issue #1628 (every rule reported twice with slightly different reason
	// wording when a pre-2026-04 install left community packs on disk).
	loadedNames := map[string]bool{}
	for _, p := range loaded.Embedded {
		loadedNames[p.Name] = true
	}

	if configDir != "" {
		loaded.PacksDir = filepath.Join(configDir, mcp.DefaultMCPPacksDir)
		loaded.LegacyDir = filepath.Join(configDir, "packs", "mcp")

		if merged, infos, err := mcp.LoadMCPPacksExcluding(loaded.PacksDir, mcpPolicy, loadedNames); err != nil {
			loaded.Warnings = append(loaded.Warnings,
				fmt.Sprintf("MCP packs dir %s could not be read (%v); skipping disk packs", loaded.PacksDir, err))
		} else if merged != nil {
			mcpPolicy = merged
			loaded.Disk = infos
			for _, p := range infos {
				loadedNames[p.Name] = true
			}
		}

		if len(loaded.Disk) == 0 && loaded.LegacyDir != loaded.PacksDir {
			if merged, infos, err := mcp.LoadMCPPacksExcluding(loaded.LegacyDir, mcpPolicy, loadedNames); err == nil && merged != nil {
				mcpPolicy = merged
				loaded.LegacyDisk = infos
			}
		}
	}

	loaded.Policy = mcpPolicy
	return loaded
}

// resolveAgentShieldConfigDir picks the config dir, preferring config.Load's
// view (which honors managed.json) and falling back to $HOME/.agentshield.
// Returns empty configDir + a warning string when neither path resolves.
func resolveAgentShieldConfigDir() (string, string) {
	if cfg, _ := config.Load(policyPath, logPath, mode); cfg != nil && cfg.ConfigDir != "" {
		return cfg.ConfigDir, ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Sprintf("cannot determine home directory (%v); using embedded MCP packs only", err)
	}
	return filepath.Join(home, config.DefaultConfigDir), ""
}
