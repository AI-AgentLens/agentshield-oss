package cli

import (
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// loadedRuleCounts is what the install enforces right now, per surface.
type loadedRuleCounts struct {
	Shell int // base policy + embedded community + ~/.agentshield/packs
	MCP   int // user MCP policy + embedded community/premium + ~/.agentshield/mcp-packs (+ legacy packs/mcp)
}

func (c loadedRuleCounts) total() int { return c.Shell + c.MCP }

// countLoadedRules reports the number of rules the running install enforces,
// by running the same loaders the hook and the MCP proxy run and counting
// what they produce — not by counting files, and not by re-parsing packs/.
// This is what the heartbeat sends the SaaS as rules_loaded.
//
// Shell mirrors hook.go: user policy → embedded community shell packs →
// disk packs. MCP mirrors loadDeployedMCPPolicy. A disk layer that fails to
// load contributes nothing, exactly as it contributes nothing to enforcement.
func countLoadedRules(cfg *config.Config) int {
	return loadedRules(cfg).total()
}

func loadedRules(cfg *config.Config) loadedRuleCounts {
	var out loadedRuleCounts

	pol, err := policy.Load(cfg.PolicyPath)
	if err != nil || pol == nil {
		pol = policy.DefaultPolicy()
	}
	pol, _, _ = policy.LoadEmbeddedShellPacks(pol)
	if merged, _, err := policy.LoadPacks(filepath.Join(cfg.ConfigDir, "packs"), pol); err == nil && merged != nil {
		pol = merged
	}
	out.Shell = len(pol.Rules)

	m := loadDeployedMCPPolicy("").Policy
	out.MCP = mcpRuleTotal(m)
	return out
}

// mcpRuleTotal counts the id-bearing rule families of a merged MCP policy —
// the same five the rule-count definition uses (rules, structural_rules,
// value_limits, resource_rules, semantic_rules). blocked_tools are
// enforcement but not rules, and are not counted.
func mcpRuleTotal(m *mcp.MCPPolicy) int {
	if m == nil {
		return 0
	}
	return len(m.Rules) + len(m.StructuralRules) + len(m.ValueLimits) + len(m.ResourceRules) + len(m.SemanticRules)
}
