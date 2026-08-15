package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpProxyCmd = &cobra.Command{
	Use:   "mcp-proxy -- <server-command> [args...]",
	Short: "MCP stdio proxy — intercept and evaluate MCP tool calls",
	Long: `Starts a transparent MCP proxy that sits between the IDE (client) and an
MCP server. The proxy intercepts tools/call requests, evaluates them against
AgentShield's MCP policy, and blocks dangerous tool calls before they reach
the server.

Tools/list responses from the server are scanned for tool description
poisoning — poisoned tools are silently hidden before reaching the IDE.
All other MCP messages (notifications, responses) are forwarded transparently.

Usage in IDE MCP config (e.g. .cursor/mcp.json):
  "command": "agentshield mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /path"

The MCP policy is loaded from ~/.agentshield/mcp-policy.yaml.
If no policy file exists, a sensible default is used.`,
	Args:               cobra.MinimumNArgs(1),
	RunE:               mcpProxyCommand,
	DisableFlagParsing: false,
}

var mcpPolicyPath string

func init() {
	mcpProxyCmd.Flags().StringVar(&mcpPolicyPath, "mcp-policy", "", "Path to MCP policy YAML (default: ~/.agentshield/mcp-policy.yaml)")
	rootCmd.AddCommand(mcpProxyCmd)
}

func mcpProxyCommand(cmd *cobra.Command, args []string) error {
	// Load config for audit log path
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: config load failed: %v\n", err)
	}

	// Load MCP policy
	mcpPolPath := mcpPolicyPath
	if mcpPolPath == "" && cfg != nil {
		mcpPolPath = filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	}

	mcpPolicy, err := mcp.LoadMCPPolicy(mcpPolPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: MCP policy load failed, using defaults: %v\n", err)
		mcpPolicy = mcp.DefaultMCPPolicy()
	}

	// Layer 1: embedded community MCP packs — always available, so the proxy
	// enforces community rules even when ~/.agentshield/mcp-packs/ is empty.
	// Before this fix, a premium-pack-less user running the MCP proxy got
	// zero MCP coverage beyond the hardcoded DefaultMCPPolicy.
	if emb, embInfos, _ := mcp.LoadEmbeddedMCPPacks(mcpPolicy); emb != nil {
		mcpPolicy = emb
		for _, pi := range embInfos {
			if pi.LoadError != nil {
				// Issue #2188: never let a parse failure pass silently.
				fmt.Fprintf(os.Stderr, "[AgentShield MCP] CRITICAL: embedded pack %s failed to parse — rules NOT loaded: %v\n", pi.Name, pi.LoadError)
				continue
			}
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] embedded pack: %s (%d rules)\n", pi.Name, pi.RuleCount)
		}
	}

	// Layer 2: disk-installed MCP packs (premium from SaaS, user custom).
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
		merged, packInfos, packErr := mcp.LoadMCPPacks(packsDir, mcpPolicy)
		if packErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: MCP packs load failed: %v\n", packErr)
		} else {
			mcpPolicy = merged
			for _, pi := range packInfos {
				if pi.LoadError != nil {
					// Issue #2188: never let a parse failure pass silently.
					fmt.Fprintf(os.Stderr, "[AgentShield MCP] CRITICAL: disk pack %s failed to parse — rules NOT loaded: %v\n", pi.Path, pi.LoadError)
					continue
				}
				status := "enabled"
				if !pi.Enabled {
					status = "disabled"
				}
				fmt.Fprintf(os.Stderr, "[AgentShield MCP] disk pack: %s (%s, %d rules)\n", pi.Name, status, pi.RuleCount)
			}
		}
	}

	evaluator := mcp.NewPolicyEvaluator(mcpPolicy)

	// Set up audit logging
	auditPath := ""
	if cfg != nil {
		auditPath = cfg.LogPath
	}

	var auditFile *os.File
	var auditMu sync.Mutex

	if auditPath != "" {
		auditFile, err = os.OpenFile(auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: audit log open failed: %v\n", err)
		}
	}
	defer func() {
		if auditFile != nil {
			_ = auditFile.Close()
		}
	}()

	onAudit := func(entry mcp.AuditEntry) {
		if auditFile == nil {
			return
		}
		auditMu.Lock()
		defer auditMu.Unlock()

		// Write as JSONL, consistent with existing audit format
		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		_, _ = auditFile.Write(data)
		_, _ = auditFile.Write([]byte("\n"))
	}

	// Find the server command after "--"
	serverCmd := args
	serverName := deriveServerName(serverCmd)
	fmt.Fprintf(os.Stderr, "[AgentShield MCP] proxy starting for server: %v\n", serverCmd)
	fmt.Fprintf(os.Stderr, "[AgentShield MCP] policy: %s (blocked tools: %d, rules: %d)\n",
		mcpPolPath, len(mcpPolicy.BlockedTools), len(mcpPolicy.Rules))
	fmt.Fprintf(os.Stderr, "[AgentShield MCP] started at %s\n", time.Now().UTC().Format(time.RFC3339))

	// Build data label scanner if labels are configured
	var dlScanner *mcp.DataLabelScanner
	if len(mcpPolicy.DataLabels) > 0 {
		dlConfigs := mcp.ConvertDataLabels(mcpPolicy.DataLabels)
		if engine, dlErr := datalabel.NewEngine(dlConfigs); dlErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: data label engine init failed: %v\n", dlErr)
		} else if engine != nil {
			dlScanner = mcp.NewDataLabelScanner(engine)
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] data label scanner: %d labels loaded\n", len(mcpPolicy.DataLabels))
		}
	}

	proxy := mcp.NewProxy(mcp.ProxyConfig{
		ServerCmd:        serverCmd,
		Evaluator:        evaluator,
		OnAudit:          onAudit,
		Stderr:           os.Stderr,
		ServerName:       serverName,
		DataLabelScanner: dlScanner,
	})

	return proxy.Run()
}

// deriveServerName returns a human-readable name for an MCP server from its
// launch command. For npx/bunx launchers it uses the package name; otherwise
// it falls back to the executable base name.
func deriveServerName(cmd []string) string {
	if len(cmd) == 0 {
		return "unknown"
	}
	base := filepath.Base(cmd[0])
	// For npx/bunx/node the meaningful name is the package/script argument.
	if base == "npx" || base == "bunx" || base == "node" {
		for _, arg := range cmd[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			// Trim scoped package prefix (e.g. @modelcontextprotocol/server-filesystem → server-filesystem)
			if i := strings.LastIndex(arg, "/"); i >= 0 {
				return arg[i+1:]
			}
			return arg
		}
	}
	return base
}

