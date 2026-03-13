package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/mcp"
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

	// Load and merge MCP packs
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
		merged, packInfos, packErr := mcp.LoadMCPPacks(packsDir, mcpPolicy)
		if packErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP] warning: MCP packs load failed: %v\n", packErr)
		} else {
			mcpPolicy = merged
			for _, pi := range packInfos {
				status := "enabled"
				if !pi.Enabled {
					status = "disabled"
				}
				fmt.Fprintf(os.Stderr, "[AgentShield MCP] pack: %s (%s, %d rules)\n", pi.Name, status, pi.RuleCount)
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

	proxy := mcp.NewProxy(mcp.ProxyConfig{
		ServerCmd:  serverCmd,
		Evaluator:  evaluator,
		OnAudit:    onAudit,
		Stderr:     os.Stderr,
		ServerName: serverName,
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
