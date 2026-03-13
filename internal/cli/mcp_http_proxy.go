package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpHTTPProxyCmd = &cobra.Command{
	Use:   "mcp-http-proxy --upstream <url>",
	Short: "MCP Streamable HTTP proxy — intercept and evaluate MCP tool calls over HTTP",
	Long: `Starts a transparent MCP HTTP reverse proxy that sits between the IDE (client)
and a remote MCP server using Streamable HTTP transport. The proxy intercepts
tools/call requests, evaluates them against AgentShield's MCP policy, and blocks
dangerous tool calls before they reach the upstream server.

Tools/list responses from the upstream server are scanned for tool description
poisoning — poisoned tools are silently hidden before reaching the IDE.

The proxy listens on a local HTTP port and forwards allowed requests to the
upstream MCP server URL. SSE streaming responses are supported.

Usage:
  agentshield mcp-http-proxy --upstream http://localhost:8080/mcp
  agentshield mcp-http-proxy --upstream https://mcp.example.com/api --port 9100

In your IDE MCP config, replace the server URL with the proxy's local URL:
  "url": "http://127.0.0.1:9100"

The MCP policy is loaded from ~/.agentshield/mcp-policy.yaml.`,
	RunE: mcpHTTPProxyCommand,
}

var (
	httpUpstreamURL string
	httpListenPort  int
)

func init() {
	mcpHTTPProxyCmd.Flags().StringVar(&httpUpstreamURL, "upstream", "", "Upstream MCP server URL (required)")
	mcpHTTPProxyCmd.Flags().IntVar(&httpListenPort, "port", 0, "Local port to listen on (default: auto-assign)")
	mcpHTTPProxyCmd.Flags().StringVar(&mcpPolicyPath, "mcp-policy", "", "Path to MCP policy YAML (default: ~/.agentshield/mcp-policy.yaml)")
	_ = mcpHTTPProxyCmd.MarkFlagRequired("upstream")
	rootCmd.AddCommand(mcpHTTPProxyCmd)
}

func mcpHTTPProxyCommand(cmd *cobra.Command, args []string) error {
	if httpUpstreamURL == "" {
		return fmt.Errorf("--upstream is required")
	}

	// Load config for audit log path
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: config load failed: %v\n", err)
	}

	// Load MCP policy
	mcpPolPath := mcpPolicyPath
	if mcpPolPath == "" && cfg != nil {
		mcpPolPath = filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	}

	mcpPolicy, err := mcp.LoadMCPPolicy(mcpPolPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: MCP policy load failed, using defaults: %v\n", err)
		mcpPolicy = mcp.DefaultMCPPolicy()
	}

	// Load and merge MCP packs
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
		merged, packInfos, packErr := mcp.LoadMCPPacks(packsDir, mcpPolicy)
		if packErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: MCP packs load failed: %v\n", packErr)
		} else {
			mcpPolicy = merged
			for _, pi := range packInfos {
				status := "enabled"
				if !pi.Enabled {
					status = "disabled"
				}
				fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] pack: %s (%s, %d rules)\n", pi.Name, status, pi.RuleCount)
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
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: audit log open failed: %v\n", err)
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

		data, err := json.Marshal(entry)
		if err != nil {
			return
		}
		_, _ = auditFile.Write(data)
		_, _ = auditFile.Write([]byte("\n"))
	}

	// Determine listen address
	listenAddr := "127.0.0.1:0"
	if httpListenPort > 0 {
		listenAddr = fmt.Sprintf("127.0.0.1:%d", httpListenPort)
	}

	fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] upstream: %s\n", httpUpstreamURL)
	fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] policy: %s (blocked tools: %d, rules: %d, value limits: %d)\n",
		mcpPolPath, len(mcpPolicy.BlockedTools), len(mcpPolicy.Rules), len(mcpPolicy.ValueLimits))
	fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] started at %s\n", time.Now().UTC().Format(time.RFC3339))

	proxy := mcp.NewHTTPProxy(mcp.HTTPProxyConfig{
		UpstreamURL: httpUpstreamURL,
		ListenAddr:  listenAddr,
		Evaluator:   evaluator,
		OnAudit:     onAudit,
		Stderr:      os.Stderr,
		ServerName:  deriveServerNameFromURL(httpUpstreamURL),
	})

	// Handle graceful shutdown on SIGINT/SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Fprintf(os.Stderr, "\n[AgentShield MCP-HTTP] shutting down...\n")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = proxy.Shutdown(ctx)
	}()

	return proxy.ListenAndServe()
}

// deriveServerNameFromURL extracts the host (without port) from an upstream URL
// to use as the ServerName in audit entries.
func deriveServerNameFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	// Strip port if present
	host := u.Hostname()
	if host == "" {
		return rawURL
	}
	return host
}
