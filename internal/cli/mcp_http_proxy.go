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

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/spf13/cobra"
)

var mcpHTTPProxyCmd = &cobra.Command{
	Use:   "mcp-http-proxy --upstream <url>",
	Short: "MCP Streamable HTTP proxy — intercept and evaluate MCP tool calls over HTTP",
	Long: `Starts a transparent MCP HTTP reverse proxy that sits between the IDE (client)
and a remote MCP server using Streamable HTTP transport. The proxy intercepts
tools/call requests, evaluates them against AgentShield's MCP policy, and blocks
dangerous tool calls before they reach the upstream server. In audit-only mode
(the default for new installs) a tool call enforce mode would block is
forwarded and recorded as AUDIT with original_decision BLOCK; the config-file
guard still blocks.

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

	// Layer 1: embedded community MCP packs — always available, so the proxy
	// enforces community rules even when ~/.agentshield/mcp-packs/ is empty.
	if emb, embInfos, _ := mcp.LoadEmbeddedMCPPacks(mcpPolicy); emb != nil {
		mcpPolicy = emb
		for _, pi := range embInfos {
			if pi.LoadError != nil {
				// Issue #2188: never let a parse failure pass silently.
				fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] CRITICAL: embedded pack %s failed to parse — rules NOT loaded: %v\n", pi.Name, pi.LoadError)
				continue
			}
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] embedded pack: %s (%d rules)\n", pi.Name, pi.RuleCount)
		}
	}

	// Layer 2: disk-installed MCP packs (premium from SaaS, user custom).
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
		merged, packInfos, packErr := mcp.LoadMCPPacks(packsDir, mcpPolicy)
		if packErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: MCP packs load failed: %v\n", packErr)
		} else {
			mcpPolicy = merged
			for _, pi := range packInfos {
				if pi.LoadError != nil {
					// Issue #2188: never let a parse failure pass silently.
					fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] CRITICAL: disk pack %s failed to parse — rules NOT loaded: %v\n", pi.Path, pi.LoadError)
					continue
				}
				status := "enabled"
				if !pi.Enabled {
					status = "disabled"
				}
				fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] disk pack: %s (%s, %d rules)\n", pi.Name, status, pi.RuleCount)
			}
		}
	}

	// The evaluator stays in enforce mode (""): the proxy's handler applies
	// audit-only itself, once per tools/call, after its own scanners have
	// run, so a would-be block from any of them is recorded with its
	// original decision and the config guard keeps blocking (#4337, #4324
	// row 1). Passing the mode here as well would downgrade the evaluator's
	// verdicts on other message types the proxy still enforces.
	evaluator := assembly.MCPEvaluator(mcpPolicy, "")
	proxyMode := ""
	if cfg != nil {
		proxyMode = cfg.Mode
	}
	if proxyMode == config.ModeAuditOnly {
		fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] mode: audit-only (%s) — tool calls enforce mode would block are forwarded and recorded; the config-file guard still blocks\n", cfg.ModeSource)
	}

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

	// #4463: the entry is redacted and data-label scrubbed like the hook's event.
	// dlEngine is set below once the policy's labels are compiled; nil scrubs nothing.
	var dlEngine *datalabel.Engine
	onAudit := func(entry mcp.AuditEntry) {
		if auditFile == nil {
			return
		}
		auditMu.Lock()
		defer auditMu.Unlock()

		data, err := json.Marshal(entry.Redacted(dlEngine.Scrub))
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

	// Build data label scanner if labels are configured
	var dlScanner *mcp.DataLabelScanner
	if len(mcpPolicy.DataLabels) > 0 {
		dlConfigs := mcp.ConvertDataLabels(mcpPolicy.DataLabels)
		if engine, dlErr := datalabel.NewEngine(dlConfigs); dlErr != nil {
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] warning: data label engine init failed: %v\n", dlErr)
		} else if engine != nil {
			dlEngine = engine
			dlScanner = mcp.NewDataLabelScanner(engine)
			fmt.Fprintf(os.Stderr, "[AgentShield MCP-HTTP] data label scanner: %d labels loaded\n", len(mcpPolicy.DataLabels))
		}
	}

	proxy := mcp.NewHTTPProxy(mcp.HTTPProxyConfig{
		UpstreamURL:      httpUpstreamURL,
		ListenAddr:       listenAddr,
		Evaluator:        evaluator,
		OnAudit:          onAudit,
		Stderr:           os.Stderr,
		ServerName:       deriveServerNameFromURL(httpUpstreamURL),
		DataLabelScanner: dlScanner,
		ManagedHost:      enterprise.ManagedHost,
		Mode:             proxyMode,
		// The shell's managed self-protection rules, applied to
		// execute_command-style arguments on a managed host (#4337 B1).
		SelfProtectCommand: enterprise.MatchSelfProtectCommand,
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
