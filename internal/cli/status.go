package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/mcp"
	"github.com/security-researcher-ca/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show AgentShield status — hooks, MCP proxies, policy, audit log",
	Long: `Check whether AgentShield is active: which IDE hooks are installed,
which MCP servers are proxied, and whether policy and audit files exist.

  agentshield status`,
	RunE: statusCommand,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func statusCommand(cmd *cobra.Command, args []string) error {
	cfg, _ := config.Load(policyPath, logPath, mode)

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield Status")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// 1. Binary
	binPath, err := os.Executable()
	if err != nil {
		binPath = "unknown"
	}
	fmt.Printf("  Binary:    %s (%s)\n", binPath, Version)

	// 2. Config directory
	configDir := "~/.agentshield"
	if cfg != nil {
		configDir = cfg.ConfigDir
	}
	fmt.Printf("  Config:    %s\n", configDir)
	fmt.Println()

	// 3. IDE Shell Hooks
	fmt.Println("─── Shell Command Hooks ────────────────────────────────")
	checkShellHook("Windsurf", filepath.Join(os.Getenv("HOME"), ".codeium", "windsurf", "hooks.json"))
	checkShellHook("Cursor", filepath.Join(os.Getenv("HOME"), ".cursor", "hooks.json"))
	checkOpenClawHook()
	fmt.Println()

	// 4. MCP Proxy
	fmt.Println("─── MCP Proxy ─────────────────────────────────────────")
	checkMCPProxy("Cursor MCP", filepath.Join(os.Getenv("HOME"), ".cursor", "mcp.json"))
	claudeConfigPath := claudeDesktopConfigPath()
	if claudeConfigPath != "" {
		checkMCPProxy("Claude Desktop", claudeConfigPath)
	}
	fmt.Println()

	// 5. Policy
	fmt.Println("─── Policy ────────────────────────────────────────────")
	checkPolicyFile("Shell policy", policyPathOrDefault(cfg))
	mcpPolPath := ""
	if cfg != nil {
		mcpPolPath = filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	}
	checkPolicyFile("MCP policy", mcpPolPath)

	// Policy packs
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		base := policy.DefaultPolicy()
		_, infos, err := policy.LoadPacks(packsDir, base)
		if err == nil && len(infos) > 0 {
			enabled := 0
			for _, info := range infos {
				if info.Enabled {
					enabled++
				}
			}
			fmt.Printf("  ✅ Policy packs: %d installed, %d enabled\n", len(infos), enabled)
		} else {
			fmt.Println("  ⚠  No policy packs installed")
		}
	}
	fmt.Println()

	// 6. Audit log
	fmt.Println("─── Audit Log ─────────────────────────────────────────")
	auditPath := ""
	if cfg != nil {
		auditPath = cfg.LogPath
	}
	checkAuditLog(auditPath)
	fmt.Println()

	return nil
}

func checkShellHook(name, hooksPath string) {
	data, err := os.ReadFile(hooksPath)
	if err != nil {
		fmt.Printf("  ⬚  %s: not configured\n", name)
		return
	}
	if strings.Contains(string(data), "agentshield hook") {
		fmt.Printf("  ✅ %s: hook active (%s)\n", name, hooksPath)
	} else {
		fmt.Printf("  ⬚  %s: hooks.json exists but no AgentShield hook\n", name)
	}
}

func checkOpenClawHook() {
	hookDir := filepath.Join(os.Getenv("HOME"), ".openclaw", "hooks", "agentshield")
	handlerPath := filepath.Join(hookDir, "handler.ts")
	if _, err := os.Stat(handlerPath); err == nil {
		fmt.Printf("  ✅ OpenClaw: hook active (%s)\n", hookDir)
	} else {
		fmt.Printf("  ⬚  OpenClaw: not configured\n")
	}
}

func checkMCPProxy(name, configPath string) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Printf("  ⬚  %s: no config found\n", name)
		return
	}

	if !strings.Contains(string(data), "agentshield") {
		// Count servers
		var configMap map[string]interface{}
		if err := json.Unmarshal(data, &configMap); err == nil {
			if servers, ok := configMap["mcpServers"].(map[string]interface{}); ok {
				fmt.Printf("  ⚠  %s: %d server(s) NOT proxied (%s)\n", name, len(servers), configPath)
				return
			}
		}
		fmt.Printf("  ⬚  %s: config exists but not proxied\n", name)
		return
	}

	// Count proxied vs total servers
	var configMap map[string]interface{}
	if err := json.Unmarshal(data, &configMap); err != nil {
		fmt.Printf("  ✅ %s: proxied (%s)\n", name, configPath)
		return
	}

	servers, ok := configMap["mcpServers"].(map[string]interface{})
	if !ok {
		fmt.Printf("  ✅ %s: proxied (%s)\n", name, configPath)
		return
	}

	proxied := 0
	for _, v := range servers {
		serverMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		command, _ := serverMap["command"].(string)
		if command == "agentshield" {
			proxied++
		}
	}

	if proxied == len(servers) {
		fmt.Printf("  ✅ %s: %d/%d server(s) proxied (%s)\n", name, proxied, len(servers), configPath)
	} else {
		fmt.Printf("  ⚠  %s: %d/%d server(s) proxied (%s)\n", name, proxied, len(servers), configPath)
	}
}

func checkPolicyFile(name, path string) {
	if path == "" {
		fmt.Printf("  ⬚  %s: using built-in defaults\n", name)
		return
	}
	if _, err := os.Stat(path); err == nil {
		fmt.Printf("  ✅ %s: %s\n", name, path)
	} else {
		fmt.Printf("  ⬚  %s: using built-in defaults (no custom file)\n", name)
	}
}

func checkAuditLog(path string) {
	if path == "" {
		fmt.Println("  ⬚  No audit log path configured")
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		fmt.Printf("  ⬚  %s (not yet created — will start on first event)\n", path)
		return
	}

	sizeKB := info.Size() / 1024
	if sizeKB == 0 {
		fmt.Printf("  ✅ %s (<1 KB)\n", path)
	} else {
		fmt.Printf("  ✅ %s (%d KB)\n", path, sizeKB)
	}
}

func policyPathOrDefault(cfg *config.Config) string {
	if cfg != nil {
		return cfg.PolicyPath
	}
	return ""
}

func claudeDesktopConfigPath() string {
	home := os.Getenv("HOME")
	candidates := []string{
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
