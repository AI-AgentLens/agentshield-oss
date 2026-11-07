package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/homedir"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/safefile"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
	fmt.Printf("  Mode:      %s\n", modeSummary(cfg))

	// 3. Login state
	creds, _ := auth.Load()
	if creds != nil && creds.Token != "" {
		fmt.Printf("  Logged in: %s (%s)\n", creds.User.Email, creds.Server)
		if isHeartbeatRunning() {
			fmt.Printf("  Heartbeat: running\n")
		} else {
			fmt.Printf("  Heartbeat: stopped — run 'agentshield login' to restart\n")
		}
	} else {
		fmt.Printf("  Logged in: no — run 'agentshield login'\n")
	}
	fmt.Println()

	// 3. IDE Shell Hooks
	fmt.Println("─── Shell Command Hooks ────────────────────────────────")
	home, _ := homedir.Dir() // not $HOME: Windows sets none (#4717)
	checkShellHook("Windsurf", filepath.Join(home, ".codeium", "windsurf", "hooks.json"))
	checkShellHook("Cursor", filepath.Join(home, ".cursor", "hooks.json"))
	checkOpenClawHook()
	fmt.Println()

	// 4. MCP Proxy
	fmt.Println("─── MCP Proxy ─────────────────────────────────────────")
	checkMCPProxy("Cursor MCP", filepath.Join(home, ".cursor", "mcp.json"))
	claudeConfigPath := claudeDesktopConfigPath()
	if claudeConfigPath != "" {
		checkMCPProxy("Claude Desktop", claudeConfigPath)
	}
	fmt.Println()

	// 5. Policy
	fmt.Println("─── Policy ────────────────────────────────────────────")
	checkShellPolicyFile(policyPathOrDefault(cfg))
	mcpPolPath := ""
	if cfg != nil {
		mcpPolPath = filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	}
	checkPolicyFile("MCP policy", mcpPolPath)

	// Policy packs — report embedded + disk separately so users can tell at a
	// glance whether they're relying on the built-in baseline or have extra
	// packs installed (e.g. premium from SaaS, custom user packs).
	if cfg != nil {
		base := policy.DefaultPolicy()
		_, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(base)
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		_, diskInfos, err := policy.LoadPacks(packsDir, base)

		enabledEmbedded := 0
		for _, info := range embeddedInfos {
			if info.Enabled {
				enabledEmbedded++
			}
		}
		enabledDisk := 0
		if err == nil {
			for _, info := range diskInfos {
				if info.Enabled {
					enabledDisk++
				}
			}
		}

		totalInfos := len(embeddedInfos) + len(diskInfos)
		if totalInfos > 0 {
			fmt.Printf("  ✅ Policy packs: %d embedded (%d enabled), %d on disk (%d enabled)\n",
				len(embeddedInfos), enabledEmbedded, len(diskInfos), enabledDisk)
		} else {
			fmt.Println("  ⚠  No policy packs available")
		}

		if ids := uncategorizedRules(policyPathOrDefault(cfg), packsDir); len(ids) > 0 {
			fmt.Printf("  ⚠  %d rule(s) name no taxonomy node, so their records map to no compliance control: %s\n",
				len(ids), listSome(ids, 5))
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

// uncategorizedRules returns the ids of the user's own rules that name no
// taxonomy node: every rule in the local policy file, plus on-disk pack rules
// with the documented "co-" (company custom) id prefix. Such a rule still
// enforces, but its audit records map to no compliance control. Shipped rules
// are left out because the user can't change them, and ALLOW rules because an
// allow is not evidence. The policy file is read as written: policy.Load would
// merge in the built-in default rules.
func uncategorizedRules(policyFile, packsDir string) []string {
	var ids []string
	add := func(rules []policy.Rule, ownOnly bool) {
		for _, r := range rules {
			if r.Taxonomy != "" || r.Decision == policy.DecisionAllow {
				continue
			}
			if ownOnly && !strings.HasPrefix(r.ID, "co-") {
				continue
			}
			ids = append(ids, r.ID)
		}
	}
	if data, err := safefile.ReadFile(policyFile); err == nil {
		var user policy.Policy
		if yaml.Unmarshal(data, &user) == nil {
			add(user.Rules, false)
		}
	}
	if packs, _, err := policy.LoadPacks(packsDir, &policy.Policy{}); err == nil && packs != nil {
		add(packs.Rules, true)
	}
	return ids
}

// listSome joins up to n items and says how many more there are.
func listSome(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(items[:n], ", "), len(items)-n)
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
	home, _ := homedir.Dir()
	hookDir := filepath.Join(home, ".openclaw", "hooks", "agentshield")
	handlerPath := filepath.Join(hookDir, "handler.ts")
	if _, err := os.Stat(handlerPath); err == nil {
		// Not ✅: the hook only injects a bootstrap instruction. No OpenClaw
		// tool call reaches `agentshield hook`, so nothing is evaluated (#4582).
		fmt.Printf("  ⚠  OpenClaw: bootstrap instruction only — commands are NOT evaluated (%s)\n", hookDir)
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
		if err := json.Unmarshal(stripUTF8BOM(data), &configMap); err == nil {
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
	if err := json.Unmarshal(stripUTF8BOM(data), &configMap); err != nil {
		fmt.Printf("  ✅ %s: proxied (%s)\n", name, configPath)
		return
	}

	servers, ok := configMap["mcpServers"].(map[string]interface{})
	if !ok {
		fmt.Printf("  ✅ %s: proxied (%s)\n", name, configPath)
		return
	}

	proxied := proxiedServerCount(servers)
	if proxied == len(servers) {
		fmt.Printf("  ✅ %s: %d/%d server(s) proxied (%s)\n", name, proxied, len(servers), configPath)
	} else {
		fmt.Printf("  ⚠  %s: %d/%d server(s) proxied (%s)\n", name, proxied, len(servers), configPath)
	}
}

// proxiedServerCount counts the stdio servers whose command is the agentshield
// binary. setup mcp writes its absolute path, agentshield.exe on Windows, so a
// bare-name comparison reported every wrapped server as unprotected (#4717).
func proxiedServerCount(servers map[string]interface{}) int {
	proxied := 0
	for _, v := range servers {
		serverMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		command, _ := serverMap["command"].(string)
		if hookentry.IsProgram(command) {
			proxied++
		}
	}
	return proxied
}

// checkShellPolicyFile is checkPolicyFile plus the parse scan and check do: a
// policy.yaml that exists but cannot be read makes the hook decide every
// command as AUDIT (agentshield-eval-error, #4393), so status must not show a
// tick for it (#4739). Reporting only; no decision changes.
func checkShellPolicyFile(path string) {
	if path != "" {
		if _, statErr := os.Stat(path); statErr == nil {
			if _, err := policy.Load(path); err != nil {
				fmt.Printf("  ❌ Shell policy: %s is not a valid AgentShield policy: %v\n", path, err)
				fmt.Println("     The hook decides every command as AUDIT (agentshield-eval-error) until it is fixed.")
				fmt.Println("     If you did not write this file, delete it to use the built-in rules.")
				return
			}
		}
	}
	checkPolicyFile("Shell policy", path)
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
	home, _ := homedir.Dir()
	candidates := []string{
		filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		filepath.Join(home, ".config", "claude", "claude_desktop_config.json"),
	}
	candidates = append(candidates, windowsClaudeDesktopConfigs(home)...)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}
