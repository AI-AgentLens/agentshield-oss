package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/packs"
	"github.com/spf13/cobra"
)

var setupMCPCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Set up AgentShield MCP proxy for IDE MCP servers",
	Long: `Rewrites IDE MCP server configurations to route through AgentShield's
MCP proxy, so every MCP tool call is evaluated against policy before reaching
the server.

Supported config files:
  Cursor:         .cursor/mcp.json (project) and ~/.cursor/mcp.json
  Claude Desktop: ~/Library/Application Support/Claude/claude_desktop_config.json (macOS)
                  %LOCALAPPDATA%\Claude-Data\<id>\, the Microsoft Store package folder,
                  or %APPDATA%\Claude\ (Windows)

  agentshield setup mcp                        # wrap MCP servers in all detected apps
  agentshield setup mcp --target claude-desktop # wrap only Claude Desktop
  agentshield setup mcp --target cursor         # wrap only Cursor
  agentshield setup mcp --disable               # restore original configs`,
	RunE: setupMCPCommand,
}

var (
	mcpDisableFlag bool
	mcpTargetFlag  string
)

func init() {
	setupMCPCmd.Flags().BoolVar(&mcpDisableFlag, "disable", false, "Restore original MCP configs and remove proxy wrapping")
	setupMCPCmd.Flags().StringVar(&mcpTargetFlag, "target", "all", "Which app(s) to wrap: all, claude-desktop, or cursor")
	setupCmd.AddCommand(setupMCPCmd)
}

// matchesTarget reports whether an MCP config location should be acted on given
// the --target selector. This prevents silently wrapping every app on the
// machine (e.g. accidentally disrupting Claude Desktop when the user only meant
// to protect Cursor).
func matchesTarget(loc mcpConfigLocation, target string) bool {
	switch target {
	case "all", "":
		return true
	case "claude-desktop", "claude":
		return strings.Contains(strings.ToLower(loc.Name), "claude")
	case "cursor":
		return strings.Contains(strings.ToLower(loc.Name), "cursor")
	default:
		return false
	}
}

// mcpConfigLocation describes a known IDE MCP config file.
type mcpConfigLocation struct {
	Name string
	Path string
}

func setupMCPCommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}

	// Managed mode refuses the MCP unwrap exactly as it refuses removing the
	// hooks (#4534): same check, before any file is read or written.
	// TestSetupDisable_EverySurfaceRefusedWhenManaged holds every `setup`
	// subcommand that takes --disable to this.
	if mcpDisableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + MCP (Tool Call Mediation)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	// Check if agentshield is in PATH
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap AI-AgentLens/oss && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	// The MCP policy and packs are what wrapping needs, so only setup creates
	// them. --disable must not create MCP state on a machine that never had
	// it (#4534).
	if !mcpDisableFlag {
		if err := ensureDefaultMCPPolicy(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Could not create default MCP policy: %v\n", err)
		}
		if err := installDefaultMCPPacks(); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Could not install default MCP packs: %v\n", err)
		}
	}

	// Validate the --target selector up front.
	switch mcpTargetFlag {
	case "all", "claude-desktop", "claude", "cursor":
	default:
		return fmt.Errorf("invalid --target %q: must be one of all, claude-desktop, cursor", mcpTargetFlag)
	}

	// Find all MCP config files, then narrow to the requested target so we never
	// silently wrap an app the user didn't ask for.
	allLocations := findMCPConfigLocations(home)
	var locations []mcpConfigLocation
	for _, loc := range allLocations {
		if matchesTarget(loc, mcpTargetFlag) {
			locations = append(locations, loc)
		}
	}
	if mcpTargetFlag != "all" {
		fmt.Printf("Target: %s (%d of %d detected configs)\n", mcpTargetFlag, len(locations), len(allLocations))
	}

	if len(locations) == 0 {
		fmt.Println()
		fmt.Println("ℹ  No MCP config files found.")
		fmt.Println("   Searched:")
		for _, p := range mcpConfigSearchPaths(runtime.GOOS) {
			fmt.Println("     " + p)
		}
		fmt.Println("   Claude Desktop connectors such as Gmail or Notion are not local MCP")
		fmt.Println("   servers, so there is nothing to wrap for them.")
		fmt.Println()
		fmt.Println("   You can also use the proxy directly:")
		fmt.Println("   agentshield mcp-proxy -- <server-command> [args...]")
		return nil
	}

	for _, loc := range locations {
		fmt.Println()
		fmt.Printf("─── %s ───\n", loc.Name)
		fmt.Printf("  Config: %s\n", loc.Path)

		if mcpDisableFlag {
			if err := restoreMCPConfig(loc); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠  %v\n", err)
			}
		} else {
			if err := wrapMCPConfig(loc, binPath); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠  %v\n", err)
			}
		}
	}

	fmt.Println()
	if mcpDisableFlag {
		fmt.Println("Restart your IDE to apply changes.")
	} else {
		fmt.Println("How it works:")
		fmt.Println("  1. IDE sends MCP tool calls (tools/call) to the server")
		fmt.Println("  2. AgentShield proxy intercepts and evaluates each call")
		fmt.Println("  3. If BLOCK (enforce mode): tool call is rejected with a JSON-RPC error")
		fmt.Println("  4. If ALLOW/AUDIT: tool call is forwarded to the real server")
		fmt.Println("  5. All decisions are logged to ~/.agentshield/audit.jsonl")
		fmt.Println()
		fmt.Println("MCP policy: ~/.agentshield/mcp-policy.yaml")
		fmt.Println()
		fmt.Println("Restart your IDE to activate the proxy.")
		fmt.Println("To disable: agentshield setup mcp --disable")
	}
	fmt.Println()

	return nil
}

// mcpConfigSearchPaths is what "No MCP config files found" lists: where
// findMCPConfigLocations looks on goos, as a user would type it. It used to
// print the macOS paths on every platform (#4717).
func mcpConfigSearchPaths(goos string) []string {
	paths := []string{".cursor/mcp.json (this project)", "~/.cursor/mcp.json"}
	if goos == "windows" {
		return append(paths,
			`%LOCALAPPDATA%\Claude-Data\*\claude_desktop_config.json`,
			`%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude\claude_desktop_config.json`,
			`%APPDATA%\Claude\claude_desktop_config.json`)
	}
	return append(paths, "~/Library/Application Support/Claude/claude_desktop_config.json")
}

// findMCPConfigLocations returns paths to known IDE MCP config files that
// exist, under home (setupHome) and in the working directory.
func findMCPConfigLocations(home string) []mcpConfigLocation {
	var found []mcpConfigLocation

	candidates := []mcpConfigLocation{
		{Name: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json")},
		{Name: "Claude Desktop", Path: filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")},
	}
	for _, p := range windowsClaudeDesktopConfigs(home) {
		candidates = append(candidates, mcpConfigLocation{Name: "Claude Desktop", Path: p})
	}

	// Also check current directory for project-level .cursor/mcp.json
	if cwd, err := os.Getwd(); err == nil {
		projectCursor := filepath.Join(cwd, ".cursor", "mcp.json")
		if projectCursor != candidates[0].Path {
			candidates = append(candidates, mcpConfigLocation{
				Name: "Cursor (project)", Path: projectCursor,
			})
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c.Path); err == nil {
			found = append(found, c)
		}
	}

	return found
}

// wrapMCPConfig reads an MCP config, wraps stdio server commands with agentshield mcp-proxy,
// and writes back the modified config. Creates a .agentshield-backup before modifying.
//
// binPath is the absolute path to the agentshield binary. GUI apps like Claude
// Desktop launch with a minimal PATH that excludes Homebrew/usr/local, so a bare
// "agentshield" command fails to spawn and every wrapped MCP server silently
// dies. Writing the resolved absolute path makes the wrapping work regardless of
// the launching app's PATH.
func wrapMCPConfig(loc mcpConfigLocation, binPath string) error {
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", loc.Path, err)
	}

	// Check if already wrapped
	if strings.Contains(string(data), "agentshield") {
		fmt.Printf("  ✅ Already wrapped with AgentShield proxy\n")
		return nil
	}

	// Parse the config
	var configMap map[string]interface{}
	if err := json.Unmarshal(stripUTF8BOM(data), &configMap); err != nil {
		return fmt.Errorf("failed to parse %s: %w", loc.Path, err)
	}

	// Find the mcpServers object (Cursor uses "mcpServers", Claude uses "mcpServers")
	serversRaw, ok := configMap["mcpServers"]
	if !ok {
		fmt.Printf("  ℹ  No mcpServers found in config — nothing to wrap\n")
		return nil
	}

	servers, ok := serversRaw.(map[string]interface{})
	if !ok {
		return fmt.Errorf("mcpServers is not an object")
	}

	// Create backup
	backupPath := loc.Path + ".agentshield-backup"
	if err := os.WriteFile(backupPath, data, 0644); err != nil {
		return fmt.Errorf("failed to create backup: %w", err)
	}
	fmt.Printf("  📋 Backup: %s\n", backupPath)

	// Wrap each stdio server
	wrapped := 0
	skipped := 0
	for name, serverRaw := range servers {
		serverMap, ok := serverRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Wrap URL-based (Streamable HTTP transport) servers
		if urlRaw, hasURL := serverMap["url"]; hasURL {
			urlStr, ok := urlRaw.(string)
			if !ok || urlStr == "" {
				continue
			}
			// Already wrapped?
			if strings.Contains(urlStr, "agentshield") || strings.Contains(urlStr, "127.0.0.1:91") {
				fmt.Printf("  ✅ %s: HTTP already wrapped\n", name)
				wrapped++
				continue
			}
			// Assign a deterministic port per server: 9100 + index
			port := 9100 + wrapped + skipped
			localURL := fmt.Sprintf("http://127.0.0.1:%d", port)
			// Store original URL and port for unwrapping and proxy startup
			serverMap["url"] = localURL
			if serverMap["_agentshield"] == nil {
				serverMap["_agentshield"] = map[string]interface{}{}
			}
			meta, _ := serverMap["_agentshield"].(map[string]interface{})
			meta["original_url"] = urlStr
			meta["proxy_port"] = port
			serverMap["_agentshield"] = meta
			servers[name] = serverMap
			fmt.Printf("  ✅ %s: HTTP wrapped (%s → %s, proxy port %d)\n", name, urlStr, localURL, port)
			fmt.Printf("     Start proxy: agentshield mcp-http-proxy --upstream %s --port %d\n", urlStr, port)
			wrapped++
			continue
		}

		command, hasCmd := serverMap["command"].(string)
		if !hasCmd || command == "" {
			continue
		}

		// Build new command: agentshield mcp-proxy -- <original-command> <original-args...>
		newArgs := []string{"mcp-proxy", "--"}
		newArgs = append(newArgs, command)
		if existingArgs, ok := serverMap["args"].([]interface{}); ok {
			for _, a := range existingArgs {
				if s, ok := a.(string); ok {
					newArgs = append(newArgs, s)
				}
			}
		}

		// Use the absolute binary path (not the bare name) so GUI-launched apps
		// with a minimal PATH can still find and spawn the proxy.
		shieldCmd := binPath
		if shieldCmd == "" {
			shieldCmd = "agentshield"
		}
		serverMap["command"] = shieldCmd
		serverMap["args"] = newArgs
		servers[name] = serverMap
		fmt.Printf("  ✅ %s: wrapped (%s → %s mcp-proxy -- %s)\n", name, command, shieldCmd, command)
		wrapped++
	}

	if wrapped == 0 {
		fmt.Printf("  ℹ  No stdio servers found to wrap\n")
		// Remove backup since we didn't modify
		_ = os.Remove(backupPath)
		return nil
	}

	// Write back
	configMap["mcpServers"] = servers
	out, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(loc.Path, out, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", loc.Path, err)
	}

	fmt.Printf("  📝 Updated: %d server(s) wrapped", wrapped)
	if skipped > 0 {
		fmt.Printf(", %d skipped (HTTP)", skipped)
	}
	fmt.Println()

	return nil
}

// restoreMCPConfig undoes the wrapping in place, so anything written to the
// config since `setup mcp` ran (a server the user added, the host app's own
// preferences) survives. The .agentshield-backup copy is the whole file as it
// was at setup time; copying it back loses those later changes (#4732), so it
// is only the fallback when the current file cannot be unwrapped (e.g. it no
// longer parses).
func restoreMCPConfig(loc mcpConfigLocation) error {
	backupPath := loc.Path + ".agentshield-backup"

	unwrapErr := unwrapMCPConfig(loc)
	if unwrapErr == nil {
		_ = os.Remove(backupPath)
		return nil
	}

	data, err := os.ReadFile(backupPath)
	if err != nil {
		return unwrapErr
	}
	if err := os.WriteFile(loc.Path, data, 0644); err != nil {
		return fmt.Errorf("failed to restore config: %w", err)
	}
	_ = os.Remove(backupPath)
	fmt.Printf("  ⚠  Could not unwrap in place (%v); restored the setup-time backup, so changes made since then are lost\n", unwrapErr)
	return nil
}

// unwrapMCPConfig removes agentshield mcp-proxy wrapping from server commands in-place.
func unwrapMCPConfig(loc mcpConfigLocation) error {
	data, err := os.ReadFile(loc.Path)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", loc.Path, err)
	}

	if !strings.Contains(string(data), "agentshield") {
		fmt.Printf("  ℹ  No AgentShield wrapping found — nothing to restore\n")
		return nil
	}

	var configMap map[string]interface{}
	if err := json.Unmarshal(stripUTF8BOM(data), &configMap); err != nil {
		return fmt.Errorf("failed to parse %s: %w", loc.Path, err)
	}

	serversRaw, ok := configMap["mcpServers"]
	if !ok {
		return nil
	}

	servers, ok := serversRaw.(map[string]interface{})
	if !ok {
		return nil
	}

	unwrapped := 0
	for name, serverRaw := range servers {
		serverMap, ok := serverRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Unwrap HTTP servers: restore original URL from _agentshield metadata
		if meta, hasMeta := serverMap["_agentshield"].(map[string]interface{}); hasMeta {
			if origURL, ok := meta["original_url"].(string); ok && origURL != "" {
				serverMap["url"] = origURL
				delete(serverMap, "_agentshield")
				servers[name] = serverMap
				fmt.Printf("  ✅ %s: HTTP unwrapped (restored %s)\n", name, origURL)
				unwrapped++
				continue
			}
		}

		// Unwrap stdio servers. The command may be the bare name (legacy) or an
		// absolute path (current), agentshield.exe on Windows (#4717).
		command, _ := serverMap["command"].(string)
		if !hookentry.IsProgram(command) {
			continue
		}

		argsRaw, ok := serverMap["args"].([]interface{})
		if !ok || len(argsRaw) < 3 {
			continue
		}

		// Expected: ["mcp-proxy", "--", "original-command", "original-args..."]
		if fmt.Sprintf("%v", argsRaw[0]) != "mcp-proxy" || fmt.Sprintf("%v", argsRaw[1]) != "--" {
			continue
		}

		// Restore original command and args
		serverMap["command"] = fmt.Sprintf("%v", argsRaw[2])
		if len(argsRaw) > 3 {
			serverMap["args"] = argsRaw[3:]
		} else {
			delete(serverMap, "args")
		}

		servers[name] = serverMap
		fmt.Printf("  ✅ %s: unwrapped\n", name)
		unwrapped++
	}

	if unwrapped == 0 {
		fmt.Printf("  ℹ  No wrapped servers found\n")
		return nil
	}

	configMap["mcpServers"] = servers
	out, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	out = append(out, '\n')

	if err := os.WriteFile(loc.Path, out, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", loc.Path, err)
	}

	return nil
}

// installDefaultMCPPacks copies the built-in MCP packs to ~/.agentshield/mcp-packs/.
// Existing packs are not overwritten (user customizations are preserved).
// Pack content is read from the embedded packs/community/mcp/*.yaml files via
// packs.MCPFiles(), so there is a single source of truth and no rule
// duplication in source code.
func installDefaultMCPPacks() error {
	cfg, err := config.Load("", "", "")
	if err != nil {
		return err
	}

	packsDir := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPacksDir)
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return err
	}

	installed := 0
	for name, content := range packs.MCPFiles() {
		dest := filepath.Join(packsDir, name)
		if _, err := os.Stat(dest); err == nil {
			continue // already exists, don't overwrite
		}
		if err := os.WriteFile(dest, content, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Could not write MCP pack %s: %v\n", name, err)
			continue
		}
		installed++
	}

	if installed > 0 {
		fmt.Printf("✅ Installed %d MCP packs to: %s\n", installed, packsDir)
	} else {
		fmt.Printf("✅ MCP packs up to date: %s\n", packsDir)
	}
	return nil
}

// ensureDefaultMCPPolicy creates ~/.agentshield/mcp-policy.yaml if it doesn't exist.
func ensureDefaultMCPPolicy() error {
	cfg, err := config.Load("", "", "")
	if err != nil {
		return err
	}

	policyPath := filepath.Join(cfg.ConfigDir, mcp.DefaultMCPPolicyFile)
	if _, err := os.Stat(policyPath); err == nil {
		return nil // already exists
	}

	// Minimal policy: defaults only, no hardcoded rules.
	// All security rules live in ~/.agentshield/mcp-packs/ (installed below by
	// installDefaultMCPPacks). Keeping rules here would duplicate the YAML in
	// packs/community/mcp/ and make them hard to maintain.
	defaultPolicy := `# AgentShield MCP Policy
# Controls which MCP tool calls are allowed, audited, or blocked.
# Security rules are provided by the packs in ~/.agentshield/mcp-packs/
# which are installed automatically. To customise, edit the pack files there.

defaults:
  decision: "AUDIT"        # ALLOW, AUDIT, or BLOCK for unmatched calls
`

	if err := os.WriteFile(policyPath, []byte(defaultPolicy), 0644); err != nil {
		return err
	}

	fmt.Printf("✅ Default MCP policy created: %s\n", policyPath)
	return nil
}
