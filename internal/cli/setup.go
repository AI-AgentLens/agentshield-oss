package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
	"github.com/spf13/cobra"
)

var setupWindsurfCmd = &cobra.Command{
	Use:   "windsurf",
	Short: "Set up AgentShield for Windsurf IDE",
	Long: `Install or remove Cascade Hooks so every command Windsurf's AI agent
runs is evaluated by AgentShield before execution.

  agentshield setup windsurf             # enable hooks
  agentshield setup windsurf --disable   # disable hooks`,
	RunE: setupWindsurfCommand,
}

var setupCursorCmd = &cobra.Command{
	Use:   "cursor",
	Short: "Set up AgentShield for Cursor IDE",
	Long: `Install or remove Cursor Hooks so every command Cursor's AI agent
runs is evaluated by AgentShield before execution.

  agentshield setup cursor             # enable hooks
  agentshield setup cursor --disable   # disable hooks`,
	RunE: setupCursorCommand,
}

var setupOpenClawCmd = &cobra.Command{
	Use:   "openclaw",
	Short: "Set up AgentShield for OpenClaw gateway",
	Long: `Install an OpenClaw bootstrap hook that adds an AgentShield note to the
agent's context. This is NOT enforcement: no OpenClaw tool call is sent to
AgentShield, so no command is evaluated or blocked (#4582).

  agentshield setup openclaw             # install hook
  agentshield setup openclaw --disable   # remove hook`,
	RunE: setupOpenClawCommand,
}

var setupClaudeCodeCmd = &cobra.Command{
	Use:   "claude-code",
	Short: "Set up AgentShield for Claude Code (PreToolUse hook)",
	Long: `Install or remove the PreToolUse hook so every Bash tool call Claude Code
makes is evaluated by AgentShield before execution.

  agentshield setup claude-code             # enable hook
  agentshield setup claude-code --disable   # disable hook

The hook is registered in ~/.claude/settings.json (user scope). A repository's
committed .claude/settings.json with "disableAllHooks": true turns user-scope
hooks off. A hook in Claude Code managed settings keeps running (#4292):

  agentshield setup claude-code --managed > agentshield.json
      # print the managed-settings JSON (stdout) and the per-OS file path
      # (stderr) for an MDM such as Jamf or Intune to deploy; writes nothing
  sudo agentshield setup claude-code --write-managed
      # merge the hook into this machine's managed settings file, keeping
      # every other key; needs administrator rights

  macOS:          /Library/Application Support/ClaudeCode/managed-settings.json
  Linux and WSL:  /etc/claude-code/managed-settings.json
  Windows:        C:\Program Files\ClaudeCode\managed-settings.json`,
	RunE: setupClaudeCodeCommand,
}

var setupGeminiCLICmd = &cobra.Command{
	Use:   "gemini-cli",
	Short: "Set up AgentShield for Gemini CLI (BeforeTool hook)",
	Long: `Install or remove the BeforeTool hook so every shell command Gemini CLI
runs is evaluated by AgentShield before execution.

  agentshield setup gemini-cli             # enable hook
  agentshield setup gemini-cli --disable   # disable hook`,
	RunE: setupGeminiCLICommand,
}

var setupCodexCmd = &cobra.Command{
	Use:   "codex",
	Short: "Set up AgentShield for OpenAI Codex CLI (PreToolUse hook)",
	Long: `Install or remove the PreToolUse hooks so every Bash and MCP tool call
Codex CLI makes is evaluated by AgentShield before execution. Codex CLI
shipped native PreToolUse hook support; the JSON payload format matches
Claude Code, so AgentShield's existing hook handler evaluates it unchanged.
Re-running it on an older install adds the MCP hook and leaves the shell
hook untouched.

  agentshield setup codex             # enable hook
  agentshield setup codex --disable   # disable hook`,
	RunE: setupCodexCommand,
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up AgentShield for your environment",
	Long: `Set up AgentShield integration with IDE agents and install default policy packs.

A new install starts in audit-only mode: nothing is blocked, and every action
enforce mode would block is recorded in ~/.agentshield/audit.jsonl. One line
turns on enforcement:

  # ~/.agentshield/agentshield.yaml
  mode: enforce

A machine that already has AgentShield state (anything in ~/.agentshield besides packs/, or a
hook in an agent's configuration) keeps the mode it has. 'agentshield status'
shows the current mode.

IDE-specific setup:
  agentshield setup claude-code           # install Claude Code PreToolUse hook
  agentshield setup claude-code --disable # remove Claude Code hook
  agentshield setup gemini-cli            # install Gemini CLI BeforeTool hook
  agentshield setup gemini-cli --disable  # remove Gemini CLI hook
  agentshield setup codex                 # install Codex CLI hooks
  agentshield setup codex --disable       # remove Codex CLI hooks
  agentshield setup copilot-cli           # install GitHub Copilot CLI PreToolUse hook
  agentshield setup copilot-cli --disable # remove Copilot CLI hook
  agentshield setup windsurf              # install Cascade Hooks
  agentshield setup windsurf --disable    # remove Cascade Hooks
  agentshield setup cursor                # install Cursor Hooks
  agentshield setup cursor --disable      # remove Cursor Hooks
  agentshield setup openclaw              # install OpenClaw Hook
  agentshield setup openclaw --disable    # remove OpenClaw Hook
  agentshield setup mcp                   # wrap MCP servers with proxy
  agentshield setup mcp --disable         # restore original MCP configs

General setup:
  agentshield setup --install   # install wrapper + policy packs
  agentshield setup             # show all integration instructions`,
	RunE: setupCommand,
}

var (
	installFlag        bool
	disableFlag        bool
	managedFlag        bool
	writeManagedFlag   bool
	onFailureBlockFlag bool
	removeManagedFlag  bool
)

func init() {
	setupCmd.Flags().BoolVar(&installFlag, "install", false, "Install wrapper script and default policy packs")
	setupClaudeCodeCmd.Flags().BoolVar(&managedFlag, "managed", false, "Print the Claude Code managed-settings JSON that registers the hook, and the per-OS file path, for MDM; writes nothing")
	setupClaudeCodeCmd.Flags().BoolVar(&writeManagedFlag, "write-managed", false, "Merge the hook into this machine's Claude Code managed settings file (needs administrator rights)")
	setupClaudeCodeCmd.Flags().BoolVar(&onFailureBlockFlag, "on-failure-block", false, `With --managed or --write-managed: give the managed hook "onFailure": "block", so Claude Code blocks a tool call when the hook cannot start, crashes or times out (for fleets running fail_closed)`)
	setupClaudeCodeCmd.Flags().BoolVar(&removeManagedFlag, "remove-managed", false, "Remove AgentShield's hook from this machine's Claude Code managed settings file (needs administrator rights; refused in managed mode)")
	setupWindsurfCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCursorCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupOpenClawCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupClaudeCodeCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupClaudeCodeCmd.MarkFlagsMutuallyExclusive("managed", "write-managed", "disable", "remove-managed")
	setupClaudeCodeCmd.MarkFlagsMutuallyExclusive("on-failure-block", "disable")
	setupClaudeCodeCmd.MarkFlagsMutuallyExclusive("on-failure-block", "remove-managed")
	setupGeminiCLICmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCodexCmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCmd.AddCommand(setupWindsurfCmd)
	setupCmd.AddCommand(setupCursorCmd)
	setupCmd.AddCommand(setupOpenClawCmd)
	setupCmd.AddCommand(setupClaudeCodeCmd)
	setupCmd.AddCommand(setupGeminiCLICmd)
	setupCmd.AddCommand(setupCodexCmd)
	// Runs for `setup` and every `setup <target>` (no subcommand defines its
	// own): new installs start in audit-only (#4337).
	setupCmd.PersistentPreRunE = setupPreRun
	rootCmd.AddCommand(setupCmd)
}

func setupCommand(cmd *cobra.Command, args []string) error {
	if installFlag {
		return runSetupInstall()
	}
	return runAutoSetup(cmd)
}

// ideDetector describes how to detect and configure an IDE.
type ideDetector struct {
	name      string
	detect    func(home string) bool
	setupFunc func(cmd *cobra.Command, args []string) error
}

func runAutoSetup(cmd *cobra.Command) error {
	home, err := setupHome()
	if err != nil {
		return err
	}

	detectors := []ideDetector{
		{
			name:      "Claude Code",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".claude")) },
			setupFunc: setupClaudeCodeCommand,
		},
		{
			name:      "Cursor",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".cursor")) },
			setupFunc: setupCursorCommand,
		},
		{
			name:      "Windsurf",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".codeium", "windsurf")) || dirExists(filepath.Join(h, ".windsurf")) },
			setupFunc: setupWindsurfCommand,
		},
		{
			name:      "OpenClaw",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".openclaw")) },
			setupFunc: setupOpenClawCommand,
		},
		{
			name:      "Gemini CLI",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".gemini")) },
			setupFunc: setupGeminiCLICommand,
		},
		{
			name:      "Codex CLI",
			detect:    func(h string) bool { return dirExists(filepath.Join(h, ".codex")) },
			setupFunc: setupCodexCommand,
		},
		{
			name:      "GitHub Copilot CLI",
			detect:    func(h string) bool { return dirExists(copilotHome(h)) },
			setupFunc: setupCopilotCLICommand,
		},
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield Auto-Setup")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()
	fmt.Println("Detecting installed IDEs...")
	fmt.Println()

	var detected []ideDetector
	for _, d := range detectors {
		if d.detect(home) {
			fmt.Printf("  ✅ %s detected\n", d.name)
			detected = append(detected, d)
		}
	}

	if len(detected) == 0 {
		fmt.Println("  ⚠  No supported IDEs detected.")
		fmt.Println()
		fmt.Println("You can set up individually:")
		fmt.Println("  agentshield setup claude-code")
		fmt.Println("  agentshield setup cursor")
		fmt.Println("  agentshield setup windsurf")
		fmt.Println("  agentshield setup openclaw")
		fmt.Println("  agentshield setup gemini-cli")
		fmt.Println("  agentshield setup codex")
		fmt.Println("  agentshield setup copilot-cli")
		return nil
	}

	fmt.Println()
	fmt.Printf("Configuring %d IDE(s)...\n", len(detected))
	fmt.Println()

	var errs []string
	for _, d := range detected {
		if err := d.setupFunc(cmd, nil); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", d.name, err))
		}
		fmt.Println()
	}

	if len(errs) > 0 {
		fmt.Println("─── Errors ───────────────────────────────────────────")
		for _, e := range errs {
			fmt.Printf("  ✗ %s\n", e)
		}
		fmt.Println()
	}

	fmt.Println("─── Quick Reference ──────────────────────────────────")
	fmt.Println()
	fmt.Println("  agentshield scan              # verify hooks are active")
	fmt.Println("  agentshield pause [minutes]   # temporarily pause enforcement")
	fmt.Println("  agentshield resume            # resume enforcement")
	fmt.Println()

	return nil
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func runSetupInstall() error {
	cfg, err := config.Load("", "", "")
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Ensure config directory exists
	if err := os.MkdirAll(cfg.ConfigDir, 0755); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}

	// Ensure packs directory exists
	packsDir := filepath.Join(cfg.ConfigDir, "packs")
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return fmt.Errorf("failed to create packs dir: %w", err)
	}

	// Find wrapper script source
	wrapperSrc := findWrapperSource()
	if wrapperSrc == "" {
		fmt.Fprintln(os.Stderr, "⚠  Could not find agentshield-wrapper.sh source.")
		fmt.Fprintln(os.Stderr, "   The wrapper will need to be installed manually.")
	} else {
		// Install wrapper to share directory
		shareDir := getShareDir()
		if err := os.MkdirAll(shareDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Could not create %s: %v\n", shareDir, err)
			fmt.Fprintln(os.Stderr, "   Try: sudo agentshield setup --install")
		} else {
			wrapperDst := filepath.Join(shareDir, "agentshield-wrapper.sh")
			data, err := os.ReadFile(wrapperSrc)
			if err != nil {
				return fmt.Errorf("failed to read wrapper source: %w", err)
			}
			if err := os.WriteFile(wrapperDst, data, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "⚠  Could not write to %s: %v\n", wrapperDst, err)
				fmt.Fprintln(os.Stderr, "   Try: sudo agentshield setup --install")
			} else {
				fmt.Printf("✅ Wrapper installed: %s\n", wrapperDst)
			}
		}
	}

	// Copy bundled packs if packs dir is empty
	packsSrc := findPacksSource()
	if packsSrc != "" {
		installed := installPacks(packsSrc, packsDir)
		if installed > 0 {
			fmt.Printf("✅ %d policy packs installed to %s\n", installed, packsDir)
		} else {
			fmt.Printf("✅ Policy packs already present in %s\n", packsDir)
		}
	}

	fmt.Println()
	printSetupInstructions()
	return nil
}

// ─── Shared Disable Logic ────────────────────────────────────────────────────

func disableHook(hooksPath, ideName string) error {
	backupPath := hooksPath + ".bak"

	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		fmt.Printf("ℹ  No hooks.json found for %s — nothing to disable.\n", ideName)
		return nil
	}

	data, err := os.ReadFile(hooksPath)
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", hooksPath, err)
	}

	if !strings.Contains(string(data), "agentshield hook") {
		fmt.Printf("ℹ  %s hooks.json does not contain AgentShield — nothing to disable.\n", ideName)
		return nil
	}

	// Back up then remove
	if err := os.Rename(hooksPath, backupPath); err != nil {
		return fmt.Errorf("failed to rename %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ AgentShield hook disabled for %s\n", ideName)
	fmt.Printf("   Backup saved: %s\n", backupPath)
	fmt.Println()
	fmt.Printf("Restart %s to apply. Re-enable anytime with:\n", ideName)
	fmt.Printf("  agentshield setup %s\n", strings.ToLower(ideName))
	return nil
}

// ─── Windsurf Setup ─────────────────────────────────────────────────────────

func setupWindsurfCommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}
	hooksPath := filepath.Join(home, ".codeium", "windsurf", "hooks.json")
	hooksDir := filepath.Dir(hooksPath)

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableHook(hooksPath, "Windsurf")
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Windsurf (Cascade Hooks)")
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

	// Check for existing hooks.json
	if _, err := os.Stat(hooksPath); err == nil {
		// Read existing hooks
		data, err := os.ReadFile(hooksPath)
		if err == nil && strings.Contains(string(data), "agentshield hook") {
			fmt.Printf("✅ Cascade Hook already configured: %s\n", hooksPath)
			fmt.Println()
			printTestHint("Cascade")
			fmt.Println()
			fmt.Println("To disable: agentshield setup windsurf --disable")
			fmt.Println()
			printStatus()
			return nil
		}
		// Hooks file exists but doesn't have our hook — show manual instructions
		fmt.Printf("⚠  Existing hooks.json found: %s\n", hooksPath)
		fmt.Println("   Add this to the \"hooks\" object manually:")
		fmt.Println()
		fmt.Println(`   "pre_run_command": [`)
		fmt.Println(`     {`)
		fmt.Println(`       "command": "agentshield hook",`)
		fmt.Println(`       "show_output": true`)
		fmt.Println(`     }`)
		fmt.Println(`   ]`)
		fmt.Println()
		return nil
	}

	// Create hooks.json
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hooksDir, err)
	}

	hooksContent := `{
  "hooks": {
    "pre_run_command": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`
	if err := os.WriteFile(hooksPath, []byte(hooksContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ Cascade Hook installed: %s\n", hooksPath)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Cascade (Windsurf's AI) tries to run a command")
	fmt.Println("  2. The pre_run_command hook calls `agentshield hook`")
	fmt.Println("  3. AgentShield evaluates the command against your policy")
	fmt.Println("  4. If BLOCK (enforce mode): Cascade is prevented from running the command")
	fmt.Println("  5. If ALLOW/AUDIT: the command runs normally")
	fmt.Println()
	fmt.Println("To disable: agentshield setup windsurf --disable")
	fmt.Println()
	fmt.Println("Restart Windsurf to activate the hook.")
	printTestHint("Cascade")
	fmt.Println()
	printStatus()
	return nil
}

// ─── Cursor Setup ───────────────────────────────────────────────────────────

func setupCursorCommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}
	hooksPath := filepath.Join(home, ".cursor", "hooks.json")
	hooksDir := filepath.Dir(hooksPath)

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableHook(hooksPath, "Cursor")
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Cursor (Hooks)")
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

	// Check for existing hooks.json
	if _, err := os.Stat(hooksPath); err == nil {
		data, err := os.ReadFile(hooksPath)
		if err == nil && strings.Contains(string(data), "agentshield hook") {
			fmt.Printf("✅ Cursor Hook already configured: %s\n", hooksPath)
			fmt.Println()
			printTestHint("Cursor's Agent")
			fmt.Println()
			fmt.Println("To disable: agentshield setup cursor --disable")
			fmt.Println()
			printStatus()
			return nil
		}
		fmt.Printf("⚠  Existing hooks.json found: %s\n", hooksPath)
		fmt.Println("   Add this to the \"hooks\" object manually:")
		fmt.Println()
		fmt.Println(`   "beforeShellExecution": [`)
		fmt.Println(`     {`)
		fmt.Println(`       "command": "agentshield hook",`)
		fmt.Println(`       "show_output": true`)
		fmt.Println(`     }`)
		fmt.Println(`   ]`)
		fmt.Println()
		return nil
	}

	// Create hooks.json
	if err := os.MkdirAll(hooksDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hooksDir, err)
	}

	hooksContent := `{
  "hooks": {
    "beforeShellExecution": [
      {
        "command": "agentshield hook",
        "show_output": true
      }
    ]
  }
}
`
	if err := os.WriteFile(hooksPath, []byte(hooksContent), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", hooksPath, err)
	}

	fmt.Printf("✅ Cursor Hook installed: %s\n", hooksPath)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Cursor's Agent tries to run a command")
	fmt.Println("  2. The beforeShellExecution hook calls `agentshield hook`")
	fmt.Println("  3. AgentShield evaluates the command against your policy")
	fmt.Println("  4. If BLOCK (enforce mode): Agent is prevented from running the command")
	fmt.Println("  5. If ALLOW/AUDIT: the command runs normally")
	fmt.Println()
	fmt.Println("To disable: agentshield setup cursor --disable")
	fmt.Println()
	fmt.Println("Restart Cursor to activate the hook.")
	printTestHint("Cursor's Agent")
	fmt.Println()
	printStatus()
	return nil
}

// ─── OpenClaw Setup ─────────────────────────────────────────────────────────

func setupOpenClawCommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}
	hookDir := filepath.Join(home, ".openclaw", "hooks", "agentshield")

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableOpenClawHook(hookDir)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + OpenClaw")
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

	// Check if openclaw is installed
	clawPath, err := exec.LookPath("openclaw")
	if err != nil {
		fmt.Println("⚠  openclaw not found in PATH. Install it first:")
		fmt.Println("   brew install openclaw")
		return nil
	}
	fmt.Printf("✅ openclaw found: %s\n", clawPath)

	// Check if hook already installed
	hookMd := filepath.Join(hookDir, "HOOK.md")
	if _, err := os.Stat(hookMd); err == nil {
		fmt.Printf("✅ AgentShield hook already installed: %s\n", hookDir)
		fmt.Println()
		fmt.Println("Hook is installed. Enable it and restart the gateway:")
		fmt.Println("  openclaw hooks enable agentshield")
		fmt.Println()
		fmt.Println("To disable: agentshield setup openclaw --disable")
		fmt.Println()
		printStatus()
		return nil
	}

	// Find the hook pack source
	hookSrc := findOpenClawHookSource()
	if hookSrc == "" {
		fmt.Println("⚠  Could not find openclaw-hook source directory.")
		fmt.Println("   Try installing from the repo:")
		fmt.Println("   openclaw hooks install /path/to/Agentic-gateway/openclaw-hook")
		return nil
	}

	// Copy hook files to ~/.openclaw/hooks/agentshield/
	if err := os.MkdirAll(hookDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", hookDir, err)
	}

	hookFiles := []string{"HOOK.md", "handler.ts", "AGENTSHIELD.md"}
	for _, f := range hookFiles {
		src := filepath.Join(hookSrc, "agentshield", f)
		dst := filepath.Join(hookDir, f)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", dst, err)
		}
	}

	fmt.Printf("✅ Hook installed: %s\n", hookDir)
	fmt.Println()

	// Try to enable the hook via openclaw CLI
	enableCmd := exec.Command("openclaw", "hooks", "enable", "agentshield")
	enableOut, err := enableCmd.CombinedOutput()
	if err != nil {
		fmt.Println("⚠  Could not auto-enable hook. Enable it manually:")
		fmt.Println("   openclaw hooks enable agentshield")
	} else {
		outStr := strings.TrimSpace(string(enableOut))
		if outStr != "" {
			// Print the last meaningful line (skip the OpenClaw banner)
			lines := strings.Split(outStr, "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				line := strings.TrimSpace(lines[i])
				if line != "" && !strings.HasPrefix(line, "🦞") && !strings.HasPrefix(line, "(node:") {
					fmt.Printf("✅ %s\n", line)
					break
				}
			}
		}
	}

	// Install policy packs
	cfg, _ := config.Load("", "", "")
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		if err := os.MkdirAll(packsDir, 0755); err == nil {
			packsSrc := findPacksSource()
			if packsSrc != "" {
				installed := installPacks(packsSrc, packsDir)
				if installed > 0 {
					fmt.Printf("✅ %d policy packs installed to %s\n", installed, packsDir)
				}
			}
		}
	}

	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. OpenClaw starts a session with the agent")
	fmt.Println("  2. AgentShield hook injects a note into the agent's context (AGENTSHIELD.md)")
	fmt.Println()
	fmt.Println("⚠  That is all it does. OpenClaw has no integration that sends its shell")
	fmt.Println("   commands or tool calls to AgentShield, so nothing is evaluated, logged")
	fmt.Println("   or blocked. Do not rely on AgentShield to protect an OpenClaw agent.")
	fmt.Println()
	fmt.Println("Restart the OpenClaw gateway to activate the hook.")
	fmt.Println()
	fmt.Println("To disable: agentshield setup openclaw --disable")
	fmt.Println()
	printStatus()
	return nil
}

func disableOpenClawHook(hookDir string) error {
	hookMd := filepath.Join(hookDir, "HOOK.md")
	if _, err := os.Stat(hookMd); os.IsNotExist(err) {
		fmt.Println("ℹ  No AgentShield hook found for OpenClaw — nothing to disable.")
		return nil
	}

	// Try to disable via openclaw CLI first
	disCmd := exec.Command("openclaw", "hooks", "disable", "agentshield")
	_ = disCmd.Run() // ignore errors — hook dir removal is the real action

	// Remove the hook directory
	backupDir := hookDir + ".bak"
	if err := os.Rename(hookDir, backupDir); err != nil {
		return fmt.Errorf("failed to remove hook: %w", err)
	}

	fmt.Println("✅ AgentShield hook disabled for OpenClaw")
	fmt.Printf("   Backup saved: %s\n", backupDir)
	fmt.Println()
	fmt.Println("Restart the OpenClaw gateway to apply.")
	fmt.Println("Re-enable anytime with: agentshield setup openclaw")
	return nil
}

// ─── Claude Code Setup ───────────────────────────────────────────────────────

// claudeCodeHook is AgentShield's hook object for Claude Code and the form it
// takes (#4292).
//
// With exec true it is exec form, {"command": binPath, "args": ["hook"]}.
// Claude Code 2.1.139 and later spawn it directly, so a CLAUDE_CODE_SHELL_PREFIX
// set from a committed project .claude/settings.json cannot wrap it. Claude
// Code 2.1.138 and earlier drop "args" and run binPath bare; the bare-invocation
// backstop (bare_hook.go) routes that to `agentshield hook`. Otherwise it is
// today's shell form. execFormBlocker decides which.
func claudeCodeHook(binPath string, exec bool) (map[string]interface{}, hookentry.Form) {
	if exec {
		return hookentry.ExecHook(binPath), hookentry.Exec
	}
	return hookentry.ShellHook(binPath), hookentry.Shell
}

// selfExecutable is the binary running setup. A variable so tests can pin it.
var selfExecutable = os.Executable

// execFormBlocker returns "" when the hook may name binPath in exec form, and
// otherwise the one-line reason it must stay in shell form.
//
// Exec form is safe only because of the bare-invocation backstop: Claude Code
// 2.1.138 and earlier run binPath bare. So binPath must be the binary running
// setup, which has the backstop. setup writes resolveAgentShieldPath(), which
// prefers /opt/homebrew/bin and /usr/local/bin over the running binary; an
// older copy there would print help and exit 0 when run bare, an allow of
// everything, where the shell form it had before still evaluated (#4292 review
// pass 1, C1). The comparison resolves symlinks, so the brew link to the
// running Cellar or Caskroom binary counts as the same binary.
//
// A binPath that is not absolute (only the "agentshield" fallback of
// resolveAgentShieldPath) also stays in shell form: an exec-form program name
// that is not a path leaves the lookup to Claude Code, which is unmeasured.
func execFormBlocker(binPath string) string {
	if !filepath.IsAbs(binPath) {
		return fmt.Sprintf("agentshield path %q is not absolute, so the hook stays in shell form, which a project-set CLAUDE_CODE_SHELL_PREFIX can wrap (#4292)", binPath)
	}
	exe, err := selfExecutable()
	if err == nil && sameBinary(binPath, exe) {
		return ""
	}
	if err != nil {
		exe = "unknown: " + err.Error()
	}
	return fmt.Sprintf("agentshield at %s is not the binary running setup (%s); keeping shell form — update or remove %s, or re-run setup with it once it is current", binPath, exe, binPath)
}

// sameBinary reports whether a and b name the same file once symlinks are
// resolved. Any resolution error counts as different.
func sameBinary(a, b string) bool {
	ra, err := filepath.EvalSymlinks(a)
	if err != nil {
		return false
	}
	rb, err := filepath.EvalSymlinks(b)
	if err != nil {
		return false
	}
	return ra == rb
}

// agentShieldPathCandidates are the install locations resolveAgentShieldPath
// prefers. A variable so tests can keep the real ones out of reach.
var agentShieldPathCandidates = []string{
	"/opt/homebrew/bin/agentshield",
	"/usr/local/bin/agentshield",
}

// resolveAgentShieldPath returns the absolute path to the agentshield binary.
// Prefers /opt/homebrew/bin (brew cask), then LookPath, then current executable.
func resolveAgentShieldPath() string {
	// Prefer the brew location
	for _, c := range agentShieldPathCandidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if p, err := exec.LookPath("agentshield"); err == nil {
		return p
	}
	if p, err := os.Executable(); err == nil {
		return p
	}
	return "agentshield"
}

// claudeHookInstall reports what installClaudeCodeHook did.
type claudeHookInstall struct {
	// Form is the form of the AgentShield entry the settings file now holds
	// (exec form when it holds entries of both forms).
	Form hookentry.Form
	// Added is true when the file held no AgentShield entry and one was appended.
	Added bool
	// Migrated holds the command of each shell-form AgentShield entry that was
	// rewritten to exec form in place.
	Migrated []string
	// OnFailureChanged counts the AgentShield hook objects already in the
	// file whose "onFailure" key the merge set or removed.
	OnFailureChanged int
}

// changed reports whether the merge changed the settings document.
func (r claudeHookInstall) changed() bool {
	return r.Added || len(r.Migrated) > 0 || r.OnFailureChanged > 0
}

// Claude Code's "onFailure" hook key, on the AgentShield entry (#4772
// follow-up, Gary 2026-11-04).
//
// On PreToolUse a command hook that cannot start, times out, or exits with a
// code other than 0 or 2 does not block: Claude Code runs the tool call. With
// "onFailure": "block" on the hook object, each of those blocks the call
// (https://code.claude.com/docs/en/hooks, "Block the action when a hook
// fails"). That covers what the hook cannot answer itself: a missing or
// killed binary, a hang, a crash that is not Go's exit 2, a call past Claude
// Code's hook timeout.
//
// Setup writes it only where the hook itself already fails closed:
// failClosedEnabled, the predicate the hook uses at run time, which reads
// fail_closed from ~/.agentshield/managed.json. Claude Code then blocks on a
// hook failure exactly when the hook would have blocked on its own failure.
// An unmanaged install gets no harness-level block (Gary's minimal-intrusion
// rule).
//
// Claude Code added the key in 2.1.295. Earlier versions load an entry that
// carries it and ignore the key: measured 2026-11-04 on 1.0.60, 1.0.128,
// 2.0.20, 2.0.77, 2.1.109, 2.1.110, 2.1.138, 2.1.139, 2.1.200, 2.1.250 and
// 2.1.294 (darwin-arm64, a mock API, a throwaway HOME). On each, a hook
// carrying the key still blocked with exit 2, and a failing one let the call
// run, as it does without the key. So no version gate.
const claudeOnFailureKey, claudeOnFailureBlock = "onFailure", "block"

// onFailurePolicy says what mergeClaudeCodeHook does with the "onFailure" key
// of the AgentShield hook objects in a document. Hook objects that are not
// AgentShield's are never touched.
type onFailurePolicy int

const (
	// onFailureKeep leaves the key as it is on existing entries and writes no
	// key on a new one.
	onFailureKeep onFailurePolicy = iota
	// onFailureBlock sets "onFailure": "block" on every AgentShield entry.
	onFailureBlock
	// onFailureOmit removes the key from every AgentShield entry.
	onFailureOmit
)

// userScopeOnFailure is the policy for the user-scope settings file, which
// setup owns: "block" when the hook runs fail_closed, and otherwise no key, so
// a host that turns fail_closed off converges back on the next setup run.
func userScopeOnFailure() onFailurePolicy {
	if failClosedEnabled(nil) {
		return onFailureBlock
	}
	return onFailureOmit
}

// managedOnFailure is the policy for Claude Code's managed settings
// (--managed, --write-managed): "block" only when the administrator passed
// --on-failure-block, and otherwise keep, which writes no key and leaves any
// key already in the file, as main did. It is never inferred from managed.json:
// these commands run under sudo or an MDM script, whose HOME (root's, or none)
// says nothing about the fleet's fail_closed (Codex pass 1 on this change).
func managedOnFailure(blockFlag bool) onFailurePolicy {
	if blockFlag {
		return onFailureBlock
	}
	return onFailureKeep
}

// applyOnFailure applies p to one AgentShield hook object and reports whether
// it changed it.
func applyOnFailure(hm map[string]interface{}, p onFailurePolicy) bool {
	switch p {
	case onFailureBlock:
		if hm[claudeOnFailureKey] != claudeOnFailureBlock {
			hm[claudeOnFailureKey] = claudeOnFailureBlock
			return true
		}
	case onFailureOmit:
		if _, ok := hm[claudeOnFailureKey]; ok {
			delete(hm, claudeOnFailureKey)
			return true
		}
	}
	return false
}

// printOnFailureState says what the entry's "onFailure" key means after a
// merge with policy p. onFailureKeep prints nothing: the key is whatever the
// file already held.
func printOnFailureState(w io.Writer, p onFailurePolicy) {
	switch p {
	case onFailureBlock:
		_, _ = fmt.Fprintln(w, "   \"onFailure\": \"block\" — fail_closed (managed.json): Claude Code (2.1.295+) blocks the tool")
		_, _ = fmt.Fprintln(w, "   call when the hook cannot start, crashes or times out. While agentshield is missing or")
		_, _ = fmt.Fprintln(w, "   broken (a Homebrew upgrade's relink, an uninstall), every Claude Code tool call is blocked.")
	case onFailureOmit:
		_, _ = fmt.Fprintln(w, "   No \"onFailure\" key: if the hook cannot start, crashes or times out, Claude Code runs the")
		_, _ = fmt.Fprintln(w, "   tool call. Managed hosts with fail_closed get \"onFailure\": \"block\".")
	}
}

// installClaudeCodeHook makes the Claude Code settings file at settingsPath
// hold AgentShield's PreToolUse hook for binPath (mergeClaudeCodeHook), and
// writes the file only when something changed. execOK says whether binPath
// may be written in exec form (execFormBlocker); onFail what happens to the
// entry's "onFailure" key.
func installClaudeCodeHook(settingsPath, binPath string, execOK bool, onFail onFailurePolicy) (claudeHookInstall, error) {
	settings, err := readClaudeSettings(settingsPath)
	if err != nil {
		return claudeHookInstall{}, err
	}
	res := mergeClaudeCodeHook(settings, binPath, execOK, onFail)
	if !res.changed() {
		return res, nil
	}
	return res, writeClaudeSettings(settingsPath, settings)
}

// mergeClaudeCodeHook makes a Claude Code settings document hold AgentShield's
// PreToolUse hook for binPath. It is the one definition of the entry: the
// user-scope install, the managed-settings snippet (`setup claude-code
// --managed`) and the managed-settings merge (--write-managed) all call it,
// so the three cannot drift (#4292).
//
//   - No AgentShield entry: append one, in exec form when execOK, else shell.
//   - A shell-form AgentShield entry and execOK: rewrite that hook object to
//     exec form in place. Its other keys (a timeout, say), its matcher group
//     and the hooks beside it are left as they are. Without execOK it stays.
//   - Otherwise the document already holds our entry: change nothing.
//   - Every AgentShield hook object, new or found, gets onFail applied to its
//     "onFailure" key (onFailurePolicy).
//
// It never adds a second entry, never downgrades exec form to shell form, and
// never touches a hook object that is not AgentShield's. Keys outside
// hooks.PreToolUse are left as they are.
func mergeClaudeCodeHook(settings map[string]interface{}, binPath string, execOK bool, onFail onFailurePolicy) claudeHookInstall {
	var res claudeHookInstall
	hooks := getOrCreateMap(settings, "hooks")
	preToolUse := getOrCreateSlice(hooks, "PreToolUse")
	want, wantForm := claudeCodeHook(binPath, execOK)
	applyOnFailure(want, onFail)

	found := false
	for _, group := range preToolUse {
		gm, ok := group.(map[string]interface{})
		if !ok {
			continue
		}
		subHooks, _ := gm["hooks"].([]interface{})
		for _, h := range subHooks {
			form := hookentry.Classify(h)
			if form == hookentry.None {
				continue
			}
			found = true
			hm := h.(map[string]interface{}) // Classify accepts only objects
			if form == hookentry.Shell && wantForm == hookentry.Exec {
				res.Migrated = append(res.Migrated, hm["command"].(string))
				hm["command"] = binPath
				hm["args"] = []interface{}{hookentry.Subcommand}
				form = hookentry.Exec
			}
			if applyOnFailure(hm, onFail) {
				res.OnFailureChanged++
			}
			if res.Form != hookentry.Exec {
				res.Form = form
			}
		}
	}

	if !found {
		// No "matcher": the group fires on every tool call, Bash and MCP alike
		// (https://code.claude.com/docs/en/hooks: "If you omit the matcher or
		// use "*", the group activates on every occurrence of the event.").
		hooks["PreToolUse"] = append(preToolUse, map[string]interface{}{
			"hooks": []interface{}{want},
		})
		res.Added = true
		res.Form = wantForm
	}
	if res.changed() {
		settings["hooks"] = hooks
	}
	return res
}

func setupClaudeCodeCommand(cmd *cobra.Command, args []string) error {
	// Managed settings (#4292). Neither path touches ~/.claude: --managed
	// writes nothing, and --write-managed usually runs under sudo, where a
	// user-scope write would leave a root-owned file in the user's home.
	// They come before HOME is resolved because they never use it, so an MDM
	// script with no HOME can still run them (#4565). --disable cannot reach
	// this branch: cobra refuses it alongside either flag
	// (MarkFlagsMutuallyExclusive in init).
	if onFailureBlockFlag && !managedFlag && !writeManagedFlag {
		return fmt.Errorf(`--on-failure-block applies to --managed and --write-managed; the user-scope hook gets "onFailure": "block" from fail_closed in ~/.agentshield/managed.json`)
	}
	if removeManagedFlag {
		// A new way to switch AgentShield off for the machine, so it is
		// refused like --disable, and also when the account that ran sudo is
		// enrolled (CheckManagedRemovalAllowed).
		if err := enterprise.CheckManagedRemovalAllowed(); err != nil {
			return err
		}
		return runRemoveManaged(cmd.OutOrStdout(), managedSetupPath())
	}
	if managedFlag || writeManagedFlag {
		hookPath := resolveAgentShieldPath()
		blocker := execFormBlocker(hookPath)
		onFail := managedOnFailure(onFailureBlockFlag)
		if managedFlag {
			return printManagedClaudeSnippet(cmd.OutOrStdout(), cmd.ErrOrStderr(), hookPath, blocker, managedSetupPath(), onFail)
		}
		return runWriteManaged(cmd.OutOrStdout(), managedSetupPath(), hookPath, blocker, onFail)
	}

	home, err := setupHome()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".claude", "settings.json")

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableClaudeCodeHook(settingsPath)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Claude Code (PreToolUse Hook)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap AI-AgentLens/oss && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	hookPath := resolveAgentShieldPath()
	blocker := execFormBlocker(hookPath)
	onFail := userScopeOnFailure()
	res, err := installClaudeCodeHook(settingsPath, hookPath, blocker == "", onFail)
	if err != nil {
		return err
	}
	if res.Form == hookentry.Shell && blocker != "" {
		fmt.Printf("⚠  %s\n", blocker)
	}

	switch {
	case res.Added:
		fmt.Printf("✅ PreToolUse hook installed in %s: %s\n", res.Form, settingsPath)
	case len(res.Migrated) > 0:
		fmt.Printf("✅ PreToolUse hook migrated from shell form to exec form: %s\n", settingsPath)
		for _, was := range res.Migrated {
			fmt.Printf("   was: %q\n", was)
		}
	case res.OnFailureChanged > 0:
		fmt.Printf("✅ PreToolUse hook updated (%s): %s\n", res.Form, settingsPath)
	default:
		fmt.Printf("✅ Claude Code hook already configured (%s): %s\n", res.Form, settingsPath)
		printOnFailureState(os.Stdout, onFail)
		fmt.Println()
		printTestHint("Claude Code")
		fmt.Println()
		fmt.Println("To disable: agentshield setup claude-code --disable")
		fmt.Println()
		printStatus()
		return nil
	}
	if res.Form == hookentry.Exec {
		fmt.Printf("   \"command\": %q, \"args\": [\"hook\"] — Claude Code runs it directly, not through a shell\n", hookPath)
	}
	printOnFailureState(os.Stdout, onFail)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Claude Code is about to run any tool call (Bash, MCP, etc.)")
	fmt.Println("  2. The PreToolUse hook calls `agentshield hook`")
	fmt.Println("  3. Bash calls → shell analyzer pipeline (6-layer)")
	fmt.Println("     MCP calls → MCP policy evaluator (packs + content scanner)")
	fmt.Println("  4. If BLOCK (enforce mode): Claude Code is prevented from running the tool")
	fmt.Println("  5. If ALLOW/AUDIT: the tool runs normally")
	fmt.Println()
	fmt.Println("To disable: agentshield setup claude-code --disable")
	fmt.Println()
	printTestHint("Claude Code")
	fmt.Println()
	printStatus()
	return nil
}

func disableClaudeCodeHook(settingsPath string) error {
	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
		fmt.Println("ℹ  No settings.json found for Claude Code — nothing to disable.")
		return nil
	}

	settings, err := readClaudeSettings(settingsPath)
	if err != nil {
		return err
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		fmt.Println("ℹ  Claude Code settings.json has no hooks — nothing to disable.")
		return nil
	}

	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	filtered, removed := removeAgentShieldHooks(preToolUse)

	if removed == 0 {
		fmt.Println("ℹ  AgentShield hook not found in Claude Code settings — nothing to disable.")
		return nil
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	if err := writeClaudeSettings(settingsPath, settings); err != nil {
		return err
	}

	fmt.Printf("✅ AgentShield hook disabled for Claude Code\n")
	fmt.Printf("   Settings: %s\n", settingsPath)
	fmt.Println()
	fmt.Println("Re-enable anytime with: agentshield setup claude-code")
	return nil
}

// removeAgentShieldHooks removes every AgentShield hook object, in shell or
// exec form, from a list of PreToolUse matcher groups and returns the groups
// left and how many objects it removed. Other hook objects stay in their
// group; a group that held only AgentShield hooks is dropped.
func removeAgentShieldHooks(groups []interface{}) ([]interface{}, int) {
	kept := make([]interface{}, 0, len(groups))
	removed := 0
	for _, group := range groups {
		gm, isMap := group.(map[string]interface{})
		subHooks, isList := gm["hooks"].([]interface{})
		if !isMap || !isList {
			kept = append(kept, group)
			continue
		}
		rest := make([]interface{}, 0, len(subHooks))
		for _, h := range subHooks {
			if hookentry.IsAgentShieldHook(h) {
				removed++
				continue
			}
			rest = append(rest, h)
		}
		switch {
		case len(rest) == len(subHooks):
			kept = append(kept, group)
		case len(rest) == 0:
			// The group held only AgentShield hooks.
		default:
			gm["hooks"] = rest
			kept = append(kept, gm)
		}
	}
	return kept, removed
}

// stripUTF8BOM drops a leading UTF-8 byte-order mark. Windows PowerShell 5.1
// writes one with Set-Content/Out-File -Encoding UTF8, and Claude Code reads
// such a file, so a config with a BOM is a real state (#4741). encoding/json
// rejects it. Every JSON config setup, status or scan reads goes through here;
// writes are re-marshalled and carry no BOM.
func stripUTF8BOM(data []byte) []byte {
	return bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
}

func readClaudeSettings(path string) (map[string]interface{}, error) {
	settings := make(map[string]interface{})
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(stripUTF8BOM(data)) > 0 {
		if err := json.Unmarshal(stripUTF8BOM(data), &settings); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
	}
	return settings, nil
}

func writeClaudeSettings(path string, settings map[string]interface{}) error {
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}
	// Ensure ~/.claude/ exists. A user running `agentshield setup claude-code`
	// before ever launching Claude Code (clean container, fresh install) would
	// otherwise see a confusing "no such file or directory" error.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

func getOrCreateMap(parent map[string]interface{}, key string) map[string]interface{} {
	if v, ok := parent[key].(map[string]interface{}); ok {
		return v
	}
	m := make(map[string]interface{})
	parent[key] = m
	return m
}

func getOrCreateSlice(parent map[string]interface{}, key string) []interface{} {
	if v, ok := parent[key].([]interface{}); ok {
		return v
	}
	return nil
}

// findOpenClawHookSource looks for the openclaw-hook directory in known locations.
func findOpenClawHookSource() string {
	candidates := []string{
		filepath.Join(getShareDir(), "openclaw-hook"),
	}

	// Check relative to binary
	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		candidates = append(candidates,
			filepath.Join(binDir, "..", "share", "agentshield", "openclaw-hook"),
			filepath.Join(binDir, "..", "openclaw-hook"),
		)
	}

	// Check current working directory (for dev)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "openclaw-hook"))
	}

	for _, c := range candidates {
		hookMd := filepath.Join(c, "agentshield", "HOOK.md")
		if _, err := os.Stat(hookMd); err == nil {
			return c
		}
	}
	return ""
}

// ─── Gemini CLI Setup ────────────────────────────────────────────────────────

// agentshieldGeminiHookEntry builds the hook object for Gemini CLI with absolute path.
func agentshieldGeminiHookEntry() map[string]interface{} {
	binPath := resolveAgentShieldPath()
	return map[string]interface{}{
		"matcher": "run_shell_command",
		"hooks": []interface{}{
			map[string]interface{}{
				"type":    "command",
				"command": binPath + " hook",
				"name":    "agentshield",
				"timeout": 10000,
			},
		},
	}
}

func setupGeminiCLICommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}
	settingsPath := filepath.Join(home, ".gemini", "settings.json")

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableGeminiCLIHook(settingsPath)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + Gemini CLI (BeforeTool Hook)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap AI-AgentLens/oss && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	// Read or initialise settings.json
	settings, err := readGeminiSettings(settingsPath)
	if err != nil {
		return err
	}

	// Navigate to hooks → BeforeTool
	hooks := getOrCreateMap(settings, "hooks")
	beforeTool := getOrCreateSlice(hooks, "BeforeTool")

	// Check whether our entry is already present
	for _, entry := range beforeTool {
		if isAgentShieldGeminiHookEntry(entry) {
			fmt.Printf("✅ Gemini CLI hook already configured: %s\n", settingsPath)
			fmt.Println()
			printTestHint("Gemini CLI")
			fmt.Println()
			fmt.Println("To disable: agentshield setup gemini-cli --disable")
			fmt.Println()
			printStatus()
			return nil
		}
	}

	hooks["BeforeTool"] = append(beforeTool, agentshieldGeminiHookEntry())
	settings["hooks"] = hooks

	if err := writeGeminiSettings(settingsPath, settings); err != nil {
		return err
	}

	fmt.Printf("✅ BeforeTool hook installed: %s\n", settingsPath)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Gemini CLI is about to run a shell command")
	fmt.Println("  2. The BeforeTool hook calls `agentshield hook`")
	fmt.Println("  3. AgentShield evaluates the command against your policy")
	fmt.Println("  4. If BLOCK (enforce mode): Gemini CLI is prevented from running the command")
	fmt.Println("  5. If ALLOW/AUDIT: the command runs normally")
	fmt.Println()
	fmt.Println("To disable: agentshield setup gemini-cli --disable")
	fmt.Println()
	printTestHint("Gemini CLI")
	fmt.Println()
	printStatus()
	return nil
}

func disableGeminiCLIHook(settingsPath string) error {
	if _, err := os.Stat(settingsPath); os.IsNotExist(err) {
		fmt.Println("ℹ  No settings.json found for Gemini CLI — nothing to disable.")
		return nil
	}

	settings, err := readGeminiSettings(settingsPath)
	if err != nil {
		return err
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		fmt.Println("ℹ  Gemini CLI settings.json has no hooks — nothing to disable.")
		return nil
	}

	beforeTool, _ := hooks["BeforeTool"].([]interface{})
	filtered := make([]interface{}, 0, len(beforeTool))
	removed := false
	for _, entry := range beforeTool {
		if isAgentShieldGeminiHookEntry(entry) {
			removed = true
			continue
		}
		filtered = append(filtered, entry)
	}

	if !removed {
		fmt.Println("ℹ  AgentShield hook not found in Gemini CLI settings — nothing to disable.")
		return nil
	}

	if len(filtered) == 0 {
		delete(hooks, "BeforeTool")
	} else {
		hooks["BeforeTool"] = filtered
	}
	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	if err := writeGeminiSettings(settingsPath, settings); err != nil {
		return err
	}

	fmt.Printf("✅ AgentShield hook disabled for Gemini CLI\n")
	fmt.Printf("   Settings: %s\n", settingsPath)
	fmt.Println()
	fmt.Println("Re-enable anytime with: agentshield setup gemini-cli")
	return nil
}

func isAgentShieldGeminiHookEntry(entry interface{}) bool {
	m, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	subHooks, _ := m["hooks"].([]interface{})
	for _, h := range subHooks {
		if hm, ok := h.(map[string]interface{}); ok {
			if cmd, ok := hm["command"].(string); ok && strings.HasSuffix(cmd, "agentshield hook") {
				return true
			}
		}
	}
	return false
}

func readGeminiSettings(path string) (map[string]interface{}, error) {
	settings := make(map[string]interface{})
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create %s: %w", dir, err)
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if len(stripUTF8BOM(data)) > 0 {
		if err := json.Unmarshal(stripUTF8BOM(data), &settings); err != nil {
			return nil, fmt.Errorf("failed to parse %s: %w", path, err)
		}
	}
	return settings, nil
}

func writeGeminiSettings(path string, settings map[string]interface{}) error {
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}
	if err := os.WriteFile(path, out, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}

// ─── Codex CLI Setup ─────────────────────────────────────────────────────────

// Codex matches a hook group against tool_name. A matcher with regex
// characters is an unanchored regex search and one without is an exact match
// (codex-rs/hooks/src/events/common.rs), so "mcp__" alone would match nothing.
// Codex names an MCP tool mcp__<server>__<tool>
// (codex-rs/core/src/tools/handlers/mcp.rs), the same as Claude Code.
const (
	codexShellMatcher = "^Bash$"
	codexMCPMatcher   = "^mcp__.*"
)

// Codex titles a hook in /hooks with its statusMessage ("Unnamed hook"
// without one) and shows it beside a hook run that takes long enough to draw
// (codex-rs/tui/src/bottom_pane/hooks_browser_view.rs, history_cell/hook_cell.rs).
// It is part of the trust hash, so only entries setup writes get it; an
// existing trusted entry keeps its name, or lack of one.
const (
	codexShellHookName = "AgentShield: shell commands"
	codexMCPHookName   = "AgentShield: MCP tool calls"
)

// agentshieldCodexHookEntry builds the Codex PreToolUse hook entry with a Bash
// matcher. Codex's JSON shape matches Claude Code's, but Codex evaluates the
// matcher as a regex against tool_name — anchoring keeps us from matching
// hypothetical future tools like "BashOutput".
func agentshieldCodexHookEntry() map[string]interface{} {
	return agentshieldCodexHookGroup(codexShellMatcher, codexShellHookName)
}

// agentshieldCodexMCPHookEntry builds the entry that sends Codex MCP tool
// calls to the same `agentshield hook`, which routes every non-Bash tool to
// the MCP policy evaluator.
func agentshieldCodexMCPHookEntry() map[string]interface{} {
	return agentshieldCodexHookGroup(codexMCPMatcher, codexMCPHookName)
}

// codexHookCoverage reports which AgentShield groups hooks.json already has.
// Any AgentShield group whose matcher is not the MCP one counts as the shell
// group, as every such group did before the MCP group existed.
func codexHookCoverage(preToolUse []interface{}) (shell, mcp bool) {
	for _, entry := range preToolUse {
		if !isAgentShieldCodexHookEntry(entry) {
			continue
		}
		m, _ := entry.(map[string]interface{})
		if matcher, _ := m["matcher"].(string); matcher == codexMCPMatcher {
			mcp = true
		} else {
			shell = true
		}
	}
	return shell, mcp
}

// ensureCodexHookEntries appends whichever AgentShield groups are missing and
// never edits, removes or reorders a group that is already there. Codex keys
// hook trust by position (pre_tool_use:<group>:<handler>) and hashes the
// event, matcher and handler (codex-rs/hooks/src/engine/discovery.rs), so
// editing a shell group the user already trusted would stop it running until
// they reviewed it again. An appended group leaves that trust alone. The new
// group needs its own /hooks review, and until then MCP calls go unchecked, as
// they did before the group existed.
func ensureCodexHookEntries(preToolUse []interface{}) ([]interface{}, []string) {
	shell, mcp := codexHookCoverage(preToolUse)
	var added []string
	if !shell {
		preToolUse = append(preToolUse, agentshieldCodexHookEntry())
		added = append(added, "shell")
	}
	if !mcp {
		preToolUse = append(preToolUse, agentshieldCodexMCPHookEntry())
		added = append(added, "MCP")
	}
	return preToolUse, added
}

// codexHooksMissingMCP reports whether hooks.json has AgentShield's shell
// group but not its MCP group: an install from before the MCP group existed,
// which a re-run of `agentshield setup codex` upgrades.
func codexHooksMissingMCP(hooksPath string) bool {
	data, err := os.ReadFile(hooksPath)
	if err != nil {
		return false
	}
	var settings map[string]interface{}
	if json.Unmarshal(stripUTF8BOM(data), &settings) != nil {
		return false
	}
	hooks, _ := settings["hooks"].(map[string]interface{})
	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	shell, mcp := codexHookCoverage(preToolUse)
	return shell && !mcp
}

func agentshieldCodexHookGroup(matcher, name string) map[string]interface{} {
	binPath := resolveAgentShieldPath()
	return map[string]interface{}{
		"matcher": matcher,
		"hooks": []interface{}{
			map[string]interface{}{
				"type":          "command",
				"command":       binPath + " hook",
				"timeout":       10,
				"statusMessage": name,
			},
		},
	}
}

// isAgentShieldCodexHookEntry returns true if the hook entry routes to the
// agentshield binary. Codex entries include an optional "matcher" alongside
// "hooks" — the binary suffix is the durable signal.
func isAgentShieldCodexHookEntry(entry interface{}) bool {
	m, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	subHooks, _ := m["hooks"].([]interface{})
	for _, h := range subHooks {
		if hm, ok := h.(map[string]interface{}); ok {
			if cmd, ok := hm["command"].(string); ok && strings.HasSuffix(cmd, "agentshield hook") {
				return true
			}
		}
	}
	return false
}

func setupCodexCommand(cmd *cobra.Command, args []string) error {
	home, err := setupHome()
	if err != nil {
		return err
	}
	codexDir := filepath.Join(home, ".codex")
	hooksPath := filepath.Join(codexDir, "hooks.json")

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableCodexHook(hooksPath)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + OpenAI Codex CLI (PreToolUse Hook)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("⚠  agentshield not found in PATH. Install it first:")
		fmt.Println("   brew tap AI-AgentLens/oss && brew install agentshield")
		return nil
	}
	fmt.Printf("✅ agentshield found: %s\n", binPath)

	if err := os.MkdirAll(codexDir, 0755); err != nil {
		return fmt.Errorf("failed to create %s: %w", codexDir, err)
	}

	settings, err := readClaudeSettings(hooksPath)
	if err != nil {
		return err
	}

	hooks := getOrCreateMap(settings, "hooks")

	// Sweep out the legacy placeholder SessionStart entry that earlier versions
	// of this command wrote (just an echo, not a real guard). Leaving it in
	// place would print a stale "Session guard active" message that no longer
	// reflects what AgentShield does.
	if sessionStart, ok := hooks["SessionStart"].([]interface{}); ok {
		filtered := sessionStart[:0]
		for _, entry := range sessionStart {
			if isLegacyAgentShieldSessionStart(entry) {
				continue
			}
			filtered = append(filtered, entry)
		}
		if len(filtered) == 0 {
			delete(hooks, "SessionStart")
		} else {
			hooks["SessionStart"] = filtered
		}
	}

	preToolUse := getOrCreateSlice(hooks, "PreToolUse")
	updated, added := ensureCodexHookEntries(preToolUse)
	if len(added) == 0 {
		fmt.Printf("✅ Codex PreToolUse hooks already configured (shell + MCP): %s\n", hooksPath)
		fmt.Println()
		fmt.Println("If Codex still shows a \"hook needs review\" notice, approve them now:")
		fmt.Println("  1. Start Codex:  codex")
		fmt.Println("  2. Type:  /hooks")
		fmt.Println("  3. Select PreToolUse → highlight each AgentShield entry → press T (Trust)")
		fmt.Println()
		fmt.Println("To disable: agentshield setup codex --disable")
		fmt.Println()
		printStatus()
		return nil
	}

	hooks["PreToolUse"] = updated
	settings["hooks"] = hooks

	if err := writeClaudeSettings(hooksPath, settings); err != nil {
		return err
	}

	fmt.Printf("✅ PreToolUse hooks added (%s): %s\n", strings.Join(added, " + "), hooksPath)
	if len(added) == 1 && added[0] == "MCP" {
		fmt.Println("   Your existing shell hook is unchanged and keeps running.")
	}
	fmt.Println()
	fmt.Println("⚠  ONE MORE STEP — Codex runs a new hook only after you approve it.")
	fmt.Println("   Until you do, Codex shows a \"hook needs review\" notice and the")
	fmt.Println("   new hook does not run.")
	fmt.Println()
	fmt.Println("   To approve:")
	fmt.Println("     1. Start Codex:  codex")
	fmt.Println("     2. At the prompt, type:  /hooks")
	fmt.Println("     3. Select \"PreToolUse\" → highlight each AgentShield entry → press T (Trust)")
	fmt.Println("     4. Exit Codex. The next session routes shell commands and MCP tool")
	fmt.Println("        calls through AgentShield.")
	fmt.Println()
	fmt.Println("   Codex asks again for any entry whose command changes")
	fmt.Println("   (for example, an AgentShield upgrade that moves the binary).")
	fmt.Println()
	fmt.Println("How it works after approval:")
	fmt.Println("  1. Codex is about to run a shell command or call an MCP tool")
	fmt.Println("  2. The PreToolUse hook calls `agentshield hook`")
	fmt.Println("  3. A command flows through the analyzer pipeline; an MCP call through the MCP policy")
	fmt.Println("  4. If BLOCK (enforce mode): Codex prevents the call from running (exit 2)")
	fmt.Println("  5. If ALLOW/AUDIT: the call runs normally")
	fmt.Println()
	fmt.Println("To disable: agentshield setup codex --disable")
	fmt.Println()
	fmt.Println("After approving the hook via /hooks:")
	printTestHint("Codex")
	fmt.Println()
	printStatus()
	return nil
}

// isLegacyAgentShieldSessionStart matches the v0.x SessionStart placeholder
// that earlier versions of `agentshield setup codex` wrote when Codex didn't
// yet support PreToolUse. We strip it on upgrade so users don't keep seeing
// the old "Session guard active" message after they have a real guard.
func isLegacyAgentShieldSessionStart(entry interface{}) bool {
	m, ok := entry.(map[string]interface{})
	if !ok {
		return false
	}
	subHooks, _ := m["hooks"].([]interface{})
	for _, h := range subHooks {
		if hm, ok := h.(map[string]interface{}); ok {
			if cmd, ok := hm["command"].(string); ok && strings.Contains(cmd, "AgentShield") && strings.Contains(cmd, "Session guard active") {
				return true
			}
		}
	}
	return false
}

func disableCodexHook(hooksPath string) error {
	if _, err := os.Stat(hooksPath); os.IsNotExist(err) {
		fmt.Println("ℹ  No hooks.json found for Codex CLI — nothing to disable.")
		return nil
	}

	settings, err := readClaudeSettings(hooksPath)
	if err != nil {
		return err
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		fmt.Println("ℹ  Codex hooks.json has no hooks — nothing to disable.")
		return nil
	}

	removed := false

	preToolUse, _ := hooks["PreToolUse"].([]interface{})
	filteredPre := preToolUse[:0]
	for _, entry := range preToolUse {
		if isAgentShieldCodexHookEntry(entry) {
			removed = true
			continue
		}
		filteredPre = append(filteredPre, entry)
	}
	if len(filteredPre) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filteredPre
	}

	// Also strip the legacy SessionStart placeholder so a `--disable` from an
	// upgraded user leaves zero AgentShield residue in hooks.json.
	if sessionStart, ok := hooks["SessionStart"].([]interface{}); ok {
		filteredSS := sessionStart[:0]
		for _, entry := range sessionStart {
			if isLegacyAgentShieldSessionStart(entry) {
				removed = true
				continue
			}
			filteredSS = append(filteredSS, entry)
		}
		if len(filteredSS) == 0 {
			delete(hooks, "SessionStart")
		} else {
			hooks["SessionStart"] = filteredSS
		}
	}

	if !removed {
		fmt.Println("ℹ  AgentShield hook not found in Codex hooks.json — nothing to disable.")
		return nil
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
	}

	// If everything we'd persist is empty, remove the file outright with a
	// backup so the user is left with a clean home.
	if len(settings) == 0 {
		backupPath := hooksPath + ".bak"
		if err := os.Rename(hooksPath, backupPath); err != nil {
			return fmt.Errorf("failed to rename %s: %w", hooksPath, err)
		}
		fmt.Println("✅ AgentShield hook disabled for Codex CLI")
		fmt.Printf("   Backup saved: %s\n", backupPath)
		fmt.Println()
		fmt.Println("Re-enable anytime with: agentshield setup codex")
		return nil
	}

	if err := writeClaudeSettings(hooksPath, settings); err != nil {
		return err
	}

	fmt.Println("✅ AgentShield hook disabled for Codex CLI")
	fmt.Printf("   Settings: %s\n", hooksPath)
	fmt.Println()
	fmt.Println("Re-enable anytime with: agentshield setup codex")
	return nil
}

// ─── Generic Setup Instructions ─────────────────────────────────────────────

func printSetupInstructions() {
	// findWrapperSource walks multiple candidates (linuxbrew, /opt/homebrew,
	// /usr/local, binary-relative). Single-candidate getShareDir() depends on
	// HOMEBREW_PREFIX being set in the env, which isn't always true — e.g.
	// scripts that invoke `agentshield setup` without `eval $(brew shellenv)`
	// silently miss the linuxbrew-installed wrapper.
	wrapperPath := findWrapperSource()
	wrapperExists := wrapperPath != ""
	if wrapperPath == "" {
		// Fall back to default share path for the documented "shell override"
		// example below — even when uninstalled, show the canonical path users
		// should expect once they run `agentshield setup --install`.
		wrapperPath = filepath.Join(getShareDir(), "agentshield-wrapper.sh")
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield Setup Guide")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	if !wrapperExists {
		fmt.Println("⚠  Wrapper not installed. Run: agentshield setup --install")
		fmt.Println()
	}

	fmt.Println("─── Windsurf (Recommended) ───────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native Cascade Hooks — no shell changes needed.")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup windsurf")
	fmt.Println()

	fmt.Println("─── Cursor ───────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native Cursor Hooks (beforeShellExecution).")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup cursor")
	fmt.Println()

	fmt.Println("─── OpenClaw ──────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native OpenClaw Hooks (agent:bootstrap).")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup openclaw")
	fmt.Println()

	fmt.Println("─── Claude Code ───────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native PreToolUse hooks — no shell changes needed.")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup claude-code")
	fmt.Println()
	fmt.Println("  Or set the shell override in Claude Code settings:")
	fmt.Println()
	fmt.Printf("    \"shell\": \"%s\"\n", wrapperPath)
	fmt.Println()

	fmt.Println("─── Gemini CLI ────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native BeforeTool hooks — no shell changes needed.")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup gemini-cli")
	fmt.Println()

	fmt.Println("─── Codex CLI ─────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Uses native PreToolUse hooks — no shell changes needed.")
	fmt.Println("  One command to install:")
	fmt.Println()
	fmt.Println("    agentshield setup codex")
	fmt.Println()

	fmt.Println("─── Direct CLI Usage ─────────────────────────────────")
	fmt.Println()
	fmt.Println("  agentshield scan                     # self-test the policy engine")
	fmt.Println("  agentshield mcp-eval --tool <name> --arg k=v  # MCP policy check")
	fmt.Println("  agentshield hook                     # IDE PreToolUse hook handler")
	fmt.Println("  agentshield log                      # view audit trail")
	fmt.Println("  agentshield log --summary            # audit summary")
	fmt.Println("  agentshield pack list                # show policy packs")
	fmt.Println()
	fmt.Println("  (AgentShield is evaluation-only — there is no `run` subcommand.")
	fmt.Println("   Commands are evaluated by the IDE hook before the host executes them.)")
	fmt.Println()

	fmt.Println("─── MCP Servers ──────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Wraps MCP server configs to route tool calls through")
	fmt.Println("  AgentShield's MCP proxy for policy evaluation.")
	fmt.Println()
	fmt.Println("    agentshield setup mcp")
	fmt.Println()
	fmt.Println("  Or use the proxy directly:")
	fmt.Println("    agentshield mcp-proxy -- npx -y @modelcontextprotocol/server-filesystem /path")
	fmt.Println()

	fmt.Println("─── Pause / Resume ───────────────────────────────────")
	fmt.Println()
	fmt.Println("  agentshield pause              # pause shell enforcement")
	fmt.Println("  agentshield pause 30           # pause for 30 minutes")
	fmt.Println("  agentshield resume             # resume enforcement")
	fmt.Println()
	fmt.Println("  MCP rules remain active while paused.")
	fmt.Println("  In managed (enterprise) mode, pause is ignored.")
	fmt.Println()

	fmt.Println("─── Current Status ───────────────────────────────────")
	fmt.Println()
	printStatus()
}

func printStatus() {
	cfg, _ := config.Load("", "", "")

	// Check binary
	binPath, err := exec.LookPath("agentshield")
	if err != nil {
		fmt.Println("  Binary:  ⚠  not found in PATH")
	} else {
		fmt.Printf("  Binary:  ✅ %s\n", binPath)
	}

	// Check wrapper. findWrapperSource walks multiple candidates (linuxbrew,
	// /opt/homebrew, /usr/local, binary-relative) so this works even when
	// HOMEBREW_PREFIX isn't set in the calling shell — which is the common
	// case for scripts that don't run `eval $(brew shellenv)` first.
	if wrapperPath := findWrapperSource(); wrapperPath != "" {
		fmt.Printf("  Wrapper: ✅ %s\n", wrapperPath)
	} else {
		fmt.Println("  Wrapper: ⚠  not installed")
	}

	// Check packs
	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		entries, err := os.ReadDir(packsDir)
		if err == nil {
			count := 0
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") && !strings.HasPrefix(e.Name(), "_") {
					count++
				}
			}
			fmt.Printf("  Packs:   ✅ %d enabled in %s\n", count, packsDir)
		} else {
			fmt.Printf("  Packs:   ⚠  %s not found\n", packsDir)
		}

		// Check policy
		if _, err := os.Stat(cfg.PolicyPath); err == nil {
			fmt.Printf("  Policy:  ✅ %s\n", cfg.PolicyPath)
		} else {
			fmt.Println("  Policy:  ℹ  using built-in defaults")
		}
	}

	fmt.Printf("  Mode:    %s\n", modeSummary(cfg))
	fmt.Println()
}

// getShareDir returns the platform-appropriate share directory for AgentShield.
func getShareDir() string {
	// Check if installed via Homebrew
	brewPrefix := os.Getenv("HOMEBREW_PREFIX")
	if brewPrefix == "" {
		if runtime.GOARCH == "arm64" && runtime.GOOS == "darwin" {
			brewPrefix = "/opt/homebrew"
		} else {
			brewPrefix = "/usr/local"
		}
	}
	return filepath.Join(brewPrefix, "share", "agentshield")
}

// findWrapperSource looks for the wrapper script in known locations.
func findWrapperSource() string {
	candidates := []string{
		filepath.Join(getShareDir(), "agentshield-wrapper.sh"),
	}

	// Check relative to binary
	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		candidates = append(candidates,
			filepath.Join(binDir, "..", "share", "agentshield", "agentshield-wrapper.sh"),
			filepath.Join(binDir, "..", "scripts", "agentshield-wrapper.sh"),
		)
	}

	// Check current working directory (for dev)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, "scripts", "agentshield-wrapper.sh"))
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// findPacksSource looks for bundled policy packs in known locations.
// Prefers packs/community/ subdirectory (new layout), falls back to packs/ (legacy).
func findPacksSource() string {
	baseCandidates := []string{
		filepath.Join(getShareDir(), "packs"),
	}

	if binPath, err := exec.LookPath("agentshield"); err == nil {
		binDir := filepath.Dir(binPath)
		baseCandidates = append(baseCandidates,
			filepath.Join(binDir, "..", "share", "agentshield", "packs"),
			filepath.Join(binDir, "..", "packs"),
		)
	}

	if cwd, err := os.Getwd(); err == nil {
		baseCandidates = append(baseCandidates, filepath.Join(cwd, "packs"))
	}

	// Prefer community/ subdirectory (new layout), fall back to base (legacy)
	for _, c := range baseCandidates {
		community := filepath.Join(c, "community")
		if info, err := os.Stat(community); err == nil && info.IsDir() {
			return community
		}
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}
	return ""
}

// installPacks copies pack files from src to dst, skipping files that already exist.
func installPacks(srcDir, dstDir string) int {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return 0
	}

	installed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		dstPath := filepath.Join(dstDir, e.Name())
		if _, err := os.Stat(dstPath); err == nil {
			continue // already exists
		}
		data, err := os.ReadFile(filepath.Join(srcDir, e.Name()))
		if err != nil {
			continue
		}
		if err := os.WriteFile(dstPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "⚠  Failed to install pack %s: %v\n", e.Name(), err)
			continue
		}
		installed++
	}
	return installed
}

// test comment
