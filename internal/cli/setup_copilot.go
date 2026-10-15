package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/spf13/cobra"
)

// GitHub Copilot CLI integration (#4251).
//
// Copilot CLI loads every *.json file in its user hooks directory
// ($COPILOT_HOME/hooks, ~/.copilot/hooks by default) for every session, so
// AgentShield owns one file there rather than editing a shared settings file:
// enabling writes it, disabling removes it, and nothing else in the directory
// is touched. User-level hooks need no per-folder trust; repository hooks
// (.github/hooks) do.
//
// The entry uses the Claude-compatible dialect ("PreToolUse", PascalCase),
// whose payloads go through the same handler as Claude Code's, and sets
// AGENTSHIELD_AGENT_ID so receipts name Copilot rather than Claude Code — the
// payload alone cannot tell them apart. The hook also accepts the native
// "preToolUse" dialect for anyone who writes their own entry.

var setupCopilotCLICmd = &cobra.Command{
	Use:   "copilot-cli",
	Short: "Set up AgentShield for GitHub Copilot CLI (PreToolUse hook)",
	Long: `Install or remove a user-level PreToolUse hook so every tool call GitHub
Copilot CLI makes is evaluated by AgentShield before it runs.

The hook is one file, $COPILOT_HOME/hooks/agentshield.json
(~/.copilot/hooks/agentshield.json by default), loaded by every session.

  agentshield setup copilot-cli             # enable hook
  agentshield setup copilot-cli --disable   # disable hook`,
	RunE: setupCopilotCLICommand,
}

func init() {
	setupCopilotCLICmd.Flags().BoolVar(&disableFlag, "disable", false, "Remove AgentShield hooks and disable integration")
	setupCmd.AddCommand(setupCopilotCLICmd)
}

// copilotHome mirrors Copilot CLI's own resolution: COPILOT_HOME, else
// $HOME/.copilot.
func copilotHome() string {
	if h := os.Getenv("COPILOT_HOME"); h != "" {
		return h
	}
	return filepath.Join(os.Getenv("HOME"), ".copilot")
}

func copilotHookFilePath() string {
	return filepath.Join(copilotHome(), "hooks", "agentshield.json")
}

// copilotHookFile is the content AgentShield owns. timeoutSec stays at
// Copilot's 30s default: a timeout is the one hook failure Copilot treats as
// fail-open, and the hook decides in well under a second.
func copilotHookFile(binPath string) map[string]interface{} {
	return map[string]interface{}{
		"version": 1,
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"type":       "command",
					"bash":       binPath + " hook",
					"env":        map[string]interface{}{"AGENTSHIELD_AGENT_ID": "copilot-cli"},
					"timeoutSec": 30,
				},
			},
		},
	}
}

// isAgentShieldCopilotHookFile reports whether the file at path is one this
// command wrote: a PreToolUse entry that runs `<binary> hook` and carries the
// AGENTSHIELD_AGENT_ID=copilot-cli marker setup writes, or one whose bash
// command is literally `agentshield hook`. The marker is what makes ownership
// independent of where the binary lives (a dev build, a test binary). A file
// we cannot parse, or one routing elsewhere, is not ours and is never
// overwritten or removed.
func isAgentShieldCopilotHookFile(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	var doc struct {
		Hooks map[string][]map[string]interface{} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return false, nil
	}
	for _, entry := range doc.Hooks["PreToolUse"] {
		cmd, _ := entry["bash"].(string)
		if strings.HasSuffix(cmd, "agentshield hook") {
			return true, nil
		}
		env, _ := entry["env"].(map[string]interface{})
		if strings.HasSuffix(cmd, " hook") && env["AGENTSHIELD_AGENT_ID"] == "copilot-cli" {
			return true, nil
		}
	}
	return false, nil
}

func setupCopilotCLICommand(cmd *cobra.Command, args []string) error {
	path := copilotHookFilePath()

	if disableFlag {
		if err := enterprise.CheckDisableAllowed(); err != nil {
			return err
		}
		return disableCopilotCLIHook(path)
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  AgentShield + GitHub Copilot CLI (PreToolUse Hook)")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println()

	binPath := resolveAgentShieldPath()
	want, err := json.MarshalIndent(copilotHookFile(binPath), "", "  ")
	if err != nil {
		return err
	}
	want = append(want, '\n')

	switch existing, err := os.ReadFile(path); {
	case err == nil && string(existing) == string(want):
		fmt.Printf("✅ Copilot CLI hook already configured: %s\n", path)
		fmt.Println()
		fmt.Println("To disable: agentshield setup copilot-cli --disable")
		return nil
	case err == nil:
		ours, _ := isAgentShieldCopilotHookFile(path)
		if !ours {
			return fmt.Errorf("%s exists and was not written by AgentShield; move it aside and re-run", path)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("reading %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, want, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}

	fmt.Printf("✅ PreToolUse hook installed: %s\n", path)
	fmt.Println()
	fmt.Println("How it works:")
	fmt.Println("  1. Copilot CLI is about to run a tool (shell, file read/edit, MCP, …)")
	fmt.Println("  2. The PreToolUse hook calls `agentshield hook`")
	fmt.Println("  3. Shell commands go through the analyzer pipeline; other tools through MCP policy")
	fmt.Println("  4. If BLOCK (enforce mode): Copilot denies the call and shows the agent the reason")
	fmt.Println("  5. If ALLOW/AUDIT: the tool runs normally")
	fmt.Println()
	fmt.Println("Applies to new Copilot CLI sessions. To disable: agentshield setup copilot-cli --disable")
	fmt.Println()
	printStatus()
	return nil
}

func disableCopilotCLIHook(path string) error {
	ours, err := isAgentShieldCopilotHookFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		fmt.Println("Copilot CLI hook not installed — nothing to remove.")
		return nil
	case err != nil:
		return fmt.Errorf("reading %s: %w", path, err)
	case !ours:
		return fmt.Errorf("%s was not written by AgentShield; leaving it in place", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("removing %s: %w", path, err)
	}
	fmt.Printf("✅ Copilot CLI hook removed: %s\n", path)
	fmt.Println("Re-enable anytime with: agentshield setup copilot-cli")
	return nil
}
