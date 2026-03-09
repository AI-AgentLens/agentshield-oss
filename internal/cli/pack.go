package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/policy"
	"github.com/spf13/cobra"
)

var packCmd = &cobra.Command{
	Use:   "pack",
	Short: "Manage policy packs",
	Long: `Manage AgentShield policy packs.

Policy packs are curated YAML policy files that target specific threat domains.
Packs are stored in ~/.agentshield/packs/ and merged with your base policy at runtime.

Examples:
  agentshield pack list                  # List installed packs
  agentshield pack enable terminal-safety  # Enable a pack
  agentshield pack disable supply-chain    # Disable a pack
  agentshield pack show terminal-safety    # Show pack details`,
}

var packListCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed policy packs",
	RunE:  packList,
}

var packEnableCmd = &cobra.Command{
	Use:   "enable <pack-name>",
	Short: "Enable a disabled policy pack",
	Args:  cobra.ExactArgs(1),
	RunE:  packEnable,
}

var packDisableCmd = &cobra.Command{
	Use:   "disable <pack-name>",
	Short: "Disable a policy pack (prefix with underscore)",
	Args:  cobra.ExactArgs(1),
	RunE:  packDisable,
}

var packShowCmd = &cobra.Command{
	Use:   "show <pack-name>",
	Short: "Show details of a policy pack",
	Args:  cobra.ExactArgs(1),
	RunE:  packShow,
}

func init() {
	packCmd.AddCommand(packListCmd)
	packCmd.AddCommand(packEnableCmd)
	packCmd.AddCommand(packDisableCmd)
	packCmd.AddCommand(packShowCmd)
	rootCmd.AddCommand(packCmd)
}

func packsDir() (string, error) {
	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cfg.ConfigDir, "packs")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func packList(cmd *cobra.Command, args []string) error {
	dir, err := packsDir()
	if err != nil {
		return err
	}

	base := policy.DefaultPolicy()
	_, infos, err := policy.LoadPacks(dir, base)
	if err != nil {
		return fmt.Errorf("failed to load packs: %w", err)
	}

	if len(infos) == 0 {
		fmt.Println("No policy packs installed.")
		fmt.Printf("\nTo install packs, copy YAML files to: %s\n", dir)
		fmt.Println("Available packs are in the packs/ directory of the AgentShield repo.")
		return nil
	}

	fmt.Println("Installed Policy Packs:")
	fmt.Println(strings.Repeat("─", 60))
	for _, info := range infos {
		status := "\xe2\x9c\x85" // check mark
		if !info.Enabled {
			status = "\xe2\x9d\x8c" // cross mark
		}
		fmt.Printf("  %s  %-25s %s\n", status, info.Name, info.Description)
		if info.Version != "" {
			fmt.Printf("       v%s by %s  (%d rules)\n", info.Version, info.Author, info.RuleCount)
		}
	}
	fmt.Println(strings.Repeat("─", 60))
	fmt.Printf("\nPacks directory: %s\n", dir)
	return nil
}

func packEnable(cmd *cobra.Command, args []string) error {
	dir, err := packsDir()
	if err != nil {
		return err
	}

	name := args[0]
	disabledPath := filepath.Join(dir, "_"+name+".yaml")
	enabledPath := filepath.Join(dir, name+".yaml")

	if _, err := os.Stat(disabledPath); err == nil {
		if err := os.Rename(disabledPath, enabledPath); err != nil {
			return fmt.Errorf("failed to enable pack: %w", err)
		}
		fmt.Printf("\xe2\x9c\x85 Pack '%s' enabled.\n", name)
		return nil
	}

	if _, err := os.Stat(enabledPath); err == nil {
		fmt.Printf("Pack '%s' is already enabled.\n", name)
		return nil
	}

	return fmt.Errorf("pack '%s' not found in %s", name, dir)
}

func packDisable(cmd *cobra.Command, args []string) error {
	dir, err := packsDir()
	if err != nil {
		return err
	}

	name := args[0]
	enabledPath := filepath.Join(dir, name+".yaml")
	disabledPath := filepath.Join(dir, "_"+name+".yaml")

	if _, err := os.Stat(enabledPath); err == nil {
		if err := os.Rename(enabledPath, disabledPath); err != nil {
			return fmt.Errorf("failed to disable pack: %w", err)
		}
		fmt.Printf("\xe2\x9d\x8c Pack '%s' disabled.\n", name)
		return nil
	}

	if _, err := os.Stat(disabledPath); err == nil {
		fmt.Printf("Pack '%s' is already disabled.\n", name)
		return nil
	}

	return fmt.Errorf("pack '%s' not found in %s", name, dir)
}

func packShow(cmd *cobra.Command, args []string) error {
	dir, err := packsDir()
	if err != nil {
		return err
	}

	name := args[0]

	// Try enabled, then disabled
	path := filepath.Join(dir, name+".yaml")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join(dir, "_"+name+".yaml")
		if _, err := os.Stat(path); err != nil {
			return fmt.Errorf("pack '%s' not found in %s", name, dir)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	fmt.Println(string(data))
	return nil
}
