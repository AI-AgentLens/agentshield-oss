package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
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
	_, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(base)
	_, diskInfos, err := policy.LoadPacks(dir, base)
	if err != nil {
		return fmt.Errorf("failed to load packs: %w", err)
	}

	// The MCP surface, through the same loader the proxy and mcp-eval use, so
	// the listing shows what is enforced rather than what is on disk.
	mcpLoaded := loadDeployedMCPPolicy("")

	return renderPackList(cmd.OutOrStdout(), dir, embeddedInfos, diskInfos, mcpLoaded)
}

// renderPackList writes the `pack list` report: shell packs (embedded, then
// on-disk) and MCP packs (embedded, on-disk, legacy). It is the testable seam;
// packList only gathers the inputs.
//
// A community shell pack that is BOTH embedded and on disk is listed twice,
// deliberately, with a label. Hiding the disk copy would misdescribe the
// engine: LoadPacks has no exclude-by-name (unlike the MCP loader, #1628), so
// the disk copy's rules are appended and every one of its matches fires twice
// (the combiner collapses only identical id+reason pairs). The honest listing
// is the one that shows both and says so; the fix is to delete the disk copy,
// which the label tells the reader.
func renderPackList(w io.Writer, dir string, embeddedShell, diskShell []policy.PackInfo, mcpLoaded *loadedMCPPolicy) error {
	var mcpEmbedded, mcpDisk, mcpLegacy []mcp.MCPPackInfo
	mcpPacksDir, mcpLegacyDir := "", ""
	if mcpLoaded != nil {
		mcpEmbedded, mcpDisk, mcpLegacy = mcpLoaded.Embedded, mcpLoaded.Disk, mcpLoaded.LegacyDisk
		mcpPacksDir, mcpLegacyDir = mcpLoaded.PacksDir, mcpLoaded.LegacyDir
	}

	if len(embeddedShell) == 0 && len(diskShell) == 0 && len(mcpEmbedded) == 0 && len(mcpDisk) == 0 && len(mcpLegacy) == 0 {
		fmt.Fprintln(w, "No policy packs available.")
		fmt.Fprintf(w, "\nTo install extra packs, copy YAML files to: %s\n", dir)
		return nil
	}

	embeddedNames := map[string]bool{}
	for _, info := range embeddedShell {
		embeddedNames[info.Name] = true
	}

	printInfos := func(header string, infos []policy.PackInfo, alsoEmbedded map[string]bool) {
		if len(infos) == 0 {
			return
		}
		fmt.Fprintln(w, header)
		fmt.Fprintln(w, strings.Repeat("─", 60))
		for _, info := range infos {
			if info.LoadError != nil {
				// Issue #2188: a pack that failed to parse contributed 0 rules.
				// Show it as failed rather than omitting it (which would imply
				// it never existed).
				fmt.Fprintf(w, "  \xe2\x9d\x8c  %-25s FAILED to parse — 0 rules loaded\n", info.Name)
				fmt.Fprintf(w, "       %s: %v\n", info.Path, info.LoadError)
				continue
			}
			status := "\xe2\x9c\x85" // check mark
			if !info.Enabled {
				status = "\xe2\x9d\x8c" // cross mark
			}
			fmt.Fprintf(w, "  %s  %-25s %s\n", status, info.Name, info.Description)
			if info.Version != "" {
				fmt.Fprintf(w, "       v%s by %s  (%d rules)\n", info.Version, info.Author, info.RuleCount)
			}
			if alsoEmbedded[info.Name] && info.Enabled {
				fmt.Fprintf(w, "       \xe2\x9a\xa0 also embedded in the binary — this disk copy is loaded a second time,\n")
				fmt.Fprintf(w, "       so its rules fire twice; delete it unless it is a deliberate override\n")
			}
		}
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	printMCP := func(header string, infos []mcp.MCPPackInfo) {
		if len(infos) == 0 {
			return
		}
		fmt.Fprintln(w, header)
		fmt.Fprintln(w, strings.Repeat("─", 60))
		for _, info := range infos {
			if info.LoadError != nil {
				fmt.Fprintf(w, "  \xe2\x9d\x8c  %-25s FAILED to parse — 0 rules loaded\n", info.Name)
				fmt.Fprintf(w, "       %s: %v\n", info.Path, info.LoadError)
				continue
			}
			status := "\xe2\x9c\x85"
			if !info.Enabled {
				status = "\xe2\x9d\x8c"
			}
			version := ""
			if info.Version != "" {
				version = " v" + info.Version
			}
			fmt.Fprintf(w, "  %s  %-25s%s  (%d rules)\n", status, info.Name, version, info.RuleCount)
		}
		fmt.Fprintln(w, strings.Repeat("─", 60))
	}

	printInfos("Built-in (embedded) Policy Packs:", embeddedShell, nil)
	if len(embeddedShell) > 0 && len(diskShell) > 0 {
		fmt.Fprintln(w)
	}
	printInfos("Installed (on-disk) Policy Packs:", diskShell, embeddedNames)
	fmt.Fprintf(w, "\nPacks directory: %s\n", dir)

	fmt.Fprintln(w)
	printMCP("Built-in (embedded) MCP Packs:", mcpEmbedded)
	if len(mcpEmbedded) > 0 && (len(mcpDisk) > 0 || len(mcpLegacy) > 0) {
		fmt.Fprintln(w)
	}
	printMCP("Installed (on-disk) MCP Packs:", mcpDisk)
	if len(mcpLegacy) > 0 {
		fmt.Fprintln(w)
		printMCP(fmt.Sprintf("Legacy (on-disk) MCP Packs — %s, loaded only because %s is empty:", mcpLegacyDir, mcpPacksDir), mcpLegacy)
	}
	if mcpPacksDir != "" {
		fmt.Fprintf(w, "\nMCP packs directory: %s\n", mcpPacksDir)
	}
	fmt.Fprintln(w, "\nRule counts are id-bearing rule entries per pack (rules, structural_rules, value_limits,")
	fmt.Fprintln(w, "resource_rules, semantic_rules); blocked_tools are enforced but are not rules. See COVERAGE.md.")
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
