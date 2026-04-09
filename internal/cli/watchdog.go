package cli

import (
	"fmt"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/spf13/cobra"
)

var watchdogCmd = &cobra.Command{
	Use:   "watchdog",
	Short: "Run background tamper detection (enterprise)",
	Long: `Start a background watchdog that continuously monitors AgentShield's
integrity: hook files, policy configuration, managed.json, and environment.

Requires managed mode (managed.json with "managed": true).

  agentshield watchdog`,
	RunE: watchdogCommand,
}

func init() {
	rootCmd.AddCommand(watchdogCmd)
}

func watchdogCommand(cmd *cobra.Command, args []string) error {
	managedCfg := enterprise.LoadManagedConfig()
	if managedCfg == nil || !managedCfg.Managed {
		return fmt.Errorf("watchdog requires managed mode — create ~/.agentshield/managed.json with {\"managed\": true}")
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}

	// RunWatchdog blocks forever
	enterprise.RunWatchdog(managedCfg, cfg.ConfigDir)
	return nil
}
