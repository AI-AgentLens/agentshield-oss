package cli

import (
	"fmt"

	"github.com/security-researcher-ca/agentshield/internal/auth"
	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/security-researcher-ca/agentshield/internal/enterprise"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to AI Agent Lens for heartbeat, policy sync, and watchdog",
	Long: `Start the managed agent daemon that:
  - Sends heartbeat telemetry to AI Agent Lens (CPU, memory, rules, commands)
  - Syncs policy updates from the server
  - Runs watchdog tamper detection checks

Requires managed mode (managed.json with heartbeat and/or policy_sync configured).

  agentshield connect`,
	RunE: connectCommand,
}

func init() {
	rootCmd.AddCommand(connectCmd)
}

func connectCommand(cmd *cobra.Command, args []string) error {
	managedCfg := enterprise.LoadManagedConfig()

	// If no managed.json, fall back to login credentials for heartbeat
	if managedCfg == nil || !managedCfg.Managed {
		creds, _ := auth.Load()
		if creds != nil && creds.Token != "" {
			managedCfg = &enterprise.ManagedConfig{
				Managed: true,
				Heartbeat: &enterprise.HeartbeatConf{
					URL:   creds.Server + "/api/heartbeat",
					Token: creds.Token,
				},
			}
			_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[AgentShield] connect: using login credentials for %s\n", creds.User.Email)
		} else {
			return fmt.Errorf("connect requires either managed mode (managed.json) or login credentials — run 'agentshield login' first")
		}
	}

	cfg, err := config.Load(policyPath, logPath, mode)
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}

	hasHeartbeat := managedCfg.Heartbeat != nil && managedCfg.Heartbeat.URL != ""
	hasPolicySync := managedCfg.PolicySync != nil && managedCfg.PolicySync.URL != ""
	hasWatchdog := managedCfg.Watchdog != nil

	if !hasHeartbeat && !hasPolicySync && !hasWatchdog {
		return fmt.Errorf("no heartbeat, policy_sync, or watchdog configured in managed.json")
	}

	// Pass version to enterprise package to avoid import cycle
	enterprise.AgentVersion = Version

	_, _ = fmt.Fprintf(cmd.OutOrStderr(), "[AgentShield] connect: starting managed agent daemon\n")

	// Launch heartbeat in background goroutine
	if hasHeartbeat {
		go enterprise.RunHeartbeat(managedCfg.Heartbeat, cfg.ConfigDir)
	}

	// Launch policy sync in background goroutine
	if hasPolicySync {
		go enterprise.RunPolicySync(managedCfg.PolicySync, cfg.ConfigDir)
	}

	// Run watchdog in foreground (blocks forever)
	if hasWatchdog {
		enterprise.RunWatchdog(managedCfg, cfg.ConfigDir)
	} else {
		// Block forever if only heartbeat/policy sync
		select {}
	}

	return nil
}
