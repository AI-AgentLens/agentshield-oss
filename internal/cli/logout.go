package cli

import (
	"fmt"

	"github.com/security-researcher-ca/agentshield/internal/auth"
	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove stored AI Agent Lens credentials",
	Long: `Log out from AI Agent Lens by removing the stored credentials.
The agent will no longer send heartbeats or appear in your dashboard.

  agentshield logout`,
	RunE: logoutCommand,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func logoutCommand(cmd *cobra.Command, args []string) error {
	creds, _ := auth.Load()
	if creds == nil {
		fmt.Println("Not logged in.")
		return nil
	}

	// Stop heartbeat daemon
	stopHeartbeatDaemon()

	if err := auth.Remove(); err != nil {
		return fmt.Errorf("failed to remove credentials: %w", err)
	}

	fmt.Printf("Logged out. Heartbeat stopped, credentials removed.\n")
	return nil
}
