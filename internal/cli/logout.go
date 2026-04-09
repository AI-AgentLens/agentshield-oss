package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
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

func deleteAgentFromSaaS(creds *auth.Credentials) {
	if creds == nil || creds.Token == "" {
		return
	}
	payload, _ := json.Marshal(map[string]string{
		"hostname":   enterprise.StableHostname(),
		"machine_id": enterprise.MachineID(),
	})
	req, err := http.NewRequest("DELETE", creds.Server+"/api/agents/self", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

func logoutCommand(cmd *cobra.Command, args []string) error {
	creds, _ := auth.Load()
	if creds == nil {
		fmt.Println("Not logged in.")
		return nil
	}

	// Stop heartbeat daemon
	stopHeartbeatDaemon()

	// Delete agent from SaaS
	deleteAgentFromSaaS(creds)

	if err := auth.Remove(); err != nil {
		return fmt.Errorf("failed to remove credentials: %w", err)
	}

	fmt.Printf("Logged out. Agent removed from dashboard, credentials deleted.\n")
	return nil
}
