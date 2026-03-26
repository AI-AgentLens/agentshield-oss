package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/auth"
	"github.com/spf13/cobra"
)

var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Send a heartbeat and verify connection to AI Agent Lens",
	Long: `Sends a heartbeat to the AI Agent Lens server and prints the response.
Useful for verifying connectivity and forcing an immediate status update.

  agentshield ping`,
	RunE: pingCommand,
}

func init() {
	rootCmd.AddCommand(pingCmd)
}

func pingCommand(cmd *cobra.Command, args []string) error {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return fmt.Errorf("not logged in — run 'agentshield login' first")
	}

	hostname, _ := os.Hostname()
	payload, _ := json.Marshal(map[string]any{
		"hostname":      hostname,
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"agent_version": Version,
		"mode":          "standalone",
	})

	req, err := http.NewRequest("POST", creds.Server+"/api/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	start := time.Now()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ping failed: %w", err)
	}
	defer resp.Body.Close()
	latency := time.Since(start)

	if resp.StatusCode == 200 {
		fmt.Printf("pong from %s (%dms)\n", creds.Server, latency.Milliseconds())
		fmt.Printf("  agent: %s (%s/%s)\n", hostname, runtime.GOOS, runtime.GOARCH)
		fmt.Printf("  user:  %s\n", creds.User.Email)
	} else {
		fmt.Printf("ping failed: server returned %d (%dms)\n", resp.StatusCode, latency.Milliseconds())
	}

	return nil
}
