package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/config"
	"github.com/spf13/cobra"
)

// pauseState is written to ~/.agentshield/paused.json
type pauseState struct {
	Paused    bool      `json:"paused"`
	PausedAt  time.Time `json:"paused_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"` // zero = indefinite
	Reason    string    `json:"reason,omitempty"`
}

var pauseCmd = &cobra.Command{
	Use:   "pause [duration-minutes]",
	Short: "Temporarily pause all shell rule enforcement",
	Long: `Pause AgentShield shell rule enforcement temporarily or indefinitely.

All hook evaluations will pass through (allow) while paused.
MCP rules are NOT affected — only shell/Bash command hooks.
Managed/enterprise mode ignores pause.

Examples:
  agentshield pause          # Pause indefinitely (until resume)
  agentshield pause 30       # Pause for 30 minutes
  agentshield pause 60       # Pause for 1 hour
  agentshield resume         # Resume enforcement`,
	Args: cobra.MaximumNArgs(1),
	RunE: pauseCommand,
}

var resumeCmd = &cobra.Command{
	Use:   "resume",
	Short: "Resume shell rule enforcement after a pause",
	RunE:  resumeCommand,
}

func init() {
	rootCmd.AddCommand(pauseCmd)
	rootCmd.AddCommand(resumeCmd)
}

func pauseFilePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, config.DefaultConfigDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "paused.json"), nil
}

func pauseCommand(cmd *cobra.Command, args []string) error {
	fp, err := pauseFilePath()
	if err != nil {
		return fmt.Errorf("failed to resolve config dir: %w", err)
	}

	state := pauseState{
		Paused:   true,
		PausedAt: time.Now(),
	}

	if len(args) > 0 {
		minutes, err := strconv.Atoi(args[0])
		if err != nil || minutes <= 0 {
			return fmt.Errorf("duration must be a positive number of minutes, got %q", args[0])
		}
		state.ExpiresAt = time.Now().Add(time.Duration(minutes) * time.Minute)
		state.Reason = fmt.Sprintf("Paused for %d minutes", minutes)
	} else {
		state.Reason = "Paused indefinitely (run 'agentshield resume' to re-enable)"
	}

	data, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(fp, data, 0600); err != nil {
		return fmt.Errorf("failed to write pause state: %w", err)
	}

	fmt.Println("⏸️  AgentShield shell enforcement PAUSED")
	if !state.ExpiresAt.IsZero() {
		fmt.Printf("   Expires: %s (%s from now)\n", state.ExpiresAt.Format("15:04:05"), time.Until(state.ExpiresAt).Round(time.Second))
	} else {
		fmt.Println("   Duration: indefinite — run 'agentshield resume' to re-enable")
	}
	fmt.Println("   MCP rules remain active")
	return nil
}

func resumeCommand(cmd *cobra.Command, args []string) error {
	fp, err := pauseFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(fp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove pause file: %w", err)
	}
	fmt.Println("▶️  AgentShield shell enforcement RESUMED")
	return nil
}

// IsPaused checks if AgentShield is currently paused.
// Called by hookCommand before evaluating shell rules.
func IsPaused() bool {
	fp, err := pauseFilePath()
	if err != nil {
		return false
	}
	data, err := os.ReadFile(fp)
	if err != nil {
		return false // no file = not paused
	}
	var state pauseState
	if err := json.Unmarshal(data, &state); err != nil {
		return false
	}
	if !state.Paused {
		return false
	}
	// Check expiry
	if !state.ExpiresAt.IsZero() && time.Now().After(state.ExpiresAt) {
		// Expired — auto-resume by removing file
		_ = os.Remove(fp)
		return false
	}
	return true
}
