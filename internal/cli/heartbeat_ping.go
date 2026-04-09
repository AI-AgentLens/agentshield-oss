package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
)

const heartbeatCooldown = 10 * time.Minute

// sendOpportunisticHeartbeat sends a heartbeat if credentials exist and enough
// time has passed since the last one. Also restarts the daemon if it's dead.
func sendOpportunisticHeartbeat() {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}

	// Restart daemon if it died (brew update, reboot, etc.)
	if !isHeartbeatRunning() {
		_ = startHeartbeatDaemon()
	}

	// Check cooldown — don't send more than once per 10 minutes
	home, _ := os.UserHomeDir()
	stampFile := filepath.Join(home, ".agentshield", "last_heartbeat")
	if info, err := os.Stat(stampFile); err == nil {
		if time.Since(info.ModTime()) < heartbeatCooldown {
			return
		}
	}

	// Send heartbeat
	hostname := stableHostname()
	payload, _ := json.Marshal(map[string]any{
		"hostname":      hostname,
		"machine_id":    enterprise.MachineID(),
		"os":            runtime.GOOS,
		"arch":          runtime.GOARCH,
		"agent_version": Version,
		"mode":          "standalone",
	})

	req, err := http.NewRequest("POST", creds.Server+"/api/heartbeat", bytes.NewReader(payload))
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

	// Update stamp file
	_ = os.MkdirAll(filepath.Dir(stampFile), 0700)
	_ = os.WriteFile(stampFile, []byte(time.Now().UTC().Format(time.RFC3339)), 0600)
}
