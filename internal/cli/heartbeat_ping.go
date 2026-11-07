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
	"github.com/AI-AgentLens/agentshield/internal/homedir"
)

const heartbeatCooldown = 10 * time.Minute

// The hook restarts a dead heartbeat daemon only for the account's own home.
//
// A launchd job is registered in the user's session, not in a HOME. Before this
// guard, a hook run with HOME pointed elsewhere (a scratch or test HOME holding
// credentials) installed a job labelled for that HOME (#4476) that ran the
// installed binary with the account's environment, so it ran against the real
// ~/.agentshield, and it outlived the scratch directory. On 2026-11-03, test
// runs on a developer Mac left 512 of them, each a KeepAlive `agentshield
// connect` (load average above 800). `agentshield login` still starts the
// daemon explicitly, for whatever HOME it runs with.
var (
	// daemonAutoStartDisabled is set by this package's TestMain, so no test,
	// and no child a test re-execs, ever installs a real daemon.
	daemonAutoStartDisabled bool
	heartbeatRunning        = isHeartbeatRunning
	heartbeatStart          = startHeartbeatDaemon
)

// mayAutoStartHeartbeatDaemon reports whether the hook may restart the
// daemon: never in tests, and only when $HOME is the account's home in the
// user database. An unknown account home means no auto-start; it is a
// convenience, not a protection.
func mayAutoStartHeartbeatDaemon() bool {
	if daemonAutoStartDisabled {
		return false
	}
	home, err := homedir.Dir()
	if err != nil {
		return false
	}
	account, err := homedir.Account()
	if err != nil {
		return false
	}
	return filepath.Clean(home) == filepath.Clean(account)
}

// sendOpportunisticHeartbeat sends a heartbeat if credentials exist and enough
// time has passed since the last one. Also restarts the daemon if it's dead.
func sendOpportunisticHeartbeat() {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}

	// Restart daemon if it died (brew update, reboot, etc.)
	if mayAutoStartHeartbeatDaemon() && !heartbeatRunning() {
		_ = heartbeatStart()
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
		"machine_id":    refreshingMachineID(enterprise.MachineID),
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
