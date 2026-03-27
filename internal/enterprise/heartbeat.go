package enterprise

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"
)

// heartbeatPayload matches the server's heartbeat.Heartbeat struct.
type heartbeatPayload struct {
	Hostname        string   `json:"hostname"`
	MachineID       string   `json:"machine_id,omitempty"`
	OS              string   `json:"os"`
	Arch            string   `json:"arch"`
	AgentVersion    string   `json:"agent_version"`
	Mode            string   `json:"mode"`
	CPUPercent      float64  `json:"cpu_percent"`
	MemoryMB        int      `json:"memory_mb"`
	RulesLoaded     int      `json:"rules_loaded"`
	CommandsAudited int      `json:"commands_audited"`
	CommandsBlocked int      `json:"commands_blocked"`
	UptimeSeconds   int      `json:"uptime_seconds"`
	Hooks           []string `json:"hooks,omitempty"`
}

// HeartbeatStats tracks command counters that the heartbeat sender reports.
// Callers should use atomic operations to update these.
var HeartbeatStats struct {
	CommandsAudited atomic.Int64
	CommandsBlocked atomic.Int64
}

// AgentVersion is set by the CLI package at startup to avoid import cycles.
var AgentVersion = "unknown"

var processStart = time.Now()

// RunHeartbeat starts the background heartbeat loop. It blocks until the agent
// is revoked from the server (SaaS delete), at which point it removes local
// credentials and exits so the daemon stops.
func RunHeartbeat(cfg *HeartbeatConf, configDir string) {
	if cfg == nil || cfg.URL == "" || cfg.Token == "" {
		fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: missing url or token, skipping\n")
		return
	}

	interval := 900 // 15 minutes
	if cfg.IntervalSeconds > 0 {
		interval = cfg.IntervalSeconds
	}

	client := &http.Client{Timeout: 10 * time.Second}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: started (interval: %ds, url: %s)\n", interval, cfg.URL)

	// Send immediately on start, then on tick
	if revoked := sendHeartbeat(client, cfg, configDir); revoked {
		handleRevocation()
		return
	}
	for range ticker.C {
		if revoked := sendHeartbeat(client, cfg, configDir); revoked {
			handleRevocation()
			return
		}
	}
}

// sendHeartbeat sends a single heartbeat. Returns true if the server says this
// agent has been revoked (deleted from the dashboard).
func sendHeartbeat(client *http.Client, cfg *HeartbeatConf, configDir string) bool {
	hostname := StableHostname()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	payload := heartbeatPayload{
		Hostname:        hostname,
		MachineID:       MachineID(),
		OS:              runtime.GOOS,
		Arch:            runtime.GOARCH,
		AgentVersion:    AgentVersion,
		Mode:            "managed",
		CPUPercent:      0, // Go doesn't expose CPU% easily; leave at 0
		MemoryMB:        int(memStats.Sys / 1024 / 1024),
		RulesLoaded:     countRules(configDir),
		CommandsAudited: int(HeartbeatStats.CommandsAudited.Load()),
		CommandsBlocked: int(HeartbeatStats.CommandsBlocked.Load()),
		UptimeSeconds:   int(time.Since(processStart).Seconds()),
		Hooks:           DetectHooks(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(data))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.Token)

		resp, err := client.Do(req)
		if err != nil {
			if attempt == 0 {
				continue
			}
			fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: send failed: %v\n", err)
			return false
		}
		_ = resp.Body.Close()

		// 403 with agent_revoked means admin deleted this agent from dashboard
		if resp.StatusCode == http.StatusForbidden {
			fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: agent revoked by server — shutting down\n")
			return true
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return false
		}
		if attempt == 1 {
			fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: server returned %d\n", resp.StatusCode)
		}
	}
	return false
}

// handleRevocation cleans up local state when the server revokes this agent.
// Removes credentials and exits the process so launchd won't restart it
// (no credentials = connect command fails on next launch).
func handleRevocation() {
	fmt.Fprintf(os.Stderr, "[AgentShield] agent was revoked from dashboard — removing credentials and stopping\n")

	// Remove credentials so the daemon won't restart successfully
	home, _ := os.UserHomeDir()
	_ = os.Remove(filepath.Join(home, ".agentshield", "credentials.json"))
	_ = os.Remove(filepath.Join(home, ".agentshield", "last_heartbeat"))

	// Exit the process. Launchd will try to restart, but connect will fail
	// with "not logged in" and exit immediately, so it won't keep retrying.
	os.Exit(0)
}

// DetectHooks checks which IDE hooks are configured.
func DetectHooks() []string {
	homeDir, _ := os.UserHomeDir()
	var hooks []string

	// Claude Code
	claudeSettings := filepath.Join(homeDir, ".claude", "settings.json")
	if data, err := os.ReadFile(claudeSettings); err == nil && strings.Contains(string(data), "agentshield") {
		hooks = append(hooks, "claude-code")
	}

	// Gemini CLI
	geminiSettings := filepath.Join(homeDir, ".gemini", "settings.json")
	if data, err := os.ReadFile(geminiSettings); err == nil && strings.Contains(string(data), "agentshield") {
		hooks = append(hooks, "gemini-cli")
	}

	// Windsurf
	windsurfHooks := filepath.Join(homeDir, ".codeium", "windsurf", "hooks.json")
	if data, err := os.ReadFile(windsurfHooks); err == nil && strings.Contains(string(data), "agentshield") {
		hooks = append(hooks, "windsurf")
	}

	// Cursor
	cursorHooks := filepath.Join(homeDir, ".cursor", "hooks.json")
	if data, err := os.ReadFile(cursorHooks); err == nil && strings.Contains(string(data), "agentshield") {
		hooks = append(hooks, "cursor")
	}

	return hooks
}

// countRules counts YAML rule files in the packs directory.
func countRules(configDir string) int {
	packsDir := filepath.Join(configDir, "packs")
	entries, err := os.ReadDir(packsDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		name := e.Name()
		if !e.IsDir() && !strings.HasPrefix(name, "_") &&
			(strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")) {
			count++
		}
	}
	return count
}
