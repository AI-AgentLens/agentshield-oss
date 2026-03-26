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

// RunHeartbeat starts the background heartbeat loop. It blocks forever.
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
	sendHeartbeat(client, cfg, configDir)
	for range ticker.C {
		sendHeartbeat(client, cfg, configDir)
	}
}

func sendHeartbeat(client *http.Client, cfg *HeartbeatConf, configDir string) {
	hostname := StableHostname()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	payload := heartbeatPayload{
		Hostname:        hostname,
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
		return
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.Token)

		resp, err := client.Do(req)
		if err != nil {
			if attempt == 0 {
				continue
			}
			fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: send failed: %v\n", err)
			return
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
		if attempt == 1 {
			fmt.Fprintf(os.Stderr, "[AgentShield] heartbeat: server returned %d\n", resp.StatusCode)
		}
	}
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
