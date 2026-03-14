package enterprise

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/logger"
)

// WatchdogCheck represents a single watchdog health check result.
type WatchdogCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// RunWatchdogOnce performs all watchdog checks and returns results.
func RunWatchdogOnce(configDir string) []WatchdogCheck {
	var checks []WatchdogCheck

	checks = append(checks, checkHookFiles()...)
	checks = append(checks, checkPolicyFile(configDir))
	checks = append(checks, checkManagedConfig(configDir))
	checks = append(checks, checkBypassEnv())

	return checks
}

// RunWatchdog starts the watchdog loop that polls at the configured interval.
func RunWatchdog(cfg *ManagedConfig, configDir string) {
	interval := 60
	if cfg.Watchdog != nil && cfg.Watchdog.IntervalSeconds > 0 {
		interval = cfg.Watchdog.IntervalSeconds
	}

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	auditLogger, err := logger.New(filepath.Join(configDir, "audit.jsonl"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "[AgentShield] watchdog: failed to init logger: %v\n", err)
		return
	}
	defer auditLogger.Close()

	fmt.Fprintf(os.Stderr, "[AgentShield] watchdog: started (interval: %ds)\n", interval)

	for {
		checks := RunWatchdogOnce(configDir)

		// Log heartbeat
		heartbeat := logger.AuditEvent{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Command:   "watchdog-heartbeat",
			Decision:  "ALLOW",
			Mode:      "watchdog",
			Source:    "watchdog",
		}
		_ = auditLogger.Log(heartbeat)

		// Check for failures
		for _, c := range checks {
			if !c.Passed {
				tamperEvent := logger.AuditEvent{
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Command:   "watchdog-tamper-detected",
					Decision:  "AUDIT",
					Flagged:   true,
					Mode:      "watchdog",
					Source:    "watchdog",
					Error:     fmt.Sprintf("%s: %s", c.Name, c.Message),
				}
				_ = auditLogger.Log(tamperEvent)

				// Alert via webhook if configured
				if cfg.Watchdog != nil && cfg.Watchdog.AlertWebhook != "" {
					go sendWatchdogAlert(cfg.Watchdog.AlertWebhook, c)
				}
			}
		}

		<-ticker.C
	}
}

func checkHookFiles() []WatchdogCheck {
	home, err := os.UserHomeDir()
	if err != nil {
		return []WatchdogCheck{{Name: "hook-files", Passed: false, Message: "cannot determine home dir"}}
	}

	hookPaths := []struct {
		name string
		path string
	}{
		{"claude-code", filepath.Join(home, ".claude", "settings.json")},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "hooks.json")},
		{"cursor", filepath.Join(home, ".cursor", "hooks.json")},
	}

	var checks []WatchdogCheck
	for _, hp := range hookPaths {
		data, err := os.ReadFile(hp.path)
		if err != nil {
			// Hook file doesn't exist — not necessarily a tamper (IDE might not be set up)
			continue
		}
		if !strings.Contains(string(data), "agentshield hook") && !strings.Contains(string(data), "agentshield") {
			checks = append(checks, WatchdogCheck{
				Name:    "hook-" + hp.name,
				Passed:  false,
				Message: fmt.Sprintf("hook file %s does not contain agentshield", hp.path),
			})
		} else {
			checks = append(checks, WatchdogCheck{
				Name:   "hook-" + hp.name,
				Passed: true,
			})
		}
	}

	return checks
}

func checkPolicyFile(configDir string) WatchdogCheck {
	policyPath := filepath.Join(configDir, "policy.yaml")
	if _, err := os.Stat(policyPath); os.IsNotExist(err) {
		return WatchdogCheck{
			Name:    "policy-file",
			Passed:  false,
			Message: "policy.yaml is missing",
		}
	}
	return WatchdogCheck{
		Name:   "policy-file",
		Passed: true,
	}
}

func checkManagedConfig(configDir string) WatchdogCheck {
	managedPath := filepath.Join(configDir, "managed.json")
	data, err := os.ReadFile(managedPath)
	if err != nil {
		return WatchdogCheck{
			Name:    "managed-config",
			Passed:  false,
			Message: "managed.json is missing or unreadable",
		}
	}
	var cfg ManagedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return WatchdogCheck{
			Name:    "managed-config",
			Passed:  false,
			Message: "managed.json is invalid JSON",
		}
	}
	return WatchdogCheck{
		Name:   "managed-config",
		Passed: true,
	}
}

func checkBypassEnv() WatchdogCheck {
	if os.Getenv("AGENTSHIELD_BYPASS") == "1" {
		return WatchdogCheck{
			Name:    "bypass-env",
			Passed:  false,
			Message: "AGENTSHIELD_BYPASS=1 is set",
		}
	}
	return WatchdogCheck{
		Name:   "bypass-env",
		Passed: true,
	}
}

func sendWatchdogAlert(webhookURL string, check WatchdogCheck) {
	alert := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"type":      "tamper_detected",
		"check":     check.Name,
		"message":   check.Message,
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return
	}
	resp.Body.Close()
}
