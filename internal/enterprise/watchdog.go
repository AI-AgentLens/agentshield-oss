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

	"github.com/AI-AgentLens/agentshield/internal/hookentry"
	"github.com/AI-AgentLens/agentshield/internal/logger"
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
	defer func() { _ = auditLogger.Close() }()

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

// hookCommandMarker is the exact substring the watchdog looks for in the
// Windsurf, Cursor, Gemini, Codex and Copilot hook files to confirm
// AgentShield is still wired in: their setup templates all emit
// "agentshield hook" as the command. Checking the full two-token form (vs. the
// bare word "agentshield") prevents a trivial bypass where an attacker
// replaces the hook command with e.g. `echo "agentshield was here"` — the file
// would still contain the bare word but no longer invoke the binary on
// PreToolUse.
//
// Claude Code's settings.json is checked structurally instead
// (checkClaudeCodeHookFile): setup writes it in exec form (#4292), where the
// two tokens are separate JSON strings and no substring check can tell a
// working entry from a broken one.
const hookCommandMarker = "agentshield hook"

func checkHookFiles() []WatchdogCheck {
	home, err := os.UserHomeDir()
	if err != nil {
		return []WatchdogCheck{{Name: "hook-files", Passed: false, Message: "cannot determine home dir"}}
	}

	// Every IDE hook file the setup.go subcommands install must be monitored;
	// missing any of these means the watchdog is blind to tamper attempts
	// targeting that IDE — which is the whole point of the premium watchdog.
	// Paths mirror setup.go: Claude Code (settings.json), Windsurf
	// (~/.codeium/windsurf/hooks.json), Cursor, Gemini CLI (settings.json),
	// and Codex (hooks.json).
	hookPaths := []struct {
		name string
		path string
	}{
		{"claude-code", filepath.Join(home, ".claude", "settings.json")},
		{"windsurf", filepath.Join(home, ".codeium", "windsurf", "hooks.json")},
		{"cursor", filepath.Join(home, ".cursor", "hooks.json")},
		{"gemini-cli", filepath.Join(home, ".gemini", "settings.json")},
		{"codex", filepath.Join(home, ".codex", "hooks.json")},
		// GitHub Copilot CLI: AgentShield's own file in the user hooks dir
		// (internal/cli/setup_copilot.go; COPILOT_HOME overrides ~/.copilot,
		// mirrored here because this package cannot import cli).
		{"copilot-cli", filepath.Join(copilotHomeFor(home), "hooks", "agentshield.json")},
	}

	var checks []WatchdogCheck
	for _, hp := range hookPaths {
		data, err := os.ReadFile(hp.path)
		if err != nil {
			// Hook file doesn't exist — not necessarily a tamper (IDE might not be set up)
			continue
		}
		if hp.name == "claude-code" {
			checks = append(checks, checkClaudeCodeHookFile(hp.path, data))
			continue
		}
		if !strings.Contains(string(data), hookCommandMarker) {
			checks = append(checks, WatchdogCheck{
				Name:    "hook-" + hp.name,
				Passed:  false,
				Message: fmt.Sprintf("hook file %s does not contain %q — AgentShield hook may have been disabled or replaced", hp.path, hookCommandMarker),
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

// checkClaudeCodeHookFile passes only when the Claude Code settings file
// parses and holds, under hooks.PreToolUse[*].hooks[*], a hook object the
// shared recognizer accepts: shell form ("… agentshield hook") or exec form
// (".../agentshield" with args exactly ["hook"]). The anti-bypass property of
// hookCommandMarker holds and tightens: an `echo "agentshield was here"`
// command fails, and so does our command appearing anywhere but a PreToolUse
// hook, an exec-form entry whose args were removed or extended, and a file
// that no longer parses (Claude Code would not load its hooks either).
func checkClaudeCodeHookFile(path string, data []byte) WatchdogCheck {
	const name = "hook-claude-code"
	ok, err := hookentry.SettingsHasPreToolUseHook(data)
	switch {
	case err != nil:
		return WatchdogCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("hook file %s does not parse as JSON (%v) — AgentShield hook may have been disabled or replaced", path, err),
		}
	case !ok:
		return WatchdogCheck{
			Name:    name,
			Passed:  false,
			Message: fmt.Sprintf("hook file %s has no PreToolUse hook that runs `agentshield hook` — AgentShield hook may have been disabled or replaced", path),
		}
	}
	return WatchdogCheck{Name: name, Passed: true}
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
	_ = resp.Body.Close()
}

// copilotHomeFor mirrors GitHub Copilot CLI's config-directory resolution:
// COPILOT_HOME, else ~/.copilot.
func copilotHomeFor(home string) string {
	if h := os.Getenv("COPILOT_HOME"); h != "" {
		return h
	}
	return filepath.Join(home, ".copilot")
}
