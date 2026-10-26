package enterprise

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
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

	// scope is what the managed-scope check read, for the loop's tamper vs
	// config-gap decision (watchdog_events.go). Nil on every other check.
	scope *managedScope
}

// RunWatchdogOnce performs all watchdog checks and returns results.
//
// When configDir's managed.json puts the host in managed mode (read the way
// every other managed-mode gate reads it, so a corrupt file counts as
// managed), it also checks that Claude Code's managed settings carry the
// AgentShield hook (#4292).
func RunWatchdogOnce(configDir string) []WatchdogCheck {
	var checks []WatchdogCheck

	checks = append(checks, checkHookFiles()...)
	if m := LoadManagedConfigFrom(filepath.Join(configDir, "managed.json")); m != nil && m.Managed {
		checks = append(checks, checkClaudeCodeHookScopes())
	}
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

	tracker := newWatchdogTracker(configDir)
	alert := func(watchdogEvent) {}
	if cfg.Watchdog != nil && cfg.Watchdog.AlertWebhook != "" {
		url := cfg.Watchdog.AlertWebhook
		alert = func(ev watchdogEvent) { go sendWatchdogAlertEvent(url, ev) }
	}
	for {
		watchdogTick(configDir, tracker, auditLogger.Log, alert)
		<-ticker.C
	}
}

// watchdogTick is one pass of the watchdog loop: run the checks, log the
// heartbeat, then log and alert each event the tracker decides on
// (watchdog_events.go).
func watchdogTick(configDir string, t *watchdogTracker, log func(logger.AuditEvent) error, alert func(watchdogEvent)) {
	checks := RunWatchdogOnce(configDir)

	_ = log(logger.AuditEvent{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Command:   "watchdog-heartbeat",
		Decision:  "ALLOW",
		Mode:      "watchdog",
		Source:    "watchdog",
	})

	for _, ev := range t.evaluate(checks) {
		_ = log(ev.auditEvent())
		alert(ev)
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

// ClaudeManagedHookCheckName names the check that Claude Code's managed
// settings carry the AgentShield hook. `agentshield scan` reports it too.
const ClaudeManagedHookCheckName = "hook-claude-code-managed"

// ClaudeManagedSettingsPath returns where Claude Code's file-based managed
// settings live on this OS. `agentshield setup claude-code --managed` and
// --write-managed use it too, so the watchdog checks the file setup writes.
// A variable only so tests can point it at a temp file; nothing else assigns
// it, and no environment variable moves it, since anything a repository's
// settings could set must not decide where the watchdog looks.
var ClaudeManagedSettingsPath = func() string {
	return hookentry.ManagedSettingsPath(runtime.GOOS)
}

// checkClaudeCodeHookScopes is managed mode's check that AgentShield's Claude
// Code hook is registered in Claude Code managed settings (#4292). A hook
// there survives a repository's committed .claude/settings.json setting
// "disableAllHooks": true, and the user-scope hook in ~/.claude/settings.json
// does not: measured for a SessionStart hook on Claude Code 2.1.296
// (2026-10-12); for PreToolUse, the event AgentShield uses, Claude Code's
// documentation says the same, but it is not measured. It fails when the
// managed settings file is missing, empty, unreadable, malformed, holds no
// AgentShield PreToolUse hook, or sets disableAllHooks itself, which turns
// managed hooks off too. It passes only when the hook is there. Its message
// always names the scopes that carry the hook, managed and user, pass or fail.
//
// It reports and never blocks: whether managed mode should require this
// scope is not decided (#4292). The user-scope check (hook-claude-code) is
// unchanged and still runs beside it. Whether a failure is logged as tamper
// or as a configuration gap, and how often, is the watchdog loop's decision
// (watchdog_events.go).
//
// Honest limit: it reads the managed settings FILE only. Claude Code uses one
// managed source by default, the highest-ranked one that delivers a policy
// key: server-managed settings, then an MDM profile or HKLM registry value,
// then the file (https://code.claude.com/docs/en/managed-settings, "How
// Claude Code combines managed sources"). A hook delivered by an MDM profile
// or server-managed settings is not seen here and is reported missing; a
// hook in the file is reported present even when a higher-ranked source
// makes Claude Code skip the file.
func checkClaudeCodeHookScopes() WatchdogCheck {
	managedPath := ClaudeManagedSettingsPath()
	scope := managedScopeState(managedPath)
	user := "unknown (cannot determine home dir)"
	if home, err := os.UserHomeDir(); err == nil {
		user = userScopeState(filepath.Join(home, ".claude", "settings.json"))
	}
	scopes := fmt.Sprintf("Claude Code hook scopes: managed %s; user %s", scope.desc, user)
	if scope.ok {
		return WatchdogCheck{Name: ClaudeManagedHookCheckName, Passed: true, Message: scopes, scope: &scope}
	}
	return WatchdogCheck{
		Name:   ClaudeManagedHookCheckName,
		Passed: false,
		Message: scopes + ". Managed mode expects the hook in Claude Code managed settings, the one scope a repository's " +
			"committed .claude/settings.json cannot switch off with disableAllHooks (#4292). Deploy it with " +
			"`agentshield setup claude-code --managed` (prints the snippet for MDM) or " +
			"`agentshield setup claude-code --write-managed` (writes the file; needs administrator rights)",
		scope: &scope,
	}
}

// managedScope is what checkClaudeCodeHookScopes read from the managed
// settings file.
type managedScope struct {
	// ok: the hook is in the file and will run.
	ok bool
	// hookInFile: the file parses and holds an AgentShield PreToolUse hook,
	// whether or not disableAllHooks turns it off.
	hookInFile bool
	// disablesAll: the file sets "disableAllHooks": true.
	disablesAll bool
	// desc is the short description for the scope report.
	desc string
}

// managedScopeState reads Claude Code's managed settings file at path and
// reports whether it carries a working AgentShield hook.
func managedScopeState(path string) managedScope {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return managedScope{desc: fmt.Sprintf("missing (%s does not exist)", path)}
	case err != nil:
		// Claude Code reads the file as the same user; a read the OS denies
		// starts every session without that source's policies.
		return managedScope{desc: fmt.Sprintf("unreadable (%s: %v)", path, err)}
	}
	if len(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")))) == 0 {
		// Claude Code reads an empty managed settings file as {} (managed
		// settings page, "Find entries Claude Code dropped"): valid, no hooks.
		return managedScope{desc: fmt.Sprintf("empty (Claude Code reads it as {}): no AgentShield hook in %s", path)}
	}
	ok, err := hookentry.SettingsHasPreToolUseHook(data)
	if err != nil {
		// Claude Code refuses to start while a managed settings file is not a
		// JSON object, so no hook runs either.
		return managedScope{desc: fmt.Sprintf("broken (%s does not parse as JSON: %v)", path, err)}
	}
	s := managedScope{hookInFile: ok, disablesAll: disablesAllHooks(data)}
	switch {
	case s.disablesAll:
		s.desc = fmt.Sprintf("off (%s sets disableAllHooks: true, which turns off managed hooks too)", path)
	case !ok:
		s.desc = fmt.Sprintf("missing (%s has no PreToolUse hook that runs `agentshield hook`)", path)
	default:
		s.ok = true
		s.desc = fmt.Sprintf("present (%s)", path)
	}
	return s
}

// userScopeState describes the user-scope hook in ~/.claude/settings.json for
// the scope report. The pass/fail verdict on that file stays with
// checkClaudeCodeHookFile.
func userScopeState(path string) string {
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf("missing (%s does not exist)", path)
	case err != nil:
		return fmt.Sprintf("unreadable (%s: %v)", path, err)
	}
	ok, err := hookentry.SettingsHasPreToolUseHook(data)
	switch {
	case err != nil:
		return fmt.Sprintf("broken (%s does not parse as JSON)", path)
	case !ok:
		return fmt.Sprintf("missing (%s has no PreToolUse hook that runs `agentshield hook`)", path)
	}
	return fmt.Sprintf("present (%s)", path)
}

// disablesAllHooks reports whether a settings document sets
// "disableAllHooks" to the JSON boolean true. Claude Code drops any other
// value in managed settings with a warning (managed-settings page, "Keys that
// fail closed"), so only true turns hooks off.
func disablesAllHooks(data []byte) bool {
	var doc struct {
		DisableAllHooks interface{} `json:"disableAllHooks"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")), &doc); err != nil {
		return false
	}
	b, ok := doc.DisableAllHooks.(bool)
	return ok && b
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
	sendWatchdogAlertType(webhookURL, alertTamper, check.Name, check.Message)
}

// sendWatchdogAlertEvent posts the webhook alert for one watchdog event.
func sendWatchdogAlertEvent(webhookURL string, ev watchdogEvent) {
	sendWatchdogAlertType(webhookURL, ev.kind.alertType(), ev.check.Name, ev.message)
}

// sendWatchdogAlertType posts one alert. The payload shape is the one the
// tamper alert always had; alertType is its "type" field.
func sendWatchdogAlertType(webhookURL, alertType, checkName, message string) {
	alert := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"type":      alertType,
		"check":     checkName,
		"message":   message,
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
