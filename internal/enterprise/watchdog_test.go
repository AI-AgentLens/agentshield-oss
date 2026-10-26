package enterprise

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestWatchdog_DetectRemovedHook(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create a claude code settings file WITHOUT agentshield
	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0755); err != nil {
		t.Fatal(err)
	}
	settings := `{"hooks": {"PreToolUse": []}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)

	// Should detect that claude-code hook doesn't contain agentshield
	foundHookIssue := false
	for _, c := range checks {
		if c.Name == "hook-claude-code" && !c.Passed {
			foundHookIssue = true
		}
	}
	if !foundHookIssue {
		t.Error("expected watchdog to detect missing agentshield hook in claude-code settings")
	}
}

func TestWatchdog_MissingPolicy(t *testing.T) {
	tmpHome := t.TempDir()
	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)

	foundPolicyIssue := false
	for _, c := range checks {
		if c.Name == "policy-file" && !c.Passed {
			foundPolicyIssue = true
		}
	}
	if !foundPolicyIssue {
		t.Error("expected watchdog to detect missing policy.yaml")
	}
}

func TestWatchdog_AllHealthy(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Create policy.yaml
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte("version: '0.1'"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create managed.json
	managed := ManagedConfig{Managed: true}
	data, _ := json.Marshal(managed)
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)

	for _, c := range checks {
		if c.Name == "policy-file" && !c.Passed {
			t.Errorf("expected policy-file check to pass, got: %s", c.Message)
		}
		if c.Name == "managed-config" && !c.Passed {
			t.Errorf("expected managed-config check to pass, got: %s", c.Message)
		}
		if c.Name == "bypass-env" && !c.Passed {
			t.Errorf("expected bypass-env check to pass, got: %s", c.Message)
		}
	}
}

func TestWatchdog_AlertWebhook(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	check := WatchdogCheck{
		Name:    "test-check",
		Passed:  false,
		Message: "test failure",
	}
	sendWatchdogAlert(server.URL, check)

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("expected alert webhook to receive data")
	}

	var alert map[string]interface{}
	if err := json.Unmarshal(received, &alert); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if alert["type"] != "tamper_detected" {
		t.Errorf("expected type=tamper_detected, got %v", alert["type"])
	}
	if alert["check"] != "test-check" {
		t.Errorf("expected check=test-check, got %v", alert["check"])
	}
}

func TestWatchdog_BypassEnvDetection(t *testing.T) {
	t.Setenv("AGENTSHIELD_BYPASS", "1")

	check := checkBypassEnv()
	if check.Passed {
		t.Error("expected bypass-env check to fail when AGENTSHIELD_BYPASS=1")
	}
}

// TestWatchdog_BypassedByEchoingAgentshield pins the regression that the old
// substring check ("agentshield" anywhere) was bypassable. An attacker can
// neuter the hook by replacing the command with `echo agentshield ...` — the
// file still contains the bare word but no longer invokes the binary on
// PreToolUse. The watchdog must look for the exact "agentshield hook" command
// marker setup.go writes.
func TestWatchdog_BypassedByEchoingAgentshield(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Tampered settings: contains "agentshield" as free text, but no
	// PreToolUse hook actually invokes the binary. Pre-fix this passed the
	// watchdog because the bare substring "agentshield" was present.
	tampered := `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "echo agentshield-disabled-by-attacker"}]}]}}`
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(tampered), 0o644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)
	foundTamper := false
	for _, c := range checks {
		if c.Name == "hook-claude-code" && !c.Passed {
			foundTamper = true
		}
	}
	if !foundTamper {
		t.Error("watchdog must flag a hook file that contains the substring \"agentshield\" but no \"agentshield hook\" command — the old substring check was bypassable")
	}
}

// TestWatchdog_DetectsGeminiAndCodexTamper pins that the watchdog monitors
// every IDE hook file setup.go can install. Before this test, only Claude
// Code / Windsurf / Cursor were checked; Gemini CLI and Codex were blind
// spots — premium customers using either could disable the hook and the
// watchdog would never alert.
func TestWatchdog_DetectsGeminiAndCodexTamper(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Gemini: settings.json with no agentshield reference.
	geminiDir := filepath.Join(tmpHome, ".gemini")
	if err := os.MkdirAll(geminiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(geminiDir, "settings.json"), []byte(`{"theme":"default"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Codex: hooks.json with no agentshield reference.
	codexDir := filepath.Join(tmpHome, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)

	foundGemini := false
	foundCodex := false
	for _, c := range checks {
		if c.Name == "hook-gemini-cli" && !c.Passed {
			foundGemini = true
		}
		if c.Name == "hook-codex" && !c.Passed {
			foundCodex = true
		}
	}
	if !foundGemini {
		t.Error("watchdog must flag missing agentshield hook in ~/.gemini/settings.json")
	}
	if !foundCodex {
		t.Error("watchdog must flag missing agentshield hook in ~/.codex/hooks.json")
	}
}

// TestWatchdog_HealthyGeminiAndCodexPass pins the happy path — when the hook
// command marker is present in a Gemini or Codex hook file, the check passes.
func TestWatchdog_HealthyGeminiAndCodexPass(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	geminiDir := filepath.Join(tmpHome, ".gemini")
	if err := os.MkdirAll(geminiDir, 0o755); err != nil {
		t.Fatal(err)
	}
	geminiSettings := `{"hooks":{"BeforeTool":[{"hooks":[{"type":"command","command":"agentshield hook"}]}]}}`
	if err := os.WriteFile(filepath.Join(geminiDir, "settings.json"), []byte(geminiSettings), 0o644); err != nil {
		t.Fatal(err)
	}

	codexDir := filepath.Join(tmpHome, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	codexHooks := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"agentshield hook"}]}]}}`
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(codexHooks), 0o644); err != nil {
		t.Fatal(err)
	}

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}

	checks := RunWatchdogOnce(configDir)
	for _, c := range checks {
		if c.Name == "hook-gemini-cli" && !c.Passed {
			t.Errorf("expected hook-gemini-cli to pass when 'agentshield hook' present, got: %s", c.Message)
		}
		if c.Name == "hook-codex" && !c.Passed {
			t.Errorf("expected hook-codex to pass when 'agentshield hook' present, got: %s", c.Message)
		}
	}
}

// TestWatchdog_CopilotHookFile (#4251 review, finding 2): the watchdog reads
// the Copilot CLI hook file (honouring COPILOT_HOME) and flags it when the
// agentshield hook is gone; an intact file passes.
func TestWatchdog_CopilotHookFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	copilotHome := filepath.Join(tmpHome, "custom-copilot")
	t.Setenv("COPILOT_HOME", copilotHome)
	hooksDir := filepath.Join(copilotHome, "hooks")
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	hookFile := filepath.Join(hooksDir, "agentshield.json")
	status := func() (found, passed bool) {
		for _, c := range RunWatchdogOnce(configDir) {
			if c.Name == "hook-copilot-cli" {
				return true, c.Passed
			}
		}
		return false, false
	}

	if err := os.WriteFile(hookFile, []byte(`{"version":1,"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if found, passed := status(); !found || passed {
		t.Errorf("tampered Copilot hook file: found=%v passed=%v, want a failing hook-copilot-cli check", found, passed)
	}
	intact := `{"version":1,"hooks":{"PreToolUse":[{"type":"command","bash":"/opt/homebrew/bin/agentshield hook"}]}}`
	if err := os.WriteFile(hookFile, []byte(intact), 0o644); err != nil {
		t.Fatal(err)
	}
	if found, passed := status(); found && !passed {
		t.Error("an intact Copilot hook file was flagged")
	}
}

// claudeCodeHookChecks writes settings as ~/.claude/settings.json in a fresh
// HOME and returns every hook-claude-code check the watchdog reports. All of
// them, not the first: a second, failing check behind a passing one is still
// a false alarm on every interval.
func claudeCodeHookChecks(t *testing.T, settings string) []WatchdogCheck {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(settings), 0o644); err != nil {
		t.Fatal(err)
	}
	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	var found []WatchdogCheck
	for _, c := range RunWatchdogOnce(configDir) {
		if c.Name == "hook-claude-code" {
			found = append(found, c)
		}
	}
	if len(found) == 0 {
		t.Fatal("watchdog reported no hook-claude-code check for an existing settings file")
	}
	return found
}

// TestWatchdog_ClaudeCodeHookIsStructural (#4292): setup now writes the Claude
// Code hook in exec form, where "agentshield" and "hook" are separate JSON
// strings. The check parses the file and requires a PreToolUse hook object
// the shared recognizer accepts. On main the exec-form entry was flagged as
// tampered, and the broken lookalikes below passed the substring check.
func TestWatchdog_ClaudeCodeHookIsStructural(t *testing.T) {
	cases := []struct {
		name     string
		settings string
		pass     bool
	}{
		{"exec form", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true},
		{"shell form, existing installs", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, true},
		{"ours beside another hook", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/lint"},{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true},

		{"exec form with args removed", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield"}]}]}}`, false},
		{"exec form with --help appended", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook","--help"]}]}]}}`, false},
		{"exec form pointing at a lookalike", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/tmp/agentshield-evil","args":["hook"]}]}]}}`, false},
		{"echo replacing the hook", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo \"agentshield was here\""}]}]}}`, false},
		{"shell string with args (never runs on 2.1.296)", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook","args":[]}]}]}}`, false},
		{"our command moved to PostToolUse", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, false},
		{"our command as free text", `{"note":"/opt/homebrew/bin/agentshield hook","hooks":{}}`, false},
		{"file no longer parses", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}`, false},

		// Claude Code loads a settings file that starts with a UTF-8 BOM
		// (measured on 2.1.296 and 2.1.138), so the watchdog must too (C2).
		{"UTF-8 BOM, exec form", "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, true},
		{"UTF-8 BOM, shell form", "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, true},
		{"UTF-8 BOM, hook removed", "\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[]}}`, false},
		// Claude Code rejects a double BOM (#4314 pass 2), so the file no longer
		// loads its hooks and the watchdog must flag it.
		{"double BOM, exec form", "\xef\xbb\xbf\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false},
		{"triple BOM, shell form", "\xef\xbb\xbf\xef\xbb\xbf\xef\xbb\xbf" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, false},
		{"BOM only", "\xef\xbb\xbf", false},
		{"partial BOM, exec form", "\xef\xbb" + `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checks := claudeCodeHookChecks(t, tc.settings)
			if len(checks) != 1 {
				t.Errorf("hook-claude-code checks = %d; want exactly 1: %+v", len(checks), checks)
			}
			// Every check, not the first: a valid install must raise no
			// failing hook-claude-code check at all, and a tampered one at
			// least one.
			anyFailed := false
			for _, c := range checks {
				if !c.Passed {
					anyFailed = true
					if c.Message == "" {
						t.Error("a failing check must say why")
					}
					if tc.pass {
						t.Errorf("valid install flagged: %s", c.Message)
					}
				}
			}
			if !tc.pass && !anyFailed {
				t.Errorf("tampered install passed every hook-claude-code check: %+v", checks)
			}
		})
	}
}

// #4326: a PreToolUse entry that merely ENDS with "agentshield hook" is not an
// installed hook. `echo agentshield hook` exits 0 and evaluates nothing, so the
// watchdog must not report hook-claude-code as passed.
func TestWatchdog_ClaudeCodeHookRejectsSuffixOnlyWrappers(t *testing.T) {
	for _, cmd := range []string{
		"echo agentshield hook",
		"true; agentshield hook",
		"false && agentshield hook",
	} {
		data := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"` + cmd + `"}]}]}}`)
		if c := checkClaudeCodeHookFile("settings.json", data); c.Passed {
			t.Errorf("%q must not satisfy the Claude Code hook check", cmd)
		}
	}
	control := []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`)
	if c := checkClaudeCodeHookFile("settings.json", control); !c.Passed {
		t.Errorf("control: a real shell-form entry must pass, got: %s", c.Message)
	}
}
