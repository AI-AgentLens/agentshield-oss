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
