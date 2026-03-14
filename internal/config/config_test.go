package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManaged_FileExists(t *testing.T) {
	tmpDir := t.TempDir()
	managedPath := filepath.Join(tmpDir, "managed.json")
	data := `{"managed": true, "organization_id": "acme-corp", "fail_closed": true}`
	if err := os.WriteFile(managedPath, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}

	mc := LoadManaged(tmpDir)
	if mc == nil {
		t.Fatal("expected ManagedConfig, got nil")
	}
	if !mc.Managed {
		t.Error("expected Managed=true")
	}
	if mc.OrganizationID != "acme-corp" {
		t.Errorf("expected OrganizationID=acme-corp, got %s", mc.OrganizationID)
	}
	if !mc.FailClosed {
		t.Error("expected FailClosed=true")
	}
}

func TestLoadManaged_FileMissing(t *testing.T) {
	tmpDir := t.TempDir()
	mc := LoadManaged(tmpDir)
	if mc != nil {
		t.Errorf("expected nil when managed.json missing, got %+v", mc)
	}
}

func TestLoadManaged_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	managedPath := filepath.Join(tmpDir, "managed.json")
	if err := os.WriteFile(managedPath, []byte("not json"), 0600); err != nil {
		t.Fatal(err)
	}
	mc := LoadManaged(tmpDir)
	if mc != nil {
		t.Errorf("expected nil for invalid JSON, got %+v", mc)
	}
}

func TestLoad_ManagedOverridesPolicyPath(t *testing.T) {
	// Create a temp dir to act as home
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	// Write managed.json
	managed := ManagedConfig{Managed: true, FailClosed: true}
	data, _ := json.Marshal(managed)
	if err := os.WriteFile(filepath.Join(configDir, "managed.json"), data, 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("/custom/policy.yaml", "/custom/audit.jsonl", "policy-only")
	if err != nil {
		t.Fatal(err)
	}

	// In managed mode, custom paths should be overridden
	expectedPolicy := filepath.Join(configDir, DefaultPolicyFile)
	if cfg.PolicyPath != expectedPolicy {
		t.Errorf("expected PolicyPath=%s (managed override), got %s", expectedPolicy, cfg.PolicyPath)
	}

	expectedLog := filepath.Join(configDir, DefaultLogFile)
	if cfg.LogPath != expectedLog {
		t.Errorf("expected LogPath=%s (managed override), got %s", expectedLog, cfg.LogPath)
	}
}

func TestLoad_NonManagedAllowsCustomPaths(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("/custom/policy.yaml", "/custom/audit.jsonl", "policy-only")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.PolicyPath != "/custom/policy.yaml" {
		t.Errorf("expected custom PolicyPath, got %s", cfg.PolicyPath)
	}
	if cfg.LogPath != "/custom/audit.jsonl" {
		t.Errorf("expected custom LogPath, got %s", cfg.LogPath)
	}
}
