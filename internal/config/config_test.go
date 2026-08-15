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

	cfg, err := Load("/custom/policy.yaml", "/custom/audit.jsonl", "enforce")
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

	cfg, err := Load("/custom/policy.yaml", "/custom/audit.jsonl", "enforce")
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

// --- Issue #1952: audit-only mode -----------------------------------------

// TestConfig_DefaultMode — when the CLI passes "" and no YAML file exists,
// Mode resolves to "enforce". This is the safety guarantee that every
// existing user's behavior stays unchanged after upgrading to the version
// that introduces this field.
func TestConfig_DefaultMode(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("expected default Mode=%q, got %q", ModeEnforce, cfg.Mode)
	}
}

// TestConfig_AuditOnlyMode_FromYAML — the YAML config file can set the mode.
// Verifies the file path Load consults (~/.agentshield/agentshield.yaml) and
// that the value flows through.
func TestConfig_AuditOnlyMode_FromYAML(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(configDir, DefaultConfigFile)
	if err := os.WriteFile(yamlPath, []byte("mode: audit-only\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeAuditOnly {
		t.Errorf("expected Mode=%q from YAML, got %q", ModeAuditOnly, cfg.Mode)
	}
}

// TestConfig_CLIOverridesYAML — the CLI flag wins over the YAML file. This
// makes "agentshield ... --mode=enforce" a reliable kill-switch even when
// the YAML has been flipped to audit-only.
func TestConfig_CLIOverridesYAML(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	yamlPath := filepath.Join(configDir, DefaultConfigFile)
	if err := os.WriteFile(yamlPath, []byte("mode: audit-only\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("", "", "enforce")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("CLI override failed: expected %q, got %q", ModeEnforce, cfg.Mode)
	}
}

// TestConfig_AuditOnlyMode_FromPolicyYAML — the SaaS-pushed policy.yaml can
// carry the enforcement_mode at the top, and that value participates in mode
// resolution as rung 3 (below agentshield.yaml). This is the path that was
// silently broken — the 2026-05-17 deep-dive caught that the Settings toggle
// in app.aiagentlens.com was a no-op because no code consulted this field.
// Issue #1952.
func TestConfig_AuditOnlyMode_FromPolicyYAML(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(configDir, DefaultPolicyFile)
	policyYAML := `version: "0.1"
enforcement_mode: "audit-only"

defaults:
  decision: "AUDIT"

rules: []
`
	if err := os.WriteFile(policyPath, []byte(policyYAML), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeAuditOnly {
		t.Errorf("expected Mode=%q from policy.yaml enforcement_mode, got %q", ModeAuditOnly, cfg.Mode)
	}
}

// TestConfig_AgentshieldYamlOverridesPolicyYaml — local agentshield.yaml
// `mode:` always wins over the SaaS-pushed policy.yaml `enforcement_mode:`.
// Without this guarantee an operator couldn't break-glass back to enforce
// while waiting for the SaaS toggle to flip back. Issue #1952.
func TestConfig_AgentshieldYamlOverridesPolicyYaml(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	// SaaS-pushed policy says audit-only
	if err := os.WriteFile(filepath.Join(configDir, DefaultPolicyFile),
		[]byte("enforcement_mode: \"audit-only\"\nrules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// Local override says enforce
	if err := os.WriteFile(filepath.Join(configDir, DefaultConfigFile),
		[]byte("mode: enforce\n"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("local agentshield.yaml must win over SaaS policy.yaml: expected %q, got %q",
			ModeEnforce, cfg.Mode)
	}
}

// TestConfig_PolicyYaml_UnparseableIsIgnored — a corrupted policy.yaml never
// blocks startup. Falls through to the next resolution rung (default enforce).
// Same fail-safe story as the other config-load paths: a broken file never
// silently turns the gateway into a passive logger. Issue #1952.
func TestConfig_PolicyYaml_UnparseableIsIgnored(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, DefaultConfigDir)
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, DefaultPolicyFile),
		[]byte("not: [valid: yaml"), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("unparseable policy.yaml should fall through to enforce default; got %q", cfg.Mode)
	}
}

// TestConfig_InvalidMode — typos in YAML or CLI must not silently turn the
// gateway into a passive logger. The policy is: coerce to enforce, warn on
// stderr, keep running. The alternative (refuse to start) trades a
// confusing-but-safe state for hard breakage on every host that has a typo
// in agentshield.yaml — strictly worse for a security tool.
func TestConfig_InvalidMode(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	cfg, err := Load("", "", "nonsense")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("invalid mode should coerce to %q, got %q", ModeEnforce, cfg.Mode)
	}
}

// TestNormalizeMode — direct unit test on the validator so callers (CLI,
// SaaS-side mirror) can reuse it.
func TestNormalizeMode(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"", ModeEnforce, true},
		{"enforce", ModeEnforce, true},
		{"audit-only", ModeAuditOnly, true},
		{"AUDIT-ONLY", ModeEnforce, false},  // case-sensitive on purpose
		{"audit_only", ModeEnforce, false},  // separator is hyphen, not underscore
		{"nonsense", ModeEnforce, false},
	}
	for _, tc := range cases {
		got, ok := NormalizeMode(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("NormalizeMode(%q) = (%q, %v); want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}
