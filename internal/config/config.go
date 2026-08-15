package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigDir  = ".agentshield"
	DefaultPolicyFile = "policy.yaml"
	DefaultLogFile    = "audit.jsonl"
	// DefaultConfigFile is the optional YAML config file for AgentShield-wide
	// settings (currently just `mode:`). It sits next to policy.yaml in the
	// config dir. Missing file is fine — defaults apply. See issue #1952.
	DefaultConfigFile = "agentshield.yaml"
)

// Enforcement modes for the AgentShield runtime. Introduced for issue #1952
// so a small pilot deployment can flip the whole installation into
// "audit-only" — collect telemetry, never interrupt — without touching
// any individual rule.
const (
	// ModeEnforce is the default. BLOCK rules block. REQUIRE_APPROVAL rules
	// prompt. Behavior matches every AgentShield release up to and including
	// the version that shipped this field.
	ModeEnforce = "enforce"
	// ModeAuditOnly downgrades BLOCK and REQUIRE_APPROVAL decisions to AUDIT
	// at the decision-pipeline boundary. The original (pre-downgrade)
	// decision is captured on the audit-log entry as `original_decision`.
	// ALLOW and AUDIT are unchanged.
	ModeAuditOnly = "audit-only"
)

type Config struct {
	PolicyPath string
	LogPath    string
	// Mode is the enforcement mode for the runtime: "enforce" (default) or
	// "audit-only". See issue #1952 and the ModeEnforce/ModeAuditOnly
	// constants for semantics. Resolution order:
	//   1. CLI flag (--mode) if explicitly set to a non-empty value
	//   2. YAML config file (~/.agentshield/agentshield.yaml, key "mode")
	//   3. SaaS-pushed policy.yaml's top-level `enforcement_mode:` field
	//      (written by the enterprise sync from /api/policy/yaml)
	//   4. ModeEnforce
	// An unrecognized value is coerced to ModeEnforce with a stderr warning —
	// we deliberately prefer fail-safe (keep enforcing) over fail-loud (refuse
	// to start), because a typo in a YAML config should never silently turn
	// the gateway into a passive logger. Documented in the test
	// TestConfig_InvalidMode.
	Mode      string
	ConfigDir string
	Analyzer  AnalyzerConfig
	Managed   *ManagedConfig
}

// ManagedConfig represents the enterprise managed configuration loaded from managed.json.
type ManagedConfig struct {
	Managed        bool   `json:"managed"`
	OrganizationID string `json:"organization_id,omitempty"`
	FailClosed     bool   `json:"fail_closed"`
}

// AnalyzerConfig controls the multi-layer analyzer pipeline.
type AnalyzerConfig struct {
	// EnabledAnalyzers lists which analyzers to run. Default: ["regex", "structural", "semantic"].
	EnabledAnalyzers []string
	// CombineStrategy controls how findings are merged. Default: "most_restrictive".
	CombineStrategy string
	// MaxParseDepth controls indirect execution parsing depth. Default: 2.
	MaxParseDepth int
}

// DefaultAnalyzerConfig returns the default analyzer configuration.
func DefaultAnalyzerConfig() AnalyzerConfig {
	return AnalyzerConfig{
		EnabledAnalyzers: []string{"regex", "structural", "semantic"},
		CombineStrategy:  "most_restrictive",
		MaxParseDepth:    2,
	}
}

// fileConfig is the on-disk shape of ~/.agentshield/agentshield.yaml. Kept
// deliberately tiny — only fields that need cross-process persistence belong
// here (CLI flags + env vars cover one-shot overrides). New fields must have
// safe zero values so a partial/old file keeps working.
type fileConfig struct {
	Mode string `yaml:"mode,omitempty"`
}

// policyFileMode is a minimal subset of policy.yaml — just the top-level
// `enforcement_mode:` field. Used by config.Load to read the SaaS-pushed
// enforcement mode without forcing a full policy.Policy parse here (which
// would create a circular import with the policy package). New fields on
// the policy struct don't change this — yaml.Unmarshal silently skips
// unknown fields. Issue #1952.
type policyFileMode struct {
	EnforcementMode string `yaml:"enforcement_mode,omitempty"`
}

// NormalizeMode validates a mode string and returns the canonical value.
// Unrecognized values (including typos in YAML) coerce to ModeEnforce; the
// boolean return reports whether the input was a recognized mode. Callers
// that care (e.g. config load) can use the boolean to emit a warning.
//
// Empty string returns (ModeEnforce, true) so a missing config field is
// treated as "user didn't say anything" rather than "user said a wrong
// thing." See issue #1952.
func NormalizeMode(m string) (string, bool) {
	switch m {
	case "", ModeEnforce:
		return ModeEnforce, true
	case ModeAuditOnly:
		return ModeAuditOnly, true
	default:
		return ModeEnforce, false
	}
}

func Load(policyPath, logPath, mode string) (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(homeDir, DefaultConfigDir)

	if err := ensureDir(configDir); err != nil {
		return nil, err
	}

	// Mode resolution (issue #1952): CLI flag wins, then agentshield.yaml,
	// then the SaaS-pushed policy.yaml's `enforcement_mode:` field, then the
	// enforce default. Local overrides (CLI / agentshield.yaml) always beat
	// the SaaS push so a developer can break-glass back to enforce without
	// waiting for the SaaS toggle to flip.
	resolvedMode := mode
	if resolvedMode == "" {
		if fc := loadFileConfig(configDir); fc != nil && fc.Mode != "" {
			resolvedMode = fc.Mode
		}
	}
	if resolvedMode == "" {
		policyResolved := policyPath
		if policyResolved == "" {
			policyResolved = filepath.Join(configDir, DefaultPolicyFile)
		}
		if pm := loadPolicyEnforcementMode(policyResolved); pm != "" {
			resolvedMode = pm
		}
	}
	canonicalMode, ok := NormalizeMode(resolvedMode)
	if !ok {
		fmt.Fprintf(os.Stderr,
			"[AgentShield] warning: unrecognized mode %q — falling back to %q (issue #1952)\n",
			resolvedMode, ModeEnforce)
	}

	cfg := &Config{
		ConfigDir: configDir,
		Mode:      canonicalMode,
		Analyzer:  DefaultAnalyzerConfig(),
	}

	if policyPath != "" {
		cfg.PolicyPath = policyPath
	} else {
		cfg.PolicyPath = filepath.Join(configDir, DefaultPolicyFile)
	}

	if logPath != "" {
		cfg.LogPath = logPath
	} else {
		cfg.LogPath = filepath.Join(configDir, DefaultLogFile)
	}

	// Load managed.json if present
	cfg.Managed = LoadManaged(configDir)

	// In managed mode, ignore --policy and --log overrides
	if cfg.Managed != nil && cfg.Managed.Managed {
		cfg.PolicyPath = filepath.Join(configDir, DefaultPolicyFile)
		cfg.LogPath = filepath.Join(configDir, DefaultLogFile)
	}

	return cfg, nil
}

// loadPolicyEnforcementMode reads just the top-level `enforcement_mode:`
// from policy.yaml (the SaaS-pushed policy written by the enterprise sync).
// Returns "" if the file is missing, unparseable, or doesn't carry the
// field — any of those cases should fall through to the next resolution
// rung, never block startup. Issue #1952.
//
// Note: this deliberately re-reads the file even though policy.Policy
// (loaded later by the engine) has the same field. Avoiding the import of
// the policy package keeps config a leaf in the dependency graph and lets
// this run before policy validation.
func loadPolicyEnforcementMode(policyPath string) string {
	data, err := os.ReadFile(policyPath)
	if err != nil {
		return ""
	}
	var pm policyFileMode
	if err := yaml.Unmarshal(data, &pm); err != nil {
		return ""
	}
	return pm.EnforcementMode
}

// loadFileConfig reads ~/.agentshield/agentshield.yaml. Returns nil if the
// file is absent or unparseable — an unreadable config never kills startup.
// (A managed enterprise install that wants strictness can layer fail_closed
// on top via managed.json.)
func loadFileConfig(configDir string) *fileConfig {
	path := filepath.Join(configDir, DefaultConfigFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var fc fileConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		fmt.Fprintf(os.Stderr,
			"[AgentShield] warning: could not parse %s: %v — using defaults (issue #1952)\n",
			path, err)
		return nil
	}
	return &fc
}

// LoadManaged loads managed.json from the given config directory.
// Returns nil if the file doesn't exist or is invalid.
func LoadManaged(configDir string) *ManagedConfig {
	managedPath := filepath.Join(configDir, "managed.json")
	data, err := os.ReadFile(managedPath)
	if err != nil {
		return nil
	}
	var mc ManagedConfig
	if err := json.Unmarshal(data, &mc); err != nil {
		return nil
	}
	return &mc
}

func ensureDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	return nil
}
