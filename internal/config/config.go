package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

const (
	DefaultConfigDir  = ".agentshield"
	DefaultPolicyFile = "policy.yaml"
	DefaultLogFile    = "audit.jsonl"
)

type Config struct {
	PolicyPath string
	LogPath    string
	Mode       string
	ConfigDir  string
	Analyzer   AnalyzerConfig
	Managed    *ManagedConfig
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

func Load(policyPath, logPath, mode string) (*Config, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	configDir := filepath.Join(homeDir, DefaultConfigDir)

	if err := ensureDir(configDir); err != nil {
		return nil, err
	}

	cfg := &Config{
		ConfigDir: configDir,
		Mode:      mode,
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
