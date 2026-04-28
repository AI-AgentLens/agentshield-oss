package enterprise

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CheckDisableAllowed returns an error if managed mode blocks hook removal.
func CheckDisableAllowed() error {
	cfg := LoadManagedConfig()
	if cfg != nil && cfg.Managed {
		return fmt.Errorf("cannot disable hooks in managed mode — contact your IT administrator")
	}
	return nil
}

// LoadManagedConfig loads managed.json from the default config directory.
// Returns nil if the file doesn't exist or is invalid.
func LoadManagedConfig() *ManagedConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return LoadManagedConfigFrom(filepath.Join(home, ".agentshield", "managed.json"))
}

// LoadManagedConfigFrom loads managed.json from the given path.
// Returns nil if the file doesn't exist or is invalid.
func LoadManagedConfigFrom(path string) *ManagedConfig {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var cfg ManagedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	return &cfg
}
