package enterprise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/safefile"
)

// CheckDisableAllowed returns an error if managed mode blocks hook removal.
func CheckDisableAllowed() error {
	if ManagedHost() {
		return fmt.Errorf("cannot disable hooks in managed mode — contact your IT administrator")
	}
	return nil
}

// ManagedHost reports whether this machine is centrally managed, by the same
// reading of managed.json that CheckDisableAllowed enforces. Callers pass it to
// the BLOCK hints in internal/policy/remediation, which take it as a parameter
// so the engine never reads enterprise config itself (#4321). Keeping one
// definition here is what stops the hint and the enforcement from drifting.
func ManagedHost() bool {
	cfg := LoadManagedConfig()
	return cfg != nil && cfg.Managed
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
//
// Returns nil only when the file does not exist. A file that exists but
// cannot be read or parsed is treated as managed with fail_closed set
// (#3620): every caller reads nil as "not managed", so returning nil for a
// corrupt enrollment let one bad byte turn pause and bypass back on. Same
// rule as config.LoadManaged; internal/cli pins the two to agree.
func LoadManagedConfigFrom(path string) *ManagedConfig {
	data, err := safefile.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return corruptManagedConfig(err)
	}
	var cfg ManagedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return corruptManagedConfig(err)
	}
	return &cfg
}

// corruptManagedConfig is the fail-closed reading of an unreadable or
// unparseable managed.json.
func corruptManagedConfig(cause error) *ManagedConfig {
	return &ManagedConfig{
		Managed:        true,
		FailClosed:     true,
		OrganizationID: fmt.Sprintf("unknown (managed.json unreadable: %v)", cause),
	}
}
