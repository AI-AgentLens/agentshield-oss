package enterprise

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/AI-AgentLens/agentshield/internal/homedir"
	"github.com/AI-AgentLens/agentshield/internal/safefile"
)

// CheckDisableAllowed returns an error if managed mode blocks hook removal.
func CheckDisableAllowed() error {
	if ManagedHost() {
		return fmt.Errorf("cannot disable hooks in managed mode — contact your IT administrator")
	}
	return nil
}

// CheckManagedRemovalAllowed returns an error when removing AgentShield's hook
// from Claude Code's machine-wide managed settings
// (`setup claude-code --remove-managed`) must be refused. It refuses wherever
// CheckDisableAllowed does, and also when the account that ran sudo is
// enrolled: the command needs administrator rights, and under sudo $HOME and
// the account lookup can both name root, so CheckDisableAllowed alone reads
// root's home and lets the removal through on an enrolled user's machine.
//
// Not refused: an MDM script or a root shell with no SUDO_USER, unless root's
// own home holds managed.json. That is the administrator's channel, and the
// documented decommission order unenrolls first. A failed SUDO_USER lookup is
// no evidence and refuses nothing, as in ManagedHost.
func CheckManagedRemovalAllowed() error {
	if err := CheckDisableAllowed(); err != nil {
		return err
	}
	if home, err := homedir.SudoInvoker(); err == nil && accountManaged(managedConfigPath(home)) {
		return fmt.Errorf("cannot remove AgentShield's managed hook: the account that ran sudo is enrolled in managed mode (%s) — unenroll it first, or contact your IT administrator", managedConfigPath(home))
	}
	return nil
}

// ManagedHost reports whether this machine is centrally managed, by the same
// reading of managed.json that CheckDisableAllowed enforces. Callers pass it to
// the BLOCK hints in internal/policy/remediation, which take it as a parameter
// so the engine never reads enterprise config itself (#4321). Keeping one
// definition here is what stops the hint and the enforcement from drifting.
//
// Managed is a property of the account, not of an environment variable
// (#4565). The host is managed when managed.json says so under $HOME or under
// the account's home from the OS user database (homedir.Account). Reading
// only $HOME let `HOME=/elsewhere agentshield setup mcp --disable`, run from
// the real home, unwrap the real home's .cursor/mcp.json, and an empty HOME
// read as "not managed" outright.
//
// The account half only ever adds a refusal. If the account lookup fails, or
// the account's managed.json cannot be read, for whatever reason, the check
// falls back to $HOME alone, which is main's behaviour, so a failure there
// cannot weaken anything versus main (Gary, 2026-10-26). It also denies
// nothing main allowed: an error is not evidence that the account is
// managed. Treating one as managed refused `setup --disable` on unmanaged
// hosts, such as a container uid with no passwd entry and USER unset, or a
// service account whose passwd home is a root-owned directory it cannot
// read. homedir.Account names the hosts where the lookup cannot see the
// account.
//
// The #3620 rule is unchanged for $HOME: an unreadable or corrupt
// $HOME/.agentshield/managed.json reads as managed. Under the account's home,
// corrupt content in a file that can be read still reads as managed: the
// file exists and is AgentShield's, which is evidence of enrollment.
//
// With HOME set to the account's home, as on any normal install, both reads
// are the same file and the answer is the one main gave.
func ManagedHost() bool {
	if cfg := LoadManagedConfig(); cfg != nil && cfg.Managed {
		return true
	}
	account, err := homedir.Account()
	if err != nil {
		return false
	}
	return accountManaged(managedConfigPath(account))
}

// accountManaged is ManagedHost's reading of managed.json under the
// account's home. Any read error (absent, permission denied, not a regular
// file) is no evidence and reads false, leaving $HOME's answer to stand.
// Content that cannot be parsed reads as managed, as in
// LoadManagedConfigFrom (#3620).
func accountManaged(path string) bool {
	data, err := safefile.ReadFile(path)
	if err != nil {
		return false
	}
	var cfg ManagedConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return true
	}
	return cfg.Managed
}

// LoadManagedConfig loads managed.json from $HOME/.agentshield, finding home
// with homedir.Dir, the resolver setup uses (#4565). Returns nil if HOME is
// empty or the file doesn't exist; a file that exists but is unreadable or
// invalid reads as managed (LoadManagedConfigFrom).
func LoadManagedConfig() *ManagedConfig {
	home, err := homedir.Dir()
	if err != nil {
		return nil
	}
	return LoadManagedConfigFrom(managedConfigPath(home))
}

// managedConfigPath is where managed.json lives under a home directory.
func managedConfigPath(home string) string {
	return filepath.Join(home, ".agentshield", "managed.json")
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
