// Package homedir is the one place `agentshield setup` and the managed-mode
// check find a home directory (#4565).
//
// Before it, the setup surfaces built config paths from os.Getenv("HOME")
// while the managed check used os.UserHomeDir(). They disagree exactly when
// HOME is empty: the check errored and read "not managed", and the surfaces
// resolved their paths against the working directory. Run from inside a
// managed home, `HOME= agentshield setup <agent> --disable` unhooked the real
// configs. Every setup path and the managed check now go through Dir, so they
// cannot disagree about where home is, and an empty HOME is an error for both.
//
// Account answers a different question: the home directory of the account
// running the process, from the OS user database rather than the
// environment. Managed mode is a property of the account, so the check
// consults both (enterprise.ManagedHost). That closes the redirected-HOME
// variant: HOME=/elsewhere, run from the real home, where `setup mcp` also
// reads the working directory's .cursor/mcp.json.
package homedir

import (
	"errors"
	"os"
	"os/user"
)

// ErrNoHome is Dir's error when HOME is empty or unset.
var ErrNoHome = errors.New("HOME is empty or unset")

// Dir returns the home directory from the environment. On the platforms
// AgentShield ships for (darwin and linux, see .goreleaser.yaml) that is
// $HOME, and an empty or unset HOME is ErrNoHome.
//
// It is os.UserHomeDir with the error made explicit, so it agrees with
// config.Load, which finds ~/.agentshield the same way.
func Dir() (string, error) {
	h, err := os.UserHomeDir()
	if err != nil || h == "" {
		return "", ErrNoHome
	}
	return h, nil
}

// Account returns the home directory of the account running this process,
// from the OS user database. $HOME plays no part on darwin, measured with
// the release build (CGO_ENABLED=0): Go reads the user database through libc
// there, and returns the same directory with HOME empty, unset or pointed
// elsewhere (#4565).
//
// On linux a CGO_ENABLED=0 build reads /etc/passwd. An account missing from
// it falls back to $HOME when USER and HOME are set, and is an error
// otherwise. A caller that gets an error knows nothing about the account;
// enterprise.ManagedHost then uses $HOME alone, as before #4565, and does
// not deny on it (Gary, 2026-10-26).
//
// Known gaps, both measured on linux/arm64 with the release build in a
// container (#4565), and both leaving the managed check reading $HOME only:
//
//   - Directory-service accounts (LDAP, sssd, AD) are not in /etc/passwd, so
//     the pure-Go lookup falls back to $HOME, and HOME pointed elsewhere
//     hides the real home's managed.json. A cgo build would ask NSS.
//   - Accounts with no passwd entry at all (a container uid such as
//     `docker run -u 4242`): Account returns $HOME, or an error when USER is
//     unset, and either way the real home is unknown.
func Account() (string, error) {
	lookup := accountLookup
	if lookup == nil {
		lookup = userDatabaseHome
	}
	h, err := lookup()
	if err != nil {
		return "", err
	}
	if h == "" {
		return "", errors.New("the user database has no home directory for this account")
	}
	return h, nil
}

// accountLookup is Account's source. Tests point it at a scratch directory
// with SetAccountLookupForTest, so they never read the developer's real home.
// A nil value means userDatabaseHome.
var accountLookup = userDatabaseHome

func userDatabaseHome() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// SetAccountLookupForTest replaces Account's source and returns a function
// that restores the previous one. It exists for tests: a test that needs the
// account's home to differ from $HOME cannot change the real user database.
func SetAccountLookupForTest(f func() (string, error)) (restore func()) {
	prev := accountLookup
	accountLookup = f
	return func() { accountLookup = prev }
}

// ErrNotSudo is SudoInvoker's error when SUDO_USER names no one, or root.
var ErrNotSudo = errors.New("not run through sudo by another account")

// SudoInvoker returns the home directory of the account that ran sudo, from
// SUDO_USER and the OS user database. Under sudo, Dir and Account can both
// name root's home (sudo may reset HOME, and the process runs as root), so a
// check that asks "is this account enrolled" reads root. An administrator
// command that would switch AgentShield off for the machine asks this too
// (enterprise.CheckManagedRemovalAllowed).
//
// Its only use is to add a refusal. An error, including no sudo at all (an MDM
// script running as root), means nothing is known and refuses nothing.
// SUDO_USER is set by sudo; a caller who unsets it already has root.
func SudoInvoker() (string, error) {
	lookup := sudoInvokerLookup
	if lookup == nil {
		lookup = sudoUserHome
	}
	h, err := lookup()
	if err != nil {
		return "", err
	}
	if h == "" {
		return "", errors.New("the user database has no home directory for SUDO_USER")
	}
	return h, nil
}

var sudoInvokerLookup = sudoUserHome

func sudoUserHome() (string, error) {
	name := os.Getenv("SUDO_USER")
	if name == "" || name == "root" {
		return "", ErrNotSudo
	}
	u, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return u.HomeDir, nil
}

// SetSudoInvokerLookupForTest replaces SudoInvoker's source and returns a
// function that restores it, so tests never consult the real SUDO_USER.
func SetSudoInvokerLookupForTest(f func() (string, error)) (restore func()) {
	prev := sudoInvokerLookup
	sudoInvokerLookup = f
	return func() { sudoInvokerLookup = prev }
}
