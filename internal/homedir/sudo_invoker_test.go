package homedir

import (
	"errors"
	"os/user"
	"testing"
)

// SudoInvoker reads SUDO_USER through the user database. No sudo, and sudo
// by root, are ErrNotSudo; an unknown name is an error; a real account gives
// that account's home.
func TestSudoInvoker_ReadsSUDO_USER(t *testing.T) {
	t.Setenv("SUDO_USER", "")
	if _, err := SudoInvoker(); !errors.Is(err, ErrNotSudo) {
		t.Errorf("no SUDO_USER: err = %v; want ErrNotSudo", err)
	}
	t.Setenv("SUDO_USER", "root")
	if _, err := SudoInvoker(); !errors.Is(err, ErrNotSudo) {
		t.Errorf("SUDO_USER=root: err = %v; want ErrNotSudo", err)
	}
	t.Setenv("SUDO_USER", "no-such-account-agentshield-test")
	if h, err := SudoInvoker(); err == nil {
		t.Errorf("unknown SUDO_USER: got %q, nil; want an error", h)
	}
	me, err := user.Current()
	if err != nil || me.Username == "root" {
		t.Skip("needs a non-root account in the user database")
	}
	t.Setenv("SUDO_USER", me.Username)
	if h, err := SudoInvoker(); err != nil || h != me.HomeDir {
		t.Errorf("SUDO_USER=%s: got %q, %v; want %q", me.Username, h, err, me.HomeDir)
	}
}

// The test seam replaces the lookup and restores it.
func TestSetSudoInvokerLookupForTest(t *testing.T) {
	restore := SetSudoInvokerLookupForTest(func() (string, error) { return "/fake/home", nil })
	if h, err := SudoInvoker(); err != nil || h != "/fake/home" {
		t.Errorf("faked: got %q, %v", h, err)
	}
	restore()
	t.Setenv("SUDO_USER", "")
	if _, err := SudoInvoker(); !errors.Is(err, ErrNotSudo) {
		t.Errorf("restored: err = %v; want ErrNotSudo", err)
	}
}
