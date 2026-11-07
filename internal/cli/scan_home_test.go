package cli

import (
	"runtime"
	"testing"
)

// scan's config-guard check finds the user's home the way the guard does
// (homedir.Dir), so it passes where HOME is unset, as in a normal Windows
// PowerShell. Built from $HOME it checked "/.bashrc" there and reported the
// guard as failing, though the guard blocks the real path (#4717).
func TestScanShellProfileGuardBlocks_WithoutHOME_4717(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("HOME", "")
	}
	if !scanShellProfileGuardBlocks() {
		t.Fatal("scan's guard check reports a write to ~/.bashrc as not blocked")
	}
}
