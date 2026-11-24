package mcp

import (
	"os"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// setTestHome points this test's home directory at dir. Production code reads
// it through os.UserHomeDir, which is $HOME on unix and %USERPROFILE% on
// Windows, so both are set; HOME alone left a Windows run looking at the real
// profile (#4717).
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	testhome.Set(t, dir)
	t.Setenv("USERPROFILE", dir)
}

// guardHome is the home directory the config guard anchored its patterns to
// at package init, in the platform's own spelling: os.UserHomeDir, which is
// $HOME on unix and %USERPROFILE% on Windows. A test that builds a protected
// path from os.Getenv("HOME") names nothing on Windows, where HOME is
// normally unset, so it checked "/.bashrc" instead of the user's (#5021).
// "" when there is no home, as os.Getenv("HOME") was; on unix the two are the
// same value.
func guardHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}
