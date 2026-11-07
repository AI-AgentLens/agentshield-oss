package mcp

import "testing"

// setTestHome points this test's home directory at dir. Production code reads
// it through os.UserHomeDir, which is $HOME on unix and %USERPROFILE% on
// Windows, so both are set; HOME alone left a Windows run looking at the real
// profile (#4717).
func setTestHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
}
