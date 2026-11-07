//go:build unix

package cli

import (
	"os"
	"os/exec"
	"testing"
)

// pidAlive moved to daemon_pid_unix.go unchanged (#4717); pin it: a running
// process is alive, an exited one is not.
func TestPidAlive_Unix(t *testing.T) {
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !pidAlive(self) {
		t.Fatal("this test process reported as not running")
	}
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	child := cmd.Process
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if pidAlive(child) {
		t.Fatal("an exited process reported as running")
	}
}
