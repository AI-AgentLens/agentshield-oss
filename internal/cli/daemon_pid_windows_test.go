//go:build windows

package cli

import (
	"os"
	"os/exec"
	"testing"
)

// The heartbeat liveness check must see a running process as alive and an
// exited one as gone; on Windows the unix signal-0 probe said "gone" for
// both, so the hook started a new daemon on every tool call (#4717).
func TestPidAlive_Windows(t *testing.T) {
	self, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if !pidAlive(self) {
		t.Fatal("this test process reported as not running")
	}

	cmd := exec.Command("cmd", "/c", "exit", "0")
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
