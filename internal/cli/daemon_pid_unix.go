//go:build unix

package cli

import (
	"os"
	"syscall"
)

// pidAlive reports whether the heartbeat daemon's process still runs.
func pidAlive(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

// stopPid asks the heartbeat daemon to exit.
func stopPid(proc *os.Process) {
	_ = proc.Signal(syscall.SIGTERM)
}
