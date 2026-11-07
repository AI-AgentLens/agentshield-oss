//go:build windows

package cli

import (
	"os"
	"syscall"
)

const (
	processQueryLimitedInformation = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
	stillActive                    = 259    // STILL_ACTIVE
)

// pidAlive reports whether the heartbeat daemon's process still runs.
// Windows has no signal 0: os.Process.Signal supports only Kill there, so the
// unix check always answered "not running", and every hook call started
// another heartbeat daemon (#4717). Ask for the process's exit code instead.
func pidAlive(proc *os.Process) bool {
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(proc.Pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(h)
	var code uint32
	if err := syscall.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == stillActive
}

// stopPid ends the heartbeat daemon. Windows has no SIGTERM to send.
func stopPid(proc *os.Process) {
	_ = proc.Kill()
}
