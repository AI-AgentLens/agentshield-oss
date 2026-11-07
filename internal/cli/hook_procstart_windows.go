//go:build windows

package cli

import (
	"syscall"
	"time"
)

// processCreated is when Windows created this process (GetProcessTimes), the
// moment the harness's hook timeout starts counting (#4785). False when the
// call fails.
func processCreated() (time.Time, bool) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return time.Time{}, false
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	return time.Unix(0, created.Nanoseconds()), true
}
