//go:build unix

package cli

import "syscall"

// detachedProcAttr starts a child in a session of its own, so it outlives
// the hook that spawned it.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
