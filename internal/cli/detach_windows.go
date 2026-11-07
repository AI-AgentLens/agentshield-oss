//go:build windows

package cli

import "syscall"

// detachedProcess is DETACHED_PROCESS, which package syscall does not export.
const detachedProcess = 0x00000008

// detachedProcAttr starts a child with no console and in a process group of
// its own, so it outlives the hook and is not sent the agent's Ctrl+C.
func detachedProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess}
}
