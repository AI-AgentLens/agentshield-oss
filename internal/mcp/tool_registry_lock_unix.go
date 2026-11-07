//go:build unix

package mcp

import (
	"os"
	"syscall"
)

// lockRegistry takes the registry file's exclusive lock, waiting for it.
func lockRegistry(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
}

func unlockRegistry(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
