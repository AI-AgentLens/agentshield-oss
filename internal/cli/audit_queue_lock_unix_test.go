//go:build unix

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func queueLockHeldElsewhere(t *testing.T, dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open queue.lock: %v", err)
	}
	defer func() { _ = f.Close() }()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		unlockFd(int(f.Fd()))
		return false
	}
	return errors.Is(err, syscall.EWOULDBLOCK)
}
