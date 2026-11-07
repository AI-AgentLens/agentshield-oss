//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/winlock"
)

func queueLockHeldElsewhere(t *testing.T, dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open queue.lock: %v", err)
	}
	defer func() { _ = f.Close() }()
	err = winlock.TryLock(f)
	if err == nil {
		_ = winlock.Unlock(f)
		return false
	}
	return errors.Is(err, winlock.ErrBusy)
}
