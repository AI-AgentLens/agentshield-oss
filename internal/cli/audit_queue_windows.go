//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/winlock"
)

// The Windows half of audit_queue_unix.go: the same contracts on a
// LockFileEx lock (#4717). Each function's unix comment is the spec.

// openRegularNoFollow opens path without following a symlink and refuses
// anything that is not a regular file. Windows has no O_NOFOLLOW, so a
// symlink is refused by Lstat before the open. A swap between the two is a
// window unix does not have; it is accepted because creating a symlink on
// Windows needs admin rights or Developer Mode.
func openRegularNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s: %w (symlink)", filepath.Base(path), errAuditQueueUnusable)
	}
	f, err := os.OpenFile(path, flag, perm)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w (not a regular file)", filepath.Base(path), errAuditQueueUnusable)
	}
	return f, nil
}

// auditQueueRecordable reports whether the uploader could record progress.
// Windows has no access(2). A file's write bits there mirror its read-only
// attribute, and a directory's read-only attribute does not stop creating
// files in it, so the check is: dir is a directory, and state.jsonl is
// absent or a regular file without the read-only attribute. An ACL that
// denies writing is not seen here.
func auditQueueRecordable(dir string) bool {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return false
	}
	st, err := os.Lstat(filepath.Join(dir, auditStateFileName))
	if os.IsNotExist(err) {
		return true
	}
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o200 != 0
}

// auditFlusherRunning probes flush.lock without waiting.
func auditFlusherRunning(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	err = winlock.TryLock(f)
	if err == nil {
		_ = winlock.Unlock(f)
	}
	return errors.Is(err, winlock.ErrBusy)
}

// lockAuditQueue takes queue.lock, waiting at most wait; past the budget, or
// when the file cannot be locked, the caller proceeds unlocked.
func lockAuditQueue(dir string, wait time.Duration) func() {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	deadline := time.Now().Add(wait)
	for {
		err := winlock.TryLock(f)
		switch {
		case err == nil:
			return func() { _ = winlock.Unlock(f); _ = f.Close() }
		case errors.Is(err, winlock.ErrBusy) && time.Now().Before(deadline):
			time.Sleep(2 * time.Millisecond)
		default:
			_ = f.Close()
			return func() {}
		}
	}
}

// tryLockFlush takes flush.lock without waiting; ok is false only when
// another uploader holds it.
func tryLockFlush(dir string) (release func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true
	}
	released := false
	release = func() {
		if !released {
			released = true
			_ = winlock.Unlock(f)
			_ = f.Close()
		}
	}
	err = winlock.TryLock(f)
	if errors.Is(err, winlock.ErrBusy) {
		_ = f.Close()
		return nil, false
	}
	return release, true
}
