//go:build unix

package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// openRegularNoFollow opens path without following a symlink and refuses
// anything that is not a regular file (a FIFO, a device, a directory).
func openRegularNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, perm)
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

// auditQueueRecordable reports whether the uploader could record progress:
// the directory is writable (state.jsonl is replaced by rename) and
// state.jsonl, if present, is a writable regular file. Two syscalls.
func auditQueueRecordable(dir string) bool {
	if syscall.Access(dir, 2 /* W_OK */) != nil {
		return false
	}
	st, err := os.Lstat(filepath.Join(dir, auditStateFileName))
	if os.IsNotExist(err) {
		return true
	}
	return err == nil && st.Mode().IsRegular() && syscall.Access(filepath.Join(dir, auditStateFileName), 2) == nil
}

// auditFlusherRunning probes flush.lock without waiting. A probe that cannot
// tell (the lock file will not open) answers "not running": the uploader it
// leads to starting runs unlocked in that case (tryLockFlush).
func auditFlusherRunning(dir string) bool {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			unlockFd(int(f.Fd()))
			return false
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			return true
		default:
			return false
		}
	}
}

// lockAuditQueue takes queue.lock, waiting at most wait. It always returns a
// release function; past the budget, or on a filesystem without flock, the
// release is a no-op and the caller proceeds unlocked.
func lockAuditQueue(dir string, wait time.Duration) func() {
	f, err := os.OpenFile(filepath.Join(dir, auditQueueLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	fd := int(f.Fd())
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return func() { unlockFd(fd); _ = f.Close() }
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK) && time.Now().Before(deadline):
			time.Sleep(2 * time.Millisecond)
		default:
			_ = f.Close()
			return func() {}
		}
	}
}

// tryLockFlush takes flush.lock without waiting; ok is false only when
// another uploader holds it. When the lock cannot be taken for any other
// reason (the file will not open, e.g. its mode was changed to 000, or the
// filesystem has no flock) it proceeds unlocked: a second uploader then costs
// repeats the SaaS drops, while refusing would leave the queue undelivered for
// good (#4471 review).
func tryLockFlush(dir string) (release func(), ok bool) {
	f, err := os.OpenFile(filepath.Join(dir, auditFlushLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}, true
	}
	fd := int(f.Fd())
	released := false
	release = func() {
		if !released {
			released = true
			unlockFd(fd)
			_ = f.Close()
		}
	}
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return release, true
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK):
			_ = f.Close()
			return nil, false
		default:
			return release, true
		}
	}
}

func unlockFd(fd int) {
	for i := 0; i < 5; i++ {
		if err := syscall.Flock(fd, syscall.LOCK_UN); !errors.Is(err, syscall.EINTR) {
			return
		}
	}
}
