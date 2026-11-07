//go:build windows

package winlock

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errLockViolation        = syscall.Errno(33) // ERROR_LOCK_VIOLATION
)

// LockFileEx locks are mandatory: a locked byte cannot be read or written
// through any other handle, even one in the same process. Locking the file's
// contents would make the tool registry's os.ReadFile of its own locked file
// fail. So the lock covers one byte far past any real end of file (SQLite's
// trick): nothing reads or writes there, and the lock serializes only the
// processes that take it, like flock.
const (
	lockOffsetHigh = 0x7FFFFFFF
	lockLength     = 1
)

// ErrBusy is returned by TryLock when another handle holds the lock.
var ErrBusy = errors.New("winlock: lock held by another handle")

// Lock takes the exclusive lock on f, waiting as long as it takes.
func Lock(f *os.File) error {
	return lockFileEx(f, lockfileExclusiveLock)
}

// TryLock takes the exclusive lock on f without waiting. It returns ErrBusy
// when another handle holds it and any other error when f cannot be locked.
func TryLock(f *os.File) error {
	err := lockFileEx(f, lockfileExclusiveLock|lockfileFailImmediately)
	if errors.Is(err, errLockViolation) {
		return ErrBusy
	}
	return err
}

// Unlock releases a lock taken through the same handle. Closing the handle
// releases it too.
func Unlock(f *os.File) error {
	r1, _, e1 := syscall.SyscallN(procUnlockFileEx.Addr(), f.Fd(), 0, lockLength, 0, uintptr(unsafe.Pointer(lockRegion())))
	return result(r1, e1)
}

func lockFileEx(f *os.File, flags uintptr) error {
	r1, _, e1 := syscall.SyscallN(procLockFileEx.Addr(), f.Fd(), flags, 0, lockLength, 0, uintptr(unsafe.Pointer(lockRegion())))
	return result(r1, e1)
}

func lockRegion() *syscall.Overlapped {
	return &syscall.Overlapped{OffsetHigh: lockOffsetHigh}
}

func result(r1 uintptr, e1 syscall.Errno) error {
	switch {
	case r1 != 0:
		return nil
	case e1 != 0:
		return e1
	default:
		return syscall.EINVAL
	}
}
