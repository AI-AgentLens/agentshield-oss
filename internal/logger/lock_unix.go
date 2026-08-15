//go:build unix

package logger

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// Bounds on how long a writer waits for the audit log lock. Losing the lock
// race must never stall an agent: after lockWaitBudget we give up and append
// anyway. A chain gap is recoverable evidence; a hung hook is not.
const (
	lockWaitBudget   = 100 * time.Millisecond
	lockRetryBackoff = 2 * time.Millisecond
)

// lockFile takes an exclusive advisory (flock) lock on f and returns the
// release function. The returned function is always safe to call.
//
// The lock is what makes the hash chain survive multiple concurrent
// agentshield processes sharing one audit.jsonl (parallel IDE hook
// invocations, the MCP proxy, the watchdog): it makes "read the chain head,
// append the next entry" atomic across processes. Without it each process
// would append an entry claiming the same prev_hash and the chain would read
// as broken after any parallel tool call.
//
// EINTR is retried rather than treated as failure: syscall.Flock is a raw
// syscall wrapper with no restart logic, and the Go runtime delivers signals
// (SIGURG for async preemption) that can interrupt it. Treating that as "this
// filesystem has no locking" would silently append unlocked.
//
// Best effort by design. If the filesystem does not implement flock, or the
// lock is still held when the budget runs out, we return a no-op release and
// the caller appends anyway.
func lockFile(f *os.File) func() {
	if f == nil {
		return func() {}
	}
	fd := int(f.Fd())
	deadline := time.Now().Add(lockWaitBudget)

	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return func() { unlockFile(fd) }
		case errors.Is(err, syscall.EINTR):
			continue // interrupted by a signal, not contention
		case errors.Is(err, syscall.EWOULDBLOCK):
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr,
					"[AgentShield] warning: audit log lock busy for %s; appending unlocked (hash chain may show a break)\n",
					lockWaitBudget)
				return func() {}
			}
			time.Sleep(lockRetryBackoff)
		default:
			// Filesystem does not implement advisory locking (some network
			// mounts). Nothing to release.
			return func() {}
		}
	}
}

// unlockFile releases the advisory lock, retrying through signal interruption.
// A lock left held would block every other writer for their full budget.
func unlockFile(fd int) {
	for i := 0; i < 5; i++ {
		err := syscall.Flock(fd, syscall.LOCK_UN)
		if !errors.Is(err, syscall.EINTR) {
			return
		}
	}
}
