//go:build windows

package logger

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/winlock"
)

// lockFile is lock_unix.go's contract on a LockFileEx lock: wait at most
// lockWaitBudget, then append unlocked rather than stall the agent.
func lockFile(f *os.File) func() {
	if f == nil {
		return func() {}
	}
	deadline := time.Now().Add(lockWaitBudget)

	for {
		err := winlock.TryLock(f)
		switch {
		case err == nil:
			return func() { _ = winlock.Unlock(f) }
		case errors.Is(err, winlock.ErrBusy):
			if time.Now().After(deadline) {
				fmt.Fprintf(os.Stderr,
					"[AgentShield] warning: audit log lock busy for %s; appending unlocked (hash chain may show a break)\n",
					lockWaitBudget)
				return func() {}
			}
			time.Sleep(lockRetryBackoff)
		default:
			return func() {}
		}
	}
}
