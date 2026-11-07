package logger

import "time"

// Bounds on how long a writer waits for the audit log lock. Losing the lock
// race must never stall an agent: after lockWaitBudget we give up and append
// anyway. A chain gap is recoverable evidence; a hung hook is not.
const (
	lockWaitBudget   = 100 * time.Millisecond
	lockRetryBackoff = 2 * time.Millisecond
)
