//go:build !unix && !windows

package logger

import "os"

// lockFile is a no-op on platforms without flock. The hash chain is still
// written and still detects edits; what it loses is cross-process
// serialization, so concurrent agentshield processes appending to one
// audit.jsonl can interleave and produce a chain break. The platforms Shield
// ships for all have a real lock: lock_unix.go and lock_windows.go.
func lockFile(_ *os.File) func() { return func() {} }
