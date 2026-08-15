//go:build !unix

package logger

import "os"

// lockFile is a no-op on platforms without flock. The hash chain is still
// written and still detects edits; what it loses is cross-process
// serialization, so concurrent agentshield processes appending to one
// audit.jsonl can interleave and produce a chain break. Released builds target
// darwin and linux only (see .github/workflows/ci-cd.yml).
func lockFile(_ *os.File) func() { return func() {} }
