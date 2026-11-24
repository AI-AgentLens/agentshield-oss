//go:build !unix && !windows

package logger

import "os"

// unlinked is always false where the package has no link count to read (see
// unlinked_unix.go and logfile_windows.go). Shield ships for unix and
// windows; this keeps other GOOS values building.
func unlinked(_ *os.File) bool { return false }
