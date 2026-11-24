//go:build !unix && !windows

package logger

import "os"

// openLogFile opens the audit log. Shield ships for unix and windows
// (logfile_unix.go, logfile_windows.go); this keeps other GOOS values
// building.
func openLogFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0600)
}

// rotatedInTheWay treats every failed rename as one <path>.1 may be in the
// way of, which keeps main's outcome here: <path>.1 is removed and the
// rename retried.
func rotatedInTheWay(error) bool { return true }
