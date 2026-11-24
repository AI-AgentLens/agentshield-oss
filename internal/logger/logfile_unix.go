//go:build unix

package logger

import (
	"errors"
	"os"
	"syscall"
)

// openLogFile opens the audit log. On unix any open file can be renamed or
// unlinked, so the plain open is all rotation needs (see logfile_windows.go
// for why Windows differs).
func openLogFile(path string, flag int) (*os.File, error) {
	return os.OpenFile(path, flag, 0600)
}

// rotatedInTheWay reports whether a failed rename of the live log onto
// <path>.1 was refused because of what is at <path>.1. rename(2) replaces
// any file atomically, open or not, so only a directory there can refuse it.
// Go's os.Rename reports one as EEXIST before it calls rename(2); EISDIR and
// ENOTEMPTY are rename(2)'s own answers if a directory appears after that
// check. Main removed <path>.1 before every rename; that is what still
// happens for an empty directory, and for every other failure <path>.1 is
// now kept.
func rotatedInTheWay(err error) bool {
	return errors.Is(err, syscall.EISDIR) || errors.Is(err, syscall.EEXIST) || errors.Is(err, syscall.ENOTEMPTY)
}
