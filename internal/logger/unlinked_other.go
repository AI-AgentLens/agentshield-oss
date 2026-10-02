//go:build !unix

package logger

import "os"

// unlinked is always false where the package has no link count to read
// (see unlinked_unix.go). Released builds target darwin and linux only.
func unlinked(_ *os.File) bool { return false }
