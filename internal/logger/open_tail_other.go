//go:build !unix

package logger

import "os"

// openTail is a plain open where the package has no O_NONBLOCK to pass
// (see open_tail_unix.go). Released builds target darwin and linux only.
func openTail(path string) (*os.File, error) { return os.Open(path) }
