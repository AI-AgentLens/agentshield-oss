//go:build !unix

package logger

import "os"

// openTail is a plain open where the package has no O_NONBLOCK to pass
// (see open_tail_unix.go): windows, and any other non-unix GOOS. Windows
// named pipes live in their own namespace (\\.\pipe\), not at a file path.
func openTail(path string) (*os.File, error) { return os.Open(path) }
