//go:build !windows

package logger

import "os"

// openIdentity is openTail off Windows. POSIX has no share modes, so an open
// handle never blocks a rename, and the identity read is unchanged from #5040.
func openIdentity(path string) (*os.File, error) { return openTail(path) }
