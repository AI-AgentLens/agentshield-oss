//go:build unix

package logger

import (
	"os"
	"syscall"
)

// openTail opens path for the tail read behind ChainHead without ever
// blocking in open(2). O_NONBLOCK makes the open of a FIFO return at once
// instead of waiting for a writer; a regular file is unaffected by the flag
// (pread never returns EAGAIN on one). The regular-file check is made on
// the open descriptor, so a symlink to a regular rotated file still reads
// (fstat follows the link) and a name swapped between a stat and the open
// cannot change what was checked (#4134 names that race).
func openTail(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
