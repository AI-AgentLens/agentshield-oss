// Package safefile reads files the hook needs for its verdict without letting
// a planted non-file hold the verdict (#4478, same class as #4474 / #4057).
//
// It is a leaf (standard library only) so the core packages that load policy
// and packs may import it; internal/logger.ReadRegularFileCapped is the
// capped variant for small files above the core.
package safefile

import (
	"errors"
	"io"
	"io/fs"
)

// ErrNotRegular is returned for a FIFO, device, socket or directory. It is
// deliberately not fs.ErrNotExist: a caller that reads a missing file as
// "absent" must still see a planted non-file as unreadable.
var ErrNotRegular = errors.New("not a regular file")

// ReadFile is a drop-in for os.ReadFile. It opens with O_NONBLOCK (unix) so
// open(2) on a FIFO with no writer returns at once, and takes the kind from
// the open descriptor, so a swap between a stat and the open changes nothing.
// A non-regular file returns an *fs.PathError wrapping ErrNotRegular. A
// missing file still satisfies errors.Is(err, fs.ErrNotExist). A symlink is
// followed and its target must be a regular file. There is no size cap: a cap
// that dropped a large pack would lower decisions, and the hang needs only the
// kind check. Every call site keeps the failure branch it already had for an
// unreadable file, so no decision semantics change.
func ReadFile(path string) ([]byte, error) {
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, &fs.PathError{Op: "read", Path: path, Err: ErrNotRegular}
	}
	return io.ReadAll(f)
}
