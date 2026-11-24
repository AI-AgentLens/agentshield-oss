package logger

import (
	"errors"
	"os"
	"testing"
)

// fileIdentity returns the identity of the file at path, read from an open
// handle, or nil when there is no file there. Tests use it to tell whether a
// rotation replaced <path>.1 between two writes.
//
// Not os.Stat: on Windows the FileInfo os.Stat returns carries no file id.
// os.SameFile fetches it later, by opening the path at comparison time, so
// two os.Stat results of one path compare equal whenever that path names a
// file at the moment of the comparison, even if a rotation replaced it in
// between (#5021). A test that counted rotations that way counted only the
// first one. f.Stat on an open handle reads the id at once on Windows, and on
// unix both calls give the same dev and inode, so unix behaviour is unchanged.
func fileIdentity(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info
}

// replacedSince reports whether the file now at path is present and is not
// the one before identifies (a nil before means there was none).
func replacedSince(t *testing.T, before os.FileInfo, path string) bool {
	t.Helper()
	after := fileIdentity(t, path)
	return after != nil && (before == nil || !os.SameFile(before, after))
}
