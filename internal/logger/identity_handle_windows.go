//go:build windows

package logger

import (
	"os"
	"syscall"
)

// fileReadAttributes is FILE_READ_ATTRIBUTES: enough for
// GetFileInformationByHandle, which is all (*os.File).Stat needs to load the
// volume serial and file index that os.SameFile compares.
const fileReadAttributes = 0x80

// openIdentity opens path only to read its identity. It asks for attribute
// access and grants every share mode, so it can never block a rotation's
// rename or delete of the live file.
//
// openTail (os.Open) asks for read access without FILE_SHARE_DELETE. A hook
// rotating while that snapshot handle was open would fail its rename, and on
// main's remove-then-rename order it would already have deleted audit.jsonl.1
// (Codex pass on #5040). FILE_FLAG_BACKUP_SEMANTICS lets the open succeed on a
// directory too, so a directory at the path still yields its identity.
func openIdentity(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := syscall.CreateFile(p, fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
