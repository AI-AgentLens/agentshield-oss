//go:build windows

package logger

import (
	"errors"
	"os"
	"syscall"
)

// How the audit log behaves on Windows (#5038). Three pieces, one story.
//
// Windows refuses to rename or delete a file while any handle on it was
// opened without FILE_SHARE_DELETE, and Go's os.OpenFile never passes that
// flag (syscall.Open: FILE_SHARE_READ|FILE_SHARE_WRITE). Every hook process,
// the watchdog and shield-server hold audit.jsonl through New, so while any
// one of them was alive a sibling's rotation failed: the live file grew past
// maxLogBytes on every write, and rotateIfNeeded's os.Remove of <path>.1,
// which ran before the rename, deleted the predecessor on the first failed
// attempt. Executed on Windows 10 22H2: a second process holding the log
// through New was enough.
//
//   - openLogFile opens with FILE_SHARE_DELETE, so the logger's own handles
//     no longer block a rename. The rename then behaves as on unix: the held
//     handle follows the file to <path>.1, and followRotation reopens the
//     live path on that writer's next write, the branch unix already relies
//     on.
//   - Windows will not replace a target that is still open, even when every
//     handle on it allows delete (MoveFileEx with MOVEFILE_REPLACE_EXISTING
//     fails with ERROR_ACCESS_DENIED). After one rotation a writer that has
//     not written since still holds <path>.1. Deleting it is allowed, and
//     the name goes at once; the holder keeps its handle on a file with no
//     name, as unix keeps an unlinked inode. rotatedInTheWay says when the
//     rename failed for that reason, so rotate removes <path>.1 and renames
//     again, and only then.
//   - unlinked reads the link count off the handle, so the degraded writer's
//     re-append (reappendIfUnlinked) sees a held file that a second rotation
//     deleted. Before this it was always false here, which was harmless only
//     while a held file could not be deleted at all.
//
// A handle opened without FILE_SHARE_DELETE still blocks rotation: the MCP
// proxy's own os.OpenFile (internal/cli/mcp_proxy.go), a verifier or
// `agentshield log` mid-read, or another program. The rename then fails with
// ERROR_SHARING_VIOLATION, not ERROR_ACCESS_DENIED, even when <path>.1 is
// also held (executed), so <path>.1 is kept and the next write retries.

// fileWriteEA is syscall's unexported _FILE_WRITE_EA: part of the access mask
// syscall.Open grants an O_APPEND open.
const fileWriteEA = 0x00000010

// openLogFile is os.OpenFile(path, flag, 0600) for the two flag sets openLog
// uses (O_APPEND|O_CREATE with O_RDWR or O_WRONLY), with FILE_SHARE_DELETE
// added to the share mode. Everything else is syscall.Open's choice for those
// flags: the O_APPEND access mask without FILE_WRITE_DATA, so every write
// lands at the end of the file; OPEN_ALWAYS; a handle that child processes
// do not inherit; FILE_ATTRIBUTE_NORMAL for a 0600 file.
//
// When that open fails, os.OpenFile is tried as before. It returns the error
// New has always returned, and it opens the paths this call cannot, such as
// one longer than MAX_PATH, which os.OpenFile prefixes and this call does
// not. A log opened that way is held without FILE_SHARE_DELETE: rotation is
// blocked while it is held, as it was for every handle before #5038, and no
// entry is lost.
func openLogFile(path string, flag int) (*os.File, error) {
	if f, err := createShareDelete(path, flag); err == nil {
		return f, nil
	}
	return os.OpenFile(path, flag, 0600)
}

func createShareDelete(path string, flag int) (*os.File, error) {
	access := uint32(syscall.FILE_APPEND_DATA | syscall.FILE_WRITE_ATTRIBUTES | fileWriteEA | syscall.STANDARD_RIGHTS_WRITE | syscall.SYNCHRONIZE)
	switch flag {
	case os.O_APPEND | os.O_CREATE | os.O_RDWR:
		access |= syscall.GENERIC_READ
	case os.O_APPEND | os.O_CREATE | os.O_WRONLY:
	default:
		return nil, errors.New("openLogFile: unsupported flags")
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const share = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE | syscall.FILE_SHARE_DELETE
	h, err := syscall.CreateFile(name, access, share, nil, syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if h == syscall.InvalidHandle {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

// rotatedInTheWay reports whether a failed rename of the live log onto
// <path>.1 was refused because of what is at <path>.1: ERROR_ACCESS_DENIED.
// That is the error for a <path>.1 still open elsewhere, a read-only one, and
// a directory, and in each case main's os.Remove-first order removed it (or
// failed to, keeping it). A source that cannot be renamed because another
// handle holds it without FILE_SHARE_DELETE is ERROR_SHARING_VIOLATION, and
// then <path>.1 must not be touched: the rename will fail again.
func rotatedInTheWay(err error) bool {
	return errors.Is(err, syscall.ERROR_ACCESS_DENIED)
}

// unlinked is unlinked_unix.go's contract on Windows: whether the open file
// f has no name left in any directory. With FILE_SHARE_DELETE a held file
// can be deleted, and the handle then reports a link count of 0. A rename
// keeps it at 1. Executed on Windows 10 22H2 (NTFS) for both a POSIX delete
// (os.Remove) and a legacy delete-pending one. False when the count cannot
// be read: "unknown" must not trigger a re-append, which would duplicate the
// entry.
func unlinked(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	var d syscall.ByHandleFileInformation
	var gerr error
	if err := rc.Control(func(fd uintptr) {
		gerr = syscall.GetFileInformationByHandle(syscall.Handle(fd), &d)
	}); err != nil || gerr != nil {
		return false
	}
	return d.NumberOfLinks == 0
}
