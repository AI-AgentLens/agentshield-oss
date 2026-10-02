//go:build unix

package logger

import (
	"os"
	"syscall"
)

// unlinked reports whether the open file f has no name left in any
// directory (link count zero). The check is nlink, not os.SameFile against
// the live path, because the two answer different questions. After one
// rotation the held inode is <path>.1: not the live file, but retained, so
// a line written there is kept and must not be appended a second time.
// After two rotations the inode is unlinked and every byte written to it
// is in no retained file; nlink 0 is permanent, an inode never regains a
// name. Only that second state justifies re-appending (#4057 Codex pass 1).
//
// False when the stat fails or the platform stat carries no link count:
// "unknown" must not trigger a re-append, which would duplicate the entry.
func unlinked(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Nlink == 0
}
