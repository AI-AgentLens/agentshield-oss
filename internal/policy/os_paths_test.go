package policy

import (
	"os"
	"path/filepath"
	"runtime"
)

// Test-only spellings for tests that run on Windows too (#5021). Both are the
// identity on unix, so a unix run sees byte-for-byte the strings it saw before.

// shellPath spells an OS path for splicing into shell text: slash form. Bash
// reads each backslash of `C:\Users\x` as an escape, so the Windows spelling
// never reaches the product as written; `C:/Users/x` does, and is the same
// absolute path to Windows.
func shellPath(p string) string { return filepath.ToSlash(p) }

// absPath spells a POSIX-absolute test path ("/tmp", "/home/tester") as an
// absolute path on this OS: on Windows a path with no volume is not
// filepath.IsAbs, so it gets the temp directory's volume ("C:/tmp"). Slash
// form, so it splices into shell text as is. A volume-less `/x` is itself
// read on the cwd's drive on Windows (#5021 P-c, pathnorm.Resolve), so from a
// cwd on the temp directory's drive both spellings name one file; a test whose
// subject is not that reading spells its paths with this.
func absPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	return filepath.VolumeName(os.TempDir()) + p
}

// osPath is the OS spelling the product returns for a slash-form absolute
// path, for comparing against what absPath and shellPath spliced in.
func osPath(p string) string { return filepath.FromSlash(p) }
