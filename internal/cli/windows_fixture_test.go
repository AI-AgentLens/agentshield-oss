package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"testing"
)

// Fixture helpers that let the package's tests describe the same install on
// Windows as on macOS and Linux (#5021). Off Windows each one is exactly what
// the tests did before, so no assertion there changes.

// exeName is the file name of a program called name on this OS. On Windows
// exec.LookPath finds a program only under a PATHEXT extension, so a stand-in
// written as plain "agentshield" is not found there and setup falls back to
// the test binary's own path. A real Windows install is agentshield.exe.
func exeName(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// fixtureInstallPath is an absolute path to an agentshield binary that need
// not exist, for tests that hand setup a binPath. Off Windows it is the
// Homebrew path the tests always used; on Windows "/opt/..." has no drive and
// is not absolute, so it is the same path under the system drive.
func fixtureInstallPath() string {
	if runtime.GOOS == "windows" {
		return `C:\opt\homebrew\bin\agentshield.exe`
	}
	return "/opt/homebrew/bin/agentshield"
}

// symlinkOrSkip makes newname a symlink to oldname. On Windows creating one
// needs SeCreateSymbolicLinkPrivilege (Developer Mode or an elevated shell),
// and a host without it, such as aial-04's runner account, skips the test.
// Elsewhere a failure fails the test, as os.Symlink did before.
func symlinkOrSkip(t *testing.T, oldname, newname string) {
	t.Helper()
	if err := os.Symlink(oldname, newname); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("cannot create a symlink on this Windows host (it needs SeCreateSymbolicLinkPrivilege): %v", err)
		}
		t.Fatal(err)
	}
}

// canSymlink reports whether this host can create symlinks. Always true off
// Windows. A test that has rows without symlinks uses it to drop only the
// symlink rows on a Windows host that cannot make them.
func canSymlink(t *testing.T) bool {
	t.Helper()
	if runtime.GOOS != "windows" {
		return true
	}
	dir := t.TempDir()
	return os.Symlink(filepath.Join(dir, "target"), filepath.Join(dir, "link")) == nil
}

// modeBitsAreReal is false on Windows, where Go reports every writable file
// as 0666 and every directory as 0777 whatever mode it was created or
// chmodded with: Chmod sets only the read-only attribute, and access is
// governed by the ACL the file inherits. A test that checks the 0600 the
// code asks for checks it where it means something.
const modeBitsAreReal = runtime.GOOS != "windows"

// accessDeniedWords is how the file system words a refused open, as an
// error's text ends: EACCES's "permission denied" off Windows,
// ERROR_ACCESS_DENIED's "Access is denied." on Windows. A test that checks a
// record names the failure "in the file system's words" checks these.
var accessDeniedWords = func() string {
	if runtime.GOOS == "windows" {
		return "Access is denied."
	}
	return "permission denied"
}()

// denyListing is Windows's mode 000 for a directory: a deny ACE for the
// current user on FILE_LIST_DIRECTORY (icacls "(RD)"), so os.ReadDir fails
// with ERROR_ACCESS_DENIED, which errors.Is reports as fs.ErrPermission, as
// it does POSIX's EACCES. The ACE is removed at cleanup, which runs before
// t.TempDir's removal of the tree. A process holding SeBackupPrivilege
// enabled lists past the ACE, because Go opens a directory with backup
// semantics; the caller checks the listing fails.
func denyListing(t *testing.T, dir string) {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	sid := "*" + u.Uid // on Windows Uid is the account's SID
	if out, err := exec.Command("icacls", dir, "/deny", sid+":(RD)").CombinedOutput(); err != nil {
		t.Fatalf("icacls /deny: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("icacls", dir, "/remove:d", sid).CombinedOutput(); err != nil {
			t.Errorf("icacls /remove:d: %v\n%s", err, out)
		}
	})
}

// jsonString is s as a JSON string literal, for splicing a path into a
// payload built as text. Pasted raw, a Windows path's backslashes are JSON
// escapes (\U is invalid) and the hook reads no payload at all. Off Windows
// it is the quoted path, byte for byte.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// dotRootSpelling is the absolute path abs with a "." segment right after its
// root: "/." + abs off Windows, exactly the spelling the PowerShell-lane tests
// always built. On Windows "/." + C:\Users\... is no path at all, so there it
// is C:/./Users/..., in slash form like shellTextPaths.
func dotRootSpelling(abs string) string {
	if runtime.GOOS != "windows" {
		return "/." + abs
	}
	vol := filepath.VolumeName(abs)
	return filepath.ToSlash(vol + `\.` + abs[len(vol):])
}
