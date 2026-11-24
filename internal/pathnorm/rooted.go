package pathnorm

import (
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// IsAbs reports whether p is an absolute path as the shell lane reads it:
// filepath.IsAbs, and on Windows also a rooted path with no drive, `/srv/x`
// or `\srv\x` (#5021 P-c). Off Windows it is filepath.IsAbs exactly.
//
// It answers "does p name a place without a cwd to join it onto?", which is
// what the callers gate on: a rooted cwd is usable, and a rooted word in a
// consumer's credential slot is a candidate. Where the place is, on Windows,
// is Resolve's question: a rooted path is on the cwd's drive.
func IsAbs(p string) bool {
	return filepath.IsAbs(p) || rootedFor(p, runtime.GOOS)
}

// rootedFor reports whether p is, on goos, a rooted path with no drive: on
// Windows a path that starts with one separator, `/srv/x` or `\srv\x`. Never off
// Windows, where filepath.IsAbs already says yes to `/x`, and `\x` is a
// relative name. A leading double separator is a UNC path, which
// filepath.IsAbs already reads as absolute on Windows.
func rootedFor(p, goos string) bool {
	return goos == "windows" && p != "" && isSlash(p[0]) && (len(p) == 1 || !isSlash(p[1]))
}

// Resolve returns the operand p read from the working directory cwd, joined
// but not cleaned, the way the shell lane resolves a path (#5021 P-c).
//
// Off Windows it is main's reading exactly: p when filepath.IsAbs, else
// filepath.Join(cwd, p).
//
// On Windows, in this order:
//  1. Git Bash's `/c/...` is drive C (FromMSYSDrive), wherever cwd is.
//  2. A rooted path with no drive, `/srv/x` or `\srv\x`, is on cwd's drive:
//     from any cwd on C:, `/srv/x` is `C:\srv\x`. That is what PowerShell 5.1
//     opens, from the drive's root and from a subdirectory alike, and what
//     cmd opens. Step 1 comes first, so a one-letter first segment is a
//     drive: `/x` is X:\, wherever cwd is.
//  3. A relative path is joined onto cwd.
//
// cwd is read by Cwd first. When it names no drive (it is empty, or rooted
// under a home that has none), a rooted p stays rooted, as written. A path
// put on a drive comes back clean, as a joined one does.
//
// # The cost, accepted (Gary, 2026-11-22)
//
// Git Bash opens a rooted `/srv/x` under its install root (`D:\Git\srv\x`),
// not on the cwd's drive, so for Bash text step 2 names a file Git Bash does
// not open. Spelled that way, a home path (`cat /Users/u/.ssh/id_rsa`) now BLOCKs
// by protected-path, on a command that fails in Git Bash because the file is
// not there. Before this, from a protected cwd (`~\.ssh`), main joined the
// path under the cwd and BLOCKed for that reason, and the reading that kept
// the path rooted lowered the PowerShell read, which opens the credential.
func Resolve(p, cwd, home string) string {
	if runtime.GOOS != "windows" {
		if !filepath.IsAbs(p) {
			return filepath.Join(cwd, p)
		}
		return p
	}
	cwd = Cwd(cwd, home)
	p = fromMSYSDriveFor(p, "windows")
	switch {
	case filepath.IsAbs(p):
		return p
	case rootedFor(p, "windows"):
		if q := onDriveFor(p, volumeFor(cwd, "windows"), "windows"); q != p {
			return filepath.Clean(q) // as a join would: C:\srv\x, not C:/srv/x
		}
		return p
	default:
		return filepath.Join(cwd, p)
	}
}

// Cwd returns the working directory cwd as the shell lane reads it, on
// Windows: Git Bash's `/c/...` is drive C, and a rooted cwd with no drive
// (`/srv/app`) is on home's drive. Every other cwd, and every cwd off Windows,
// is returned as written.
//
// # Why home's drive
//
// The hook never sends such a cwd: payloadEvalCwd falls back to the process's
// own directory, which has a drive, for a payload cwd that is not
// filepath.IsAbs. One comes from a remote client (shield-server's request) or
// a test. Home's drive is the one `~` expands on, and every shipped
// protected_paths pattern but the system trees is anchored at `~`, so it is
// the drive where reading the wrong one could hide a protected read. It is
// already an input of both layers, and it is fixed for a process. A home
// with no drive (a POSIX-shaped one) leaves the cwd rooted, so a reading made
// entirely of POSIX paths decides as on POSIX (#4717).
//
// A cwd put on a drive comes back clean (C:\srv\app); one returned as written
// is not cleaned.
func Cwd(cwd, home string) string {
	if c := cwdFor(cwd, home, runtime.GOOS); c != cwd {
		return filepath.Clean(c)
	}
	return cwd
}

func cwdFor(cwd, home, goos string) string {
	if goos != "windows" {
		return cwd
	}
	c := fromMSYSDriveFor(cwd, goos)
	return onDriveFor(c, volumeFor(home, goos), goos)
}

// Drive returns the drive a rooted path is on when read from cwd: the volume
// of Cwd(cwd, home), on Windows. "" when it has none, and off Windows.
func Drive(cwd, home string) string {
	return volumeFor(cwdFor(cwd, home, runtime.GOOS), runtime.GOOS)
}

// OnDrive returns p on drive when p is a rooted path with no drive, on
// Windows, and p otherwise. The protected-path matcher reads a pattern, and a
// path that did not come through Resolve, with it, so both sides of a
// comparison are on the drive normalize resolved the operand on.
func OnDrive(p, drive string) string {
	return onDriveFor(p, drive, runtime.GOOS)
}

func onDriveFor(p, drive, goos string) string {
	if drive != "" && rootedFor(p, goos) {
		return drive + p
	}
	return p
}

// volumeFor returns the volume p names on goos, as filepath.VolumeName reads
// the two forms a working directory takes on Windows: a drive (`C:`) or a UNC
// share (`\\server\share`). "" for any other path, and off Windows. It is
// spelled out, not filepath.VolumeName, so the Windows reading runs in the
// tests on every OS.
func volumeFor(p, goos string) string {
	if goos != "windows" {
		return ""
	}
	if len(p) >= 2 && isASCIILetter(p[0]) && p[1] == ':' {
		return p[:2]
	}
	if len(p) < 3 || !isSlash(p[0]) || !isSlash(p[1]) {
		return ""
	}
	rest := p[2:]
	i := strings.IndexAny(rest, `/\`)
	if i <= 0 {
		return ""
	}
	share := rest[i+1:]
	if j := strings.IndexAny(share, `/\`); j >= 0 {
		share = share[:j]
	}
	if share == "" {
		return ""
	}
	return p[:2+i+1+len(share)]
}

// FromMSYSDrive returns p with Git Bash's spelling of a drive read as that
// drive, on Windows only: `/c/Users/u/.aws/credentials` is
// `C:\Users\u\.aws\credentials` (#5021 P-c). Every other path, and every path
// off Windows, is returned exactly as written.
//
// # Why
//
// Git Bash's `pwd` and its tab completion spell C:\Users\u as /c/Users/u. Read
// as a rooted path that is \c\Users\u, which no protected_paths pattern (`~`
// expands to C:\Users\u) matches. Measured over the packs' `~/` test commands
// respelled that way, protected-path fired on 0 of the 139 where macOS fires
// it; read as the drive, it fires on all 139.
//
// # The rule is Git Bash's
//
// The first segment is one ASCII letter, followed by a separator or the end:
// `/c`, `/c/`, `/D/x`. That is the MSYS2/Cygwin cygdrive rule with the prefix
// `/`, which the runtime applies before its mount table, so `/c` is drive C
// even when the Git install root holds a directory named `c`.
//
//   - A leading double separator is a UNC path (`//server/share`), never a drive.
//   - Cygwin's `/cygdrive/c` is not read: Git Bash does not spell it, and WSL
//     runs the Linux binary, where none of this applies.
//   - The letter is upper-cased. `~` in a protected_paths pattern expands from
//     USERPROFILE, which Windows spells C:\Users\..., and the matcher compares
//     case-sensitively.
//
// # The lexical clean is ours, not Git Bash's
//
// The path is cleaned lexically before its first segment is read, so
// `/x/../c/Users` is drive C and `/c/../Users` is no drive. Git Bash resolves
// `..` against the directory before it instead. Measured on Windows,
// `cat /usr/../c/<path>` opens C:\<path>, because its install root holds a
// `usr`, and `cat /x/../c/<path>` fails, because it holds no `x`. The clean
// reads both as drive C: right for the first, an over-read for the second.
// It is kept because it only adds. A path it reads as a drive can only gain a
// protected_paths match, so its cost is an over-block on a command that
// fails in Git Bash. Without it `/usr/../c/...`, a real read, would be read
// as `C:\c\...` and miss.
//
// A path it reads as a drive comes back clean, in filepath.Clean's Windows
// form (C:\Users\u).
func FromMSYSDrive(p string) string {
	return fromMSYSDriveFor(p, runtime.GOOS)
}

func fromMSYSDriveFor(p, goos string) string {
	if goos != "windows" || len(p) < 2 || !isSlash(p[0]) || isSlash(p[1]) {
		return p
	}
	q := path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if len(q) < 2 || !isASCIILetter(q[1]) || (len(q) > 2 && q[2] != '/') {
		return p
	}
	rest := strings.TrimPrefix(q[2:], "/")
	return strings.ToUpper(q[1:2]) + `:\` + strings.ReplaceAll(rest, "/", `\`)
}

func isSlash(c byte) bool { return c == '/' || c == '\\' }

func isASCIILetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
