package pathnorm

import (
	"path/filepath"
	"runtime"
	"testing"
)

// #5021 P-c. The goos-parameterised cores run on every OS, so a macOS or Linux
// run checks the Windows reading too. Credential-shaped paths are assembled at
// runtime: this repo dogfoods AgentShield, which reads test sources as text.

func TestFromMSYSDriveFor_Windows(t *testing.T) {
	aws := "." + "aws"
	for _, c := range []struct{ in, want string }{
		{"/c/Users/u/" + aws + "/credentials", `C:\Users\u\` + aws + `\credentials`},
		{"/c", `C:\`},
		{"/c/", `C:\`},
		{"/D/x", `D:\x`},
		{"/z/a/b/", `Z:\a\b`},
		{`\c\Users\u`, `C:\Users\u`},          // filepath.Clean's Windows spelling of /c/Users/u
		{"/c//Users///u/./x", `C:\Users\u\x`}, // cleaned lexically
		{"/x/../c/Users", `C:\Users`},         // cleaned before the drive is read (an over-read; see FromMSYSDrive)
		{"/usr/../c/Users", `C:\Users`},       // what Git Bash opens: its root holds a usr
		{"/./c/Users", `C:\Users`},
		{"/../c/Users", `C:\Users`},
		// Not a drive: returned exactly as written.
		{"/c/../Users", "/c/../Users"},
		{"//c/share", "//c/share"}, // UNC
		{`\\c\share`, `\\c\share`},
		{`\/c/share`, `\/c/share`},
		{"/cc/x", "/cc/x"},
		{"/c:/x", "/c:/x"},
		{"/1/x", "/1/x"},
		{"/_/x", "/_/x"},
		{"/\u00e9/x", "/\u00e9/x"},
		{"/var/tmp/x", "/var/tmp/x"},
		{"/cygdrive/c/x", "/cygdrive/c/x"},
		{"c/Users", "c/Users"},
		{"C:/Users", "C:/Users"},
		{`C:\Users`, `C:\Users`},
		{"/", "/"},
		// Clean to `/`, one byte: the length guard returns them as written
		// (without it, reading the drive letter indexes past the end).
		{"/.", "/."},
		{"/..", "/.."},
		{`\.`, `\.`},
		{"", ""},
		{"~/c/x", "~/c/x"},
	} {
		if got := fromMSYSDriveFor(c.in, "windows"); got != c.want {
			t.Errorf("windows %q: got %q, want %q", c.in, got, c.want)
		}
	}
}

// Off Windows `/c/...` is a directory named c, never a drive.
func TestFromMSYSDriveFor_OffWindowsIsTheIdentity(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "freebsd"} {
		for _, in := range []string{"/c/Users/u", "/c", `\c\Users`, "/x/../c/Users", "/D/x"} {
			if got := fromMSYSDriveFor(in, goos); got != in {
				t.Errorf("%s %q: got %q, want it unchanged", goos, in, got)
			}
		}
	}
}

func TestRootedFor(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"/var/tmp/x", true},
		{`\var\tmp\x`, true},
		{"/", true},
		{`\`, true},
		{"var/tmp", false},
		{"", false},
		{`C:\x`, false}, // filepath.IsAbs's to decide, not rootedFor's
		{"~/x", false},
		// A leading double separator is UNC: filepath.IsAbs on Windows, and
		// never put on a drive.
		{`\\server\share\x`, false},
		{"//server/share", false},
		{`\/x`, false},
	} {
		if got := rootedFor(c.in, "windows"); got != c.want {
			t.Errorf("windows %q: got %v, want %v", c.in, got, c.want)
		}
		if rootedFor(c.in, "linux") || rootedFor(c.in, "darwin") {
			t.Errorf("off windows %q: rootedFor must add nothing to filepath.IsAbs", c.in)
		}
	}
}

// IsAbs on this host: filepath.IsAbs, plus the rooted reading on Windows only.
func TestIsAbs(t *testing.T) {
	win := runtime.GOOS == "windows"
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"/var/tmp/x", true}, // POSIX: filepath.IsAbs; Windows: rooted
		{`\var\tmp\x`, win},  // a relative name off Windows
		{"var/tmp/x", false},
		{"", false},
		{"~/x", false},
		{`C:\x`, win},
		{"C:/x", win},
		{"C:x", false}, // drive-relative on Windows
	} {
		if got := IsAbs(c.in); got != c.want {
			t.Errorf("%s %q: got %v, want %v", runtime.GOOS, c.in, got, c.want)
		}
	}
}

// FromMSYSDrive on this host: the Windows reading there, the identity elsewhere.
func TestFromMSYSDrive_ThisHost(t *testing.T) {
	in := "/c/Users/u"
	want := in
	if runtime.GOOS == "windows" {
		want = `C:\Users\u`
	}
	if got := FromMSYSDrive(in); got != want {
		t.Errorf("%s: got %q, want %q", runtime.GOOS, got, want)
	}
}

func TestVolumeFor(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`C:\Users\u`, "C:"},
		{"c:/", "c:"},
		{"C:", "C:"},
		{"C:x", "C:"},
		{"1:/x", ""}, // a drive is a letter
		{`\\server\share\dir`, `\\server\share`},
		{`\\server\share`, `\\server\share`},
		{"//server/share/dir", "//server/share"},
		{`\\?\C:\x`, `\\?\C:`},
		{`\\server`, ""},
		{`\\server\`, ""},
		{`\\\share`, ""}, // no server
		{`\\`, ""},
		{`\x`, ""},
		{"/c/Users", ""}, // Git Bash's spelling: FromMSYSDrive's to read
		{"Users", ""},
		{"", ""},
	} {
		if got := volumeFor(c.in, "windows"); got != c.want {
			t.Errorf("windows %q: got %q, want %q", c.in, got, c.want)
		}
		if got := volumeFor(c.in, "linux"); got != "" {
			t.Errorf("linux %q: got %q, want no volume off Windows", c.in, got)
		}
	}
}

// The cwd half of (c): Git Bash's spelling is its own drive, and a rooted cwd
// with no drive is on the home's. Every other cwd is as written.
func TestCwdFor_Windows(t *testing.T) {
	ssh := "." + "ssh"
	for _, c := range []struct{ cwd, home, want string }{
		{`C:\proj`, `D:\Users\u`, `C:\proj`},
		{"/c/Users/u/" + ssh, `D:\Users\u`, `C:\Users\u\` + ssh},
		{"/d", `C:\Users\u`, `D:\`},
		{"/srv/app", `C:\Users\u`, "C:/srv/app"},
		{`\srv\app`, `D:\Users\u`, `D:\srv\app`},
		{"/", `C:\Users\u`, "C:/"},
		{"/srv/app", `\\server\home\u`, `\\server\home/srv/app`},
		{"/srv/app", "/Users/u", "/srv/app"}, // a home with no drive: POSIX's reading
		{"/srv/app", "", "/srv/app"},
		{`\\server\share\dir`, `C:\Users\u`, `\\server\share\dir`},
		{"", `C:\Users\u`, ""},
		{"proj", `C:\Users\u`, "proj"},
	} {
		if got := cwdFor(c.cwd, c.home, "windows"); got != c.want {
			t.Errorf("windows cwd %q home %q: got %q, want %q", c.cwd, c.home, got, c.want)
		}
		if got := cwdFor(c.cwd, c.home, "darwin"); got != c.cwd {
			t.Errorf("darwin cwd %q: got %q, want it unchanged", c.cwd, got)
		}
	}
}

func TestOnDriveFor(t *testing.T) {
	for _, c := range []struct{ p, drive, want string }{
		{`\etc\**`, "C:", `C:\etc\**`},
		{"/etc/**", "c:", "c:/etc/**"},
		{`\x`, `\\server\share`, `\\server\share\x`},
		{`\x`, "", `\x`},                               // no drive to put it on
		{`C:\x`, "D:", `C:\x`},                         // has its own
		{`\\server\share\x`, "C:", `\\server\share\x`}, // UNC
		{"x", "C:", "x"},                               // relative: Resolve joins it, OnDrive does not
		{"~/x", "C:", "~/x"},
	} {
		if got := onDriveFor(c.p, c.drive, "windows"); got != c.want {
			t.Errorf("windows %q on %q: got %q, want %q", c.p, c.drive, got, c.want)
		}
		if got := onDriveFor(c.p, c.drive, "linux"); got != c.p {
			t.Errorf("linux %q: got %q, want it unchanged", c.p, got)
		}
	}
}

// Resolve on this host. Windows: B, then (c) on the cwd's drive, then a
// relative join. Elsewhere: main's join exactly.
func TestResolve(t *testing.T) {
	aws := "." + "aws"
	type row struct{ p, cwd, home, posix, windows string }
	for _, c := range []row{
		// (c): from any cwd on C:, `/srv/x` is C:\srv\x, at the root and below it.
		{"/srv/x", `C:\proj\sub`, `C:\Users\u`, "/srv/x", `C:\srv\x`},
		{`\srv\x`, `C:\proj`, `C:\Users\u`, `C:\proj/\srv\x`, `C:\srv\x`},
		{"/srv/x", `C:\`, `C:\Users\u`, "/srv/x", `C:\srv\x`},
		{"/srv/x", `D:\data`, `C:\Users\u`, "/srv/x", `D:\srv\x`},
		{"/srv/x", `\\server\share\dir`, `C:\Users\u`, "/srv/x", `\\server\share\srv\x`},
		{"/Users/u/" + aws + "/credentials", `C:\Users\u\.` + "ssh", `C:\Users\u`, "/Users/u/" + aws + "/credentials", `C:\Users\u\` + aws + `\credentials`},
		// B comes first: `/c/...` is drive C wherever the cwd is, and so is a
		// one-letter first segment alone.
		{"/c/Users/u/" + aws, `D:\`, `D:\Users\u`, "/c/Users/u/" + aws, `C:\Users\u\` + aws},
		{"/c/Users/u/" + aws, `C:\`, `C:\Users\u`, "/c/Users/u/" + aws, `C:\Users\u\` + aws},
		{"/x", `C:\proj`, `C:\Users\u`, "/x", `X:\`},
		// A cwd with no drive of its own.
		{"/srv/x", "/c/Users/u", `D:\Users\u`, "/srv/x", `C:\srv\x`},
		{"/srv/x", "/srv/app", `D:\Users\u`, "/srv/x", `D:\srv\x`},
		{"x", "/srv/app", `D:\Users\u`, "/srv/app/x", `D:\srv\app\x`},
		{"/srv/x", "/srv/app", "/Users/u", "/srv/x", `\srv\x`}, // nothing has a drive: POSIX's reading
		{"/srv/x", "", `C:\Users\u`, "/srv/x", `\srv\x`},       // no cwd: stays rooted, as main read it
		// Relative and drive paths are main's.
		{"x", `C:\proj`, `C:\Users\u`, `C:\proj/x`, `C:\proj\x`},
		{`D:\y`, `C:\proj`, `C:\Users\u`, `C:\proj/D:\y`, `D:\y`},
	} {
		want := c.posix
		if runtime.GOOS == "windows" {
			want = c.windows
		}
		if got := filepath.Clean(Resolve(c.p, c.cwd, c.home)); got != filepath.Clean(want) {
			t.Errorf("%s Resolve(%q, cwd %q, home %q) = %q, want %q", runtime.GOOS, c.p, c.cwd, c.home, got, filepath.Clean(want))
		}
	}
}

// Drive on this host: the cwd's volume after Cwd, on Windows only.
func TestDrive(t *testing.T) {
	win := runtime.GOOS == "windows"
	for _, c := range []struct{ cwd, home, windows string }{
		{`C:\proj`, `D:\Users\u`, "C:"},
		{"/d/x", `C:\Users\u`, "D:"},
		{"/srv", `D:\Users\u`, "D:"},
		{"/srv", "/Users/u", ""},
		{"", `C:\Users\u`, ""},
	} {
		want := ""
		if win {
			want = c.windows
		}
		if got := Drive(c.cwd, c.home); got != want {
			t.Errorf("%s Drive(%q, %q) = %q, want %q", runtime.GOOS, c.cwd, c.home, got, want)
		}
	}
}

// A path or cwd put on a drive comes back clean, as a joined one does; the
// matcher and the audit-only keep compare these strings as they are.
func TestResolvedOnADriveIsClean(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("off Windows nothing is put on a drive")
	}
	for _, c := range []struct{ got, want string }{
		{Resolve("/srv/x", `C:\`, `C:\Users\u`), `C:\srv\x`},
		{Resolve("/srv/./x/../y", `D:\data`, `C:\Users\u`), `D:\srv\y`},
		{Resolve("/srv/x", "", `C:\Users\u`), "/srv/x"}, // no drive: as written
		{Cwd("/srv/app", `C:\Users\u`), `C:\srv\app`},
		{Cwd("/srv/app", "/Users/u"), "/srv/app"},
		{Cwd(`C:/work`, `C:\Users\u`), `C:/work`}, // returned as written
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
