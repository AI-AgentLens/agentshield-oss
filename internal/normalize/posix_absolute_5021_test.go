package normalize

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// #5021 P-c, option (c): on Windows Git Bash's `/c/...` is drive C, and a
// rooted `/x` with no drive is on the cwd's drive, at every operand and cwd
// site. Each row's expectation is computed for this OS: a POSIX run pins the
// output byte-for-byte as before, a Windows run pins the new reading.
// Credential names are assembled at runtime, because this repo dogfoods
// AgentShield.

// msysSpelling spells an OS path the way Git Bash's pwd does: C:\Users\u is
// /c/Users/u. A path with no drive (every POSIX path) comes back in slash form.
func msysSpelling(p string) string {
	p = filepath.ToSlash(p)
	if len(p) >= 2 && p[1] == ':' {
		return "/" + strings.ToLower(p[:1]) + p[2:]
	}
	return p
}

// rootedSpelling is p without its volume, in slash form: on Windows
// C:\Users\u is /Users/u, a rooted path on the current drive. On POSIX it is p.
func rootedSpelling(p string) string {
	return filepath.ToSlash(p[len(filepath.VolumeName(p)):])
}

// onDriveOf is the slash-form rooted path p as the product returns it when
// read from cwd: on Windows on cwd's drive (C:\x for /x from C:\proj), and p
// itself on POSIX.
func onDriveOf(cwd, p string) string {
	return filepath.VolumeName(cwd) + osPath(p)
}

// otherDrive is a drive letter that is not the one p is on, for lexical rows
// (nothing reads the disk there, so the drive need not exist).
func otherDrive(p string) string {
	if strings.EqualFold(filepath.VolumeName(p), "Z:") {
		return "Y:"
	}
	return "Z:"
}

// count is how many times want occurs in paths.
func count(paths []string, want string) int {
	n := 0
	for _, p := range paths {
		if p == want {
			n++
		}
	}
	return n
}

// (c): from a directory below the drive's root, a rooted operand is on the
// cwd's drive, not under the cwd. PowerShell opens `/x` there.
func TestRootedOperandIsOnTheCwdsDrive_5021(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "a", "b")
	for _, c := range []struct{ cmd, want string }{
		{"cat /var/tmp/org-token", "/var/tmp/org-token"},
		{"ls 2>/dev/null", "/dev/null"},
		{"cp notes.txt /srv/app/out.txt", "/srv/app/out.txt"},
		{"Get-Content /srv/app/x", "/srv/app/x"},
		{"type /srv/app/y", "/srv/app/y"},
	} {
		nc := NormalizeCommand(c.cmd, cwd)
		want := onDriveOf(cwd, c.want)
		if !slices.Contains(nc.Paths, want) {
			t.Errorf("%q cwd=%s: paths %q, want %q among them", c.cmd, cwd, nc.Paths, want)
		}
		for _, p := range nc.Paths {
			if strings.HasPrefix(p, cwd) && strings.HasSuffix(filepath.ToSlash(p), c.want) {
				t.Errorf("%q: %q was joined under the cwd", c.cmd, p)
			}
		}
	}
}

// A rooted tar member is read from cwd as any operand is. tar's -C directory
// adds a candidate only when it puts the member on another drive (bsdtar
// opens `\x` on the -C directory's drive); on cwd's drive it would be the
// same path twice.
func TestTarRootedMemberIsOneCandidate_5021(t *testing.T) {
	cwd, dir := t.TempDir(), t.TempDir()
	cmd := "tar czf x.tgz -C " + shellPath(dir) + " /srv/app/x"
	nc := NormalizeCommand(cmd, cwd)
	want := onDriveOf(cwd, "/srv/app/x")
	if n := count(nc.Paths, want); n != 1 {
		t.Errorf("paths %q: %d copies of %q, want 1", nc.Paths, n, want)
	}
	for _, p := range nc.Paths {
		if strings.HasPrefix(p, dir) && strings.HasSuffix(filepath.ToSlash(p), "/srv/app/x") {
			t.Errorf("%q: resolved under the -C directory", p)
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	other := otherDrive(cwd) + `\data`
	cmd = "tar czf x.tgz -C " + shellPath(other) + " /srv/app/x"
	nc = NormalizeCommand(cmd, cwd)
	for _, w := range []string{want, otherDrive(cwd) + osPath("/srv/app/x")} {
		if n := count(nc.Paths, w); n != 1 {
			t.Errorf("%q: paths %q: %d copies of %q, want 1", cmd, nc.Paths, n, w)
		}
	}
}

// `/c/...` is drive C on Windows only. On POSIX it is a directory named c.
func TestMSYSDriveOperand_5021(t *testing.T) {
	aws, ssh := "."+"aws", "."+"ssh"
	drive := runtime.GOOS == "windows"
	cwd := t.TempDir()
	for _, c := range []struct{ cmd, posix, windows string }{
		{"cat /c/Users/u/" + aws + "/credentials", "/c/Users/u/" + aws + "/credentials", `C:\Users\u\` + aws + `\credentials`},
		{"cat /D/work/x", "/D/work/x", `D:\work\x`},
		{"tar czf x.tgz -C /c/Users/u " + ssh, "/c/Users/u/" + ssh, `C:\Users\u\` + ssh},
		{"cat /cc/x", "/cc/x", onDriveOf(cwd, "/cc/x")}, // not a drive: rooted, on the cwd's
	} {
		want := c.posix
		if drive {
			want = c.windows
		}
		nc := NormalizeCommand(c.cmd, cwd)
		if !slices.Contains(nc.Paths, want) {
			t.Errorf("%q: paths %q, want %q among them", c.cmd, nc.Paths, want)
		}
	}
}

// A rooted cwd is usable on Windows, on the home's drive (pathnorm.Cwd): a
// bare operand and a bare glob resolve in the directory it names there, as
// under a POSIX cwd. The directory is a real temp dir spelled without its
// drive, so the existence check and the glob have files to find.
func TestRootedCwdResolvesBareOperands_5021(t *testing.T) {
	native := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(filepath.VolumeName(home), filepath.VolumeName(native)) {
		t.Skipf("the temp dir %s is not on the home's drive (%s), so its rooted spelling names another directory", native, home)
	}
	key := "id_" + "x"
	if err := os.WriteFile(filepath.Join(native, key), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := rootedSpelling(native)
	for _, c := range []struct{ cmd, name string }{
		{"cat " + key, key},            // existing entry (bareOperandPath)
		{"touch new-file", "new-file"}, // created (fileOperandCommands)
		{"cat id_*", key},              // glob (bareGlobPaths)
	} {
		nc := NormalizeCommand(c.cmd, cwd)
		want := filepath.Join(native, c.name)
		if !slices.Contains(nc.Paths, want) {
			t.Errorf("%q cwd=%s: paths %q, want %q among them", c.cmd, cwd, nc.Paths, want)
		}
	}
}

// A cwd Git Bash spells /c/... is drive C's directory: the existence check,
// the glob and the join all look at the directory the shell is in.
func TestMSYSCwdResolvesBareOperands_5021(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("on POSIX /c/... is a directory named c; TestMSYSDriveOperand_5021 pins that")
	}
	native := t.TempDir()
	key := "id_" + "x"
	if err := os.WriteFile(filepath.Join(native, key), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := msysSpelling(native)
	for _, c := range []struct{ cmd, name string }{
		{"cat " + key, key},
		{"cat id_*", key},
		{"cat ./" + key, key},
		{"touch new-file", "new-file"},
	} {
		nc := NormalizeCommand(c.cmd, cwd)
		want := filepath.Join(native, c.name)
		if !slices.Contains(nc.Paths, want) {
			t.Errorf("%q cwd=%s: paths %q, want %q among them", c.cmd, cwd, nc.Paths, want)
		}
	}
	// A rooted operand is on the drive the Git Bash cwd names.
	if nc := NormalizeCommand("cat /srv/app/x", cwd); !slices.Contains(nc.Paths, onDriveOf(native, "/srv/app/x")) {
		t.Errorf("cat /srv/app/x cwd=%s: paths %q, want %q among them", cwd, nc.Paths, onDriveOf(native, "/srv/app/x"))
	}
}

// From a volume's root a rooted operand is on that root's drive: C:\ + /x is
// C:\x, what cmd and PowerShell open, and what main's join gave there. Git
// Bash's `/c/...` is drive C first, from any drive's root (the pass-1
// finding: a volume-root join ran before the MSYS reading). On POSIX the root
// is `/` and nothing changes.
func TestRootedOperandFromAVolumeRoot_5021(t *testing.T) {
	aws := "." + "aws"
	root := "/"
	if runtime.GOOS == "windows" {
		root = filepath.VolumeName(t.TempDir()) + `\`
	}
	if nc := NormalizeCommand("cat /var/tmp/org-token", root); !slices.Contains(nc.Paths, filepath.Join(root, "var", "tmp", "org-token")) {
		t.Errorf("cwd=%s: paths %q, want %q among them", root, nc.Paths, filepath.Join(root, "var", "tmp", "org-token"))
	}
	// tar -C <root> reads a rooted member from the root too (bsdtar on
	// Windows opens `\x` on the -C directory's drive), whatever the cwd.
	cmd := "tar czf x.tgz -C " + shellPath(root) + " /srv/app/x"
	if nc := NormalizeCommand(cmd, t.TempDir()); !slices.Contains(nc.Paths, filepath.Join(root, "srv", "app", "x")) {
		t.Errorf("%q: paths %q, want %q among them", cmd, nc.Paths, filepath.Join(root, "srv", "app", "x"))
	}
	roots := []string{root}
	if runtime.GOOS == "windows" {
		roots = append(roots, otherDrive(root)+`\`)
	}
	msys := "/c/Users/u/" + aws + "/credentials"
	want := msys
	if runtime.GOOS == "windows" {
		want = `C:\Users\u\` + aws + `\credentials`
	}
	for _, r := range roots {
		if nc := NormalizeCommand("cat "+msys, r); !slices.Contains(nc.Paths, want) {
			t.Errorf("cat %s cwd=%s: paths %q, want %q among them", msys, r, nc.Paths, want)
		}
	}
}
