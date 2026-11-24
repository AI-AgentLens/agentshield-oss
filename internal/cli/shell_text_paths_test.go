package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// shellTextPaths writes the test's temporary paths in a shell command the way
// an agent types them in Git Bash on Windows, with forward slashes (#5021).
//
// The e2e tests build commands like "grep KEY " + file, where file comes from
// t.TempDir(). On Windows that is C:\Users\…\notes.txt. In bash an unquoted
// backslash is an escape, so bash would open C:Users…notes.txt, and
// AgentShield, which reads the command as bash does, rightly saw no protected
// path there. The slash form C:/Users/…/notes.txt names the file in Git Bash
// and in every native Windows program.
//
// Only drive-letter paths (C:\...) are rewritten. Every fixture path a test
// builds on Windows has that shape: t.TempDir(), and shortTempRoot's
// <volume>\tmp. A backslash a test wrote on purpose (a\ b) has no drive
// letter and is kept. Off Windows the command is returned unchanged.
func shellTextPaths(cmd string) string {
	return shellTextPathsFor(cmd, runtime.GOOS)
}

var driveLetterPath = regexp.MustCompile("(?i)\\b[A-Z]:\\\\[^\\s\"'`;|&<>()]*")

func shellTextPathsFor(cmd, goos string) string {
	if goos != "windows" {
		return cmd
	}
	return driveLetterPath.ReplaceAllStringFunc(cmd, func(p string) string { return strings.ReplaceAll(p, `\`, "/") })
}

// shortTempRoot is the short root the e2e tests make fixtures under. A long
// random temp segment in command text reads as a high-entropy secret to
// guardian, a second reason to block that would hide what a test measures.
// Off Windows it is /tmp. On Windows "/tmp" is a rooted path with no drive
// (\tmp\...), which is not absolute there, so a fixture under it would hit the
// POSIX-absolute question (#5021 P-c) for reasons unrelated to the test. There
// it is <temp volume>\tmp, created if missing.
func shortTempRoot(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		return "/tmp"
	}
	root := filepath.VolumeName(os.TempDir()) + `\tmp`
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

// withShellTextPaths returns input with its "command" (if any) passed through
// shellTextPaths, leaving the caller's map alone.
func withShellTextPaths(input map[string]interface{}) map[string]interface{} {
	c, ok := input["command"].(string)
	if !ok {
		return input
	}
	out := make(map[string]interface{}, len(input))
	for k, v := range input {
		out[k] = v
	}
	out["command"] = shellTextPaths(c)
	return out
}

func TestShellTextPathsRewritesOnlyDriveLetterPathsOnWindows(t *testing.T) {
	key := "." + "ssh"
	in := `grep KEY C:\Users\u\AppData\Local\Temp\TestX1\001\acme\notes.txt && echo a\ b`
	want := `grep KEY C:/Users/u/AppData/Local/Temp/TestX1/001/acme/notes.txt && echo a\ b`
	if got := shellTextPathsFor(in, "windows"); got != want {
		t.Errorf("windows:\n got %q\nwant %q", got, want)
	}
	quoted := `cat "c:\users\u\appdata\local\temp\T\001\` + key + `\k"`
	if got := shellTextPathsFor(quoted, "windows"); !strings.Contains(got, `/T/001/`+key+`/k"`) {
		t.Errorf("windows, quoted and lower-case: %q", got)
	}
	tmp := `tar czf x.tgz -C C:\tmp\pp4676-1\acme notes.txt`
	if got := shellTextPathsFor(tmp, "windows"); got != `tar czf x.tgz -C C:/tmp/pp4676-1/acme notes.txt` {
		t.Errorf("windows, a C:\\tmp fixture: %q", got)
	}
	if got := shellTextPathsFor(in, "linux"); got != in {
		t.Errorf("linux changed the command: %q", got)
	}
	if got := shellTextPaths("echo " + filepath.Join("a", "b")); runtime.GOOS != "windows" && got != "echo "+filepath.Join("a", "b") {
		t.Errorf("off Windows, shellTextPaths changed %q", got)
	}
}
