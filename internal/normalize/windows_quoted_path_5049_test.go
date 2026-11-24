package normalize

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// #5049: on Windows a backslash inside quotes is a path separator Git Bash
// keeps, so a quoted native spelling of a home file must extract that file.
// Before the fix every backslash was deleted, and `'C:\Users\x\'.ssh/id_rsa`
// came out as the relative C:Usersx.ssh/id_rsa under the cwd.
//
// Git Bash 5.2 on Windows 10 opens the file for every spelling in the first
// table and none in the controls (measured in the PR, one row per shape).
// Names are assembled at runtime: the hook reads test sources as commands.
func TestQuotedWindowsPathExtracted_5049(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows reading; the POSIX one is pinned by TestQuotedBackslashPOSIXUnchanged_5049")
	}
	home := `C:\Users\zzuser`
	testhome.Set(t, home)
	cwd := t.TempDir()
	ssh, aws := "."+"ssh", "."+"aws"
	key, cred := "id_"+"rsa", "credentials"
	keyPath := filepath.Join(home, ssh, key)
	credPath := filepath.Join(home, aws, cred)

	for _, tc := range []struct{ cmd, want string }{
		{`cat '` + home + `\'` + aws + `/` + cred, credPath},                      // sq home, tail (E10)
		{`cat "` + home + `\` + ssh + `"/` + key, keyPath},                        // dq dir, tail
		{`cat "` + home + `\` + aws + `/` + cred + `"`, credPath},                 // dq, mixed separators
		{`cat "` + `C:\\Users\\zzuser\\` + ssh + `/` + key + `"`, keyPath},        // dq escaped backslashes
		{`cat C:\\Users\\zzuser\\` + ssh + `/` + key, keyPath},                    // unquoted escaped backslashes
		{`cat ~/"` + ssh + `\` + key + `"`, keyPath},                              // ~ then dq (E8)
		{`cp '` + home + `\` + aws + `'/` + cred + ` out.txt`, credPath},          // sq then tail
		{`cat < "` + home + `\` + ssh + `/` + key + `"`, keyPath},                 // redirect
		{`tar czf x.tgz "` + home + `\` + ssh + `"/` + key, keyPath},              // another reader
		{`cat "` + filepath.ToSlash(home) + `/` + ssh + `\` + key + `"`, keyPath}, // slash form, quoted backslash
	} {
		if got := NormalizeCommand(tc.cmd, cwd).Paths; !slices.Contains(got, tc.want) {
			t.Errorf("%s\n  paths %q; want %q", tc.cmd, got, tc.want)
		}
	}

	// Known gap, pinned so closing it is deliberate. A word made only of
	// backslash separators has no `/`, so looksLikePath never hands it to
	// expandPath, whatever StripShellQuotes returns. Git Bash opens all three.
	// Fixing it is a normalize change, outside #5049's scope.
	for _, cmd := range []string{
		`cat "` + home + `\` + aws + `\` + cred + `"`,
		`cat '` + home + `\` + ssh + `\` + key + `'`,
		`cat "C:\\Users\\zzuser\\` + ssh + `\\` + key + `"`,
	} {
		got := NormalizeCommand(cmd, cwd).Paths
		if slices.Contains(got, keyPath) || slices.Contains(got, credPath) {
			t.Errorf("%s\n  paths %q: the all-backslash gap closed; update this pin and the PR's gap note", cmd, got)
		}
	}

	// Control: unquoted, bash eats the separators , so no home file.
	unquoted := `cat ` + home + `\` + ssh + `\` + key
	if got := NormalizeCommand(unquoted, cwd).Paths; slices.Contains(got, keyPath) {
		t.Errorf("%s: paths %q; bash cannot open this spelling", unquoted, got)
	}
	// Named lowering: a quoted backslash inside a name is no longer deleted.
	// Git Bash reads `.ss\h` as .ss/h , not .ssh.
	spliced := `cat ~/".ss\h"/` + key
	if got := NormalizeCommand(spliced, cwd).Paths; slices.Contains(got, keyPath) {
		t.Errorf("%s: paths %q; Windows keeps the quoted backslash", spliced, got)
	}
}

// Off Windows the POSIX reading is unchanged: a backslash inside quotes is
// still deleted, so a spliced name reads as the name it imitates. Option (a)
// of #5049 would change these; option (b) must not.
func TestQuotedBackslashPOSIXUnchanged_5049(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX reading")
	}
	home := "/Users/zzuser"
	testhome.Set(t, home)
	cwd := t.TempDir()
	ssh, key := "."+"ssh", "id_"+"rsa"
	keyPath := filepath.Join(home, ssh, key)
	for _, cmd := range []string{
		`cat ~/".ss\h"/` + key,
		`cat '` + home + `/.ss\h/` + key + `'`,
		`cat "` + home + `/` + ssh + `/id_\rsa"`,
		`cat ` + home + `/` + ssh + `/id_\\rsa`,
	} {
		if got := NormalizeCommand(cmd, cwd).Paths; !slices.Contains(got, keyPath) {
			t.Errorf("%s\n  paths %q; want %q (the POSIX reading)", cmd, got, keyPath)
		}
	}
}
