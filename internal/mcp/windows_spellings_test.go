package mcp

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Tests for the Windows spellings of a path under HOME (#5060, #5062). The
// helpers are pure and run on every platform. The guard's decisions run on
// Windows only (TestConfigGuard_WindowsSpellings), where the spellings name
// this machine's files; TestConfigGuard_WindowsSpellingsUnchangedOffWindows
// pins that every other platform reads them as before.

func TestDriveURIPath(t *testing.T) {
	for _, r := range []struct {
		in, want string
		ok       bool
	}{
		{"/C:/Users/u/x", "C:/Users/u/x", true},
		{"/c:/Users/u/x", "c:/Users/u/x", true},
		{"/C|/Users/u/x", "C:/Users/u/x", true},
		{"/c%3A/Users/u/x", "c:/Users/u/x", true},
		{"/c%3a/Users/u/x", "c:/Users/u/x", true},
		{`/C:\Users\u\x`, `C:\Users\u\x`, true},
		{"/C:", "C:", true},
		// Not a drive: unchanged.
		{"/Users/u/x", "/Users/u/x", false},
		{"/CD:/x", "/CD:/x", false},
		{"/C:x", "/C:x", false},
		{"/1:/x", "/1:/x", false},
		{"C:/Users/u/x", "C:/Users/u/x", false},
		{"//C:/x", "//C:/x", false},
		{"", "", false},
	} {
		if got, ok := driveURIPath(r.in); got != r.want || ok != r.ok {
			t.Errorf("driveURIPath(%q) = %q, %v; want %q, %v", r.in, got, ok, r.want, r.ok)
		}
	}
}

func TestIsDriveAbs(t *testing.T) {
	for in, want := range map[string]bool{
		`C:\Users`: true, `c:\x`: true, "C:/Users": true, "z:/": true,
		"C:": false, "C:x": false, `\Users\u`: false, "/Users/u": false, `\\host\share`: false,
		`1:\x`: false, `@:\x`: false, `[:\x`: false, "": false, "file:///C:/x": false,
	} {
		if got := isDriveAbs(in); got != want {
			t.Errorf("isDriveAbs(%q) = %v; want %v", in, got, want)
		}
	}
}

func TestExpandWindowsRefs(t *testing.T) {
	env := map[string]string{"USERPROFILE": `C:\Users\John Smith`, "HOMEDRIVE": "C:", "HOMEPATH": `\Users\u`, "EMPTY": ""}
	lookup := func(k string) (string, bool) { v, ok := env[strings.ToUpper(k)]; return v, ok }
	for _, r := range []struct{ in, want string }{
		{`%USERPROFILE%\x`, `C:\Users\John Smith\x`},
		{`%userprofile%\x`, `C:\Users\John Smith\x`},
		{`%HOMEDRIVE%%HOMEPATH%\x`, `C:\Users\u\x`},
		{`$env:USERPROFILE\x`, `C:\Users\John Smith\x`},
		{`$ENV:UserProfile\x`, `C:\Users\John Smith\x`},
		{`${env:USERPROFILE}\x`, `C:\Users\John Smith\x`},
		{`${env:USERPROFILE}x`, `C:\Users\John Smithx`},
		{`$env:HOMEDRIVE$env:HOMEPATH\x`, `C:\Users\u\x`},
		{`$HOME\x`, `C:\Users\John Smith\x`},
		{`$home/x`, `C:\Users\John Smith/x`},
		{`${HOME}\x`, `C:\Users\John Smith\x`},
		// Left as written: unknown, empty, or not a reference.
		{`%NOPE%\x`, `%NOPE%\x`},
		{`%EMPTY%\x`, `%EMPTY%\x`},
		{`$env:NOPE\x`, `%NOPE%\x`},
		{`$HOMEDRIVE\x`, `$HOMEDRIVE\x`},
		{`$homes\x`, `$homes\x`},
		{`100%`, `100%`},
		{`a % b % c`, `a % b % c`},
	} {
		if got := expandPercentRefs(canonWindowsRefs(r.in), lookup); got != r.want {
			t.Errorf("expand(%q) = %q; want %q", r.in, got, r.want)
		}
	}
}

func TestWindowsCommandTokens(t *testing.T) {
	lookup := func(k string) (string, bool) {
		if strings.EqualFold(k, "USERPROFILE") {
			return `C:\Users\John Smith`, true
		}
		return "", false
	}
	has := func(toks []string, want string) bool {
		for _, tok := range toks {
			if tok == want {
				return true
			}
		}
		return false
	}
	for _, r := range []struct{ text, want string }{
		{`Remove-Item -Recurse -Force C:\Users\u\.x`, `C:\Users\u\.x`},
		{`rm -rf C:/Users/u/.x`, `C:/Users/u/.x`},
		{`del %USERPROFILE%\.x\m.json`, `C:\Users\John Smith\.x\m.json`},
		{`Remove-Item $env:USERPROFILE\.x`, `C:\Users\John Smith\.x`},
		{`Remove-Item ${env:USERPROFILE}\.x`, `C:\Users\John Smith\.x`},
		{`Remove-Item "C:\Users\John Smith\.x"`, `C:\Users\John Smith\.x`},
		{`python -c "open('C:\Users\John Smith\.x\p','w')"`, `C:\Users\John Smith\.x\p`},
		{`python -c "open('C:\Users\u\.x\p','w')"`, `C:\Users\u\.x\p`},
		{"Remove-Item C:\\Users\\u\\.agent`shield", `C:\Users\u\.agentshield`},
		{`rd /s /q C:\Users\u\.agent^shield`, `C:\Users\u\.agentshield`},
		{`tool --dir=C:\Users\u\.x`, `C:\Users\u\.x`},
		{`& { Remove-Item C:\Users\u\.x }`, `C:\Users\u\.x`},
		{`X=shield; rm -rf C:/Users/u/.agent$X`, `C:/Users/u/.agentshield`},
	} {
		if toks := windowsCommandTokens(r.text, lookup); !has(toks, r.want) {
			t.Errorf("windowsCommandTokens(%q) = %q; want a word %q", r.text, toks, r.want)
		}
	}
	// Main's reading of the first row, for contrast: the backslash goes.
	if toks := commandTokens(`Remove-Item C:\Users\u\.x`); !reflect.DeepEqual(toks, []string{"Remove-Item", "C:Usersu.x"}) {
		t.Errorf("commandTokens changed: %q", toks)
	}
}

func TestWindowsPlainRead(t *testing.T) {
	for text, want := range map[string]bool{
		`type C:\Users\u\.x\audit.jsonl`:                               true,
		`TYPE C:\Users\u\.x\audit.jsonl`:                               true,
		`more C:\Users\u\.x\audit.jsonl`:                               true,
		`Get-Content -Tail 5 C:\Users\u\.x\audit.jsonl`:                true,
		`gc $env:USERPROFILE\.x\policy.yaml`:                           true,
		`dir /a C:\Users\u\.x`:                                         true,
		`Get-ChildItem -Force %USERPROFILE%\.x`:                        true,
		`gci C:\Users\u\.x`:                                            true,
		`Get-Item C:\Users\u\.x\managed.json`:                          true,
		`Test-Path C:\Users\u\.x`:                                      true,
		`Select-String -Path C:\Users\u\.x\audit.jsonl -Pattern BLOCK`: true,
		`findstr BLOCK C:\Users\u\.x\audit.jsonl`:                      true,
		`findstr.exe BLOCK C:\Users\u\.x\audit.jsonl`:                  true,
		`  type C:\x`: true,
		`type`:        true,
		// Not a plain read.
		`Get-Content C:\Users\u\.x\policy.yaml | Set-Content C:\y`: false,
		`type C:\Users\u\.x\policy.yaml > C:\y`:                    false,
		`type C:\x & del C:\Users\u\.x\managed.json`:               false,
		`type C:\x; Remove-Item C:\Users\u\.x`:                     false,
		"type C:\\x\nRemove-Item C:\\Users\\u\\.x":                 false,
		"type C:\\x\rRemove-Item C:\\Users\\u\\.x":                 false,
		"Get-Content C:\\x `\n; rm C:\\y":                          false,
		`Get-Content (Remove-Item C:\Users\u\.x)`:                  false,
		`Get-Content $(Remove-Item C:\Users\u\.x)`:                 false,
		`Get-ChildItem C:\x -Filter { Remove-Item C:\y }`:          false,
		`dir !x!`:                             false,
		`typed C:\x`:                          false,
		`Get-Contents C:\x`:                   false,
		`Remove-Item C:\Users\u\.x`:           false,
		`del C:\Users\u\.x\managed.json`:      false,
		`cp C:\Users\u\.x\policy.yaml C:\tmp`: false,
		`moretools C:\x`:                      false,
	} {
		if got := windowsPlainReadRe.MatchString(text); got != want {
			t.Errorf("windowsPlainReadRe(%q) = %v; want %v", text, got, want)
		}
	}
}

// Off Windows every new reading is skipped: the Windows spellings decide as
// they did before #5060/#5062.
func TestConfigGuard_WindowsSpellingsUnchangedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows readings apply here; TestConfigGuard_WindowsSpellings covers them")
	}
	home := "/Users/u"
	for in, want := range map[string]string{
		"file:///C:/Users/u/x":        "/C:/Users/u/x",
		"file://localhost/C:/Users/u": "/C:/Users/u",
		"file:///c|/x":                "/c|/x",
		"file:///C%3A/x":              "/C:/x",
		`~\x`:                         `~\x`,
		`$HOME\x`:                     `$HOME\x`,
		`${HOME}\x`:                   `${HOME}\x`,
	} {
		if got, ok := spellingToPath(in, home); !ok || got != want {
			t.Errorf("spellingToPath(%q) = %q, %v; want %q as before", in, got, ok, want)
		}
	}
	if _, ok := spellingToPath("file://C:/x", home); ok {
		t.Error(`spellingToPath("file://C:/x") ok; want another host, as before`)
	}
	for _, uri := range []string{"file:///C:/Users/u/.bashrc", "file:///c%3A/x", "https://x/y", "/C:/x"} {
		if got, want := resourceGuardPath(uri), strings.TrimPrefix(uri, "file://"); got != want {
			t.Errorf("resourceGuardPath(%q) = %q; want %q as before", uri, got, want)
		}
	}
	home = newTargetHome(t)
	cfg := home + "/" + spDir
	t.Setenv("ZZ_SP_DIR", cfg)
	cmd := func(c string) map[string]interface{} { return map[string]interface{}{"command": c} }
	runGuardRows(t, []guardRow{
		// Main's reading of command text is unchanged here.
		{"POSIX: absolute path", "start_process", cmd("rm -rf " + cfg), true},
		{"POSIX: plain read", "start_process", cmd("cat " + cfg + "/audit.jsonl"), false},
		{"POSIX: Get-Content is not a plain read here", "start_process", cmd("Get-Content " + cfg + "/audit.jsonl"), true},
		{"POSIX: %VAR% is not expanded", "start_process", cmd(`rm -rf %ZZ_SP_DIR%`), false},
		{"POSIX: $env:VAR is not expanded", "start_process", cmd(`rm -rf $env:ZZ_SP_DIR`), false},
		{"POSIX: backslash is an escape", "start_process", cmd(`rm -rf ~/.agent\shield`), true},
	})
}

// The spellings an agent can use on Windows for the config directory and the
// hook files, each next to a benign near miss (#5060, #5062).
func TestConfigGuard_WindowsSpellings(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows spellings: drive letters, the environment and file:///C:/ URIs name this machine's files only on Windows")
	}
	home := newTargetHome(t)
	cfg := filepath.Join(home, spDir)
	notes := filepath.Join(home, "projects", spDir+"-notes")
	hook := filepath.Join(home, ".claude", "settings.json")
	other := filepath.Join(filepath.Dir(home), "other-user", spDir)
	t.Setenv("HOMEDRIVE", home[:2])
	t.Setenv("HOMEPATH", home[2:])
	slash := filepath.ToSlash
	lowerDrive := strings.ToLower(home[:1]) + home[1:]
	cmd := func(c string) map[string]interface{} { return map[string]interface{}{"command": c} }
	w := func(p string) map[string]interface{} { return map[string]interface{}{"path": p, "content": "{}"} }

	runGuardRows(t, []guardRow{
		// #5060: command text.
		{"drive, backslash", "start_process", cmd(`Remove-Item -Recurse -Force ` + cfg), true},
		{"drive, slash", "start_process", cmd(`rm -rf ` + slash(cfg)), true},
		{"drive, lower-case letter", "start_process", cmd(`Remove-Item -Recurse ` + lowerDrive + `\` + spDir), true},
		{"drive, all lower case (NTFS folds)", "start_process", cmd(`Remove-Item -Recurse ` + strings.ToLower(cfg)), true},
		{"%USERPROFILE%", "start_process", cmd(`del %USERPROFILE%\` + spDir + `\managed.json`), true},
		{"%userprofile%, lower case", "start_process", cmd(`rd /s /q %userprofile%\` + spDir), true},
		{"%HOMEDRIVE%%HOMEPATH%", "start_process", cmd(`rd /s /q %HOMEDRIVE%%HOMEPATH%\` + spDir), true},
		{"$env:USERPROFILE", "start_process", cmd(`Remove-Item -Recurse -Force $env:USERPROFILE\` + spDir), true},
		{"${env:USERPROFILE}", "start_process", cmd(`Remove-Item -Recurse -Force ${env:USERPROFILE}\` + spDir), true},
		{"PowerShell $HOME", "start_process", cmd(`Remove-Item -Recurse $HOME\` + spDir), true},
		{"PowerShell $home, lower case", "start_process", cmd(`Remove-Item -Recurse $home\` + spDir), true},
		{"PowerShell ~\\", "start_process", cmd(`Remove-Item -Recurse ~\` + spDir), true},
		{"quoted drive path", "start_process", cmd(`Remove-Item -Recurse "` + cfg + `"`), true},
		{"PowerShell backtick escape", "start_process", cmd("Remove-Item -Recurse " + home + "\\.agent`shield"), true},
		{"cmd caret escape", "start_process", cmd(`rd /s /q ` + home + `\.agent^shield`), true},
		{"interpreter, drive path", "start_process", cmd(`python -c "open('` + filepath.Join(cfg, "policy.yaml") + `','w')"`), true},
		{"hook file, drive path", "start_process", cmd(`Set-Content -Path ` + hook + ` -Value {}`), true},
		{"hook file, $env:USERPROFILE", "start_process", cmd(`echo {} > $env:USERPROFILE\.claude\settings.json`), true},
		{"redirect after a read word is no plain read", "start_process", cmd(`type ` + filepath.Join(cfg, "policy.yaml") + ` > C:\tmp\x`), true},
		{"pipe after a read word is no plain read", "start_process", cmd(`Get-Content ` + filepath.Join(cfg, "policy.yaml") + ` | Set-Content C:\tmp\x`), true},
		// #5060 controls: reads, near misses, and what this change leaves alone.
		{"near miss: .agentshield-notes, drive", "start_process", cmd(`Remove-Item -Recurse -Force ` + notes), false},
		{"near miss: .agentshield-notes, $env:USERPROFILE", "start_process", cmd(`Remove-Item -Recurse $env:USERPROFILE\projects\` + spDir + `-notes`), false},
		{"near miss: another user's directory", "start_process", cmd(`Remove-Item -Recurse ` + other), false},
		{"near miss: project-level config dir", "start_process", cmd(`Remove-Item -Recurse ` + filepath.Join(home, "projects", "app", "config", spDir)), false},
		{"near miss: unset variable", "start_process", cmd(`del %ZZ_NOT_SET_5060%\` + spDir + `\managed.json`), false},
		{"plain read: type", "start_process", cmd(`type ` + filepath.Join(cfg, "audit.jsonl")), false},
		{"plain read: Get-Content -Tail", "start_process", cmd(`Get-Content -Tail 5 $env:USERPROFILE\` + spDir + `\audit.jsonl`), false},
		{"plain read: dir", "start_process", cmd(`dir %USERPROFILE%\` + spDir), false},
		{"plain read: Get-ChildItem -Force", "start_process", cmd(`Get-ChildItem -Force ` + cfg), false},
		{"plain read: Test-Path", "start_process", cmd(`Test-Path ` + filepath.Join(cfg, "managed.json")), false},
		{"plain read: findstr", "start_process", cmd(`findstr BLOCK ` + filepath.Join(cfg, "audit.jsonl")), false},
		{"plain read: cat (main's plain read)", "start_process", cmd(`cat ` + filepath.Join(cfg, "audit.jsonl")), false},
		// The Windows read words exempt only the Windows reading: main's still
		// reads this, and blocked it before this change.
		{"main's reading is not exempted: type ~/", "start_process", cmd(`type ~/` + spDir + `/policy.yaml`), true},
		{"not command text: write_file content", "write_file", map[string]interface{}{"path": filepath.Join(home, "projects", "app", "notes.md"), "content": `Remove-Item ` + cfg}, false},
		{"not an exec tool: update_description input", "update_description", map[string]interface{}{"input": `Remove-Item ` + cfg}, false},
		{"unchanged (#5061, not decided here): drive-less, backslash", "start_process", cmd(`Remove-Item -Recurse ` + cfg[2:]), false},

		// #5062: file: URIs in a path argument.
		{"file:///C:/", "write_file", w(fileURI(filepath.Join(cfg, "managed.json"))), true},
		{"file://localhost/C:/", "write_file", w(fileURIHost("localhost", filepath.Join(cfg, "managed.json"))), true},
		{"file:///c:/, lower-case drive", "write_file", w("file:///" + slash(filepath.Join(lowerDrive, spDir, "managed.json"))), true},
		{"file:///C|/, legacy drive", "write_file", w("file:///" + home[:1] + "|" + slash(filepath.Join(cfg, "managed.json"))[2:]), true},
		{"file:///c%3A/, encoded colon (vscode-uri)", "write_file", w("file:///" + strings.ToLower(home[:1]) + "%3A" + slash(filepath.Join(cfg, "managed.json"))[2:]), true},
		{"file:/C:/, one slash", "write_file", w("file:/" + slash(filepath.Join(cfg, "managed.json"))), true},
		{"file://C:/, drive as authority", "write_file", w("file://" + slash(filepath.Join(cfg, "managed.json"))), true},
		{`file://C:\, as main's tests spelled it`, "write_file", w("file://" + filepath.Join(cfg, "managed.json")), true},
		{"file:///C:/, hook file", "write_file", w(fileURI(hook)), true},
		{"file:///C:/, Cursor MCP config", "write_file", w(fileURI(filepath.Join(home, ".cursor", "mcp.json"))), true},
		{"file:///C:/, Codex hooks", "write_file", w(fileURI(filepath.Join(home, ".codex", "hooks.json"))), true},
		{"file:///C:/ in command text", "start_process", cmd(`curl -T x ` + fileURI(filepath.Join(cfg, "managed.json"))), true},
		{"PowerShell ~\\ in a path argument", "write_file", w(`~\` + spDir + `\managed.json`), true},
		{"$HOME\\ in a path argument", "write_file", w(`$HOME\` + spDir + `\managed.json`), true},
		// #5062 controls.
		{"near miss: file:///C:/ to .agentshield-notes", "write_file", w(fileURI(filepath.Join(notes, "readme.md"))), false},
		{"near miss: file:///C:/ to another user's directory", "write_file", w(fileURI(filepath.Join(other, "managed.json"))), false},
		{"near miss: file://host/C:/ on another host", "write_file", w(fileURIHost("fileserver", filepath.Join(cfg, "managed.json"))), false},
		{"near miss: file:///C:/ read", "read_file", map[string]interface{}{"path": fileURI(filepath.Join(home, "projects", "app", "README.md"))}, false},
	})

	// End to end through the handler, with no rules: the guard alone blocks,
	// in enforce and in audit-only mode.
	for _, mode := range []string{"", "audit-only"} {
		var entries []AuditEntry
		h := newMessageHandler(NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "t", t.TempDir(), nil, nil)
		h.Mode = mode
		params, _ := json.Marshal(map[string]interface{}{"name": "start_process", "arguments": cmd(`Remove-Item -Recurse -Force $env:USERPROFILE\` + spDir)})
		raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": json.RawMessage(params)})
		msg, _, _ := ParseMessage(raw)
		if blocked, _ := h.HandleToolCall(msg); !blocked {
			t.Errorf("mode %q: start_process Remove-Item $env:USERPROFILE\\%s forwarded; want BLOCK (record %+v)", mode, spDir, entries)
		}
	}
}

// A Windows profile directory with a space in it (C:\Users\John Smith): a
// quoted path and an environment reference are one word to the shell, and so
// to the guard.
func TestConfigGuard_WindowsSpacedHome(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows spellings")
	}
	home := filepath.Join(t.TempDir(), "John Smith")
	if err := os.MkdirAll(filepath.Join(home, spDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, spDir, "managed.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestHome(t, home)
	cfg := filepath.Join(home, spDir)
	cmd := func(c string) map[string]interface{} { return map[string]interface{}{"command": c} }
	runGuardRows(t, []guardRow{
		{"double-quoted drive path", "start_process", cmd(`Remove-Item -Recurse -Force "` + cfg + `"`), true},
		{"single-quoted drive path", "start_process", cmd(`Remove-Item -Recurse -Force '` + cfg + `'`), true},
		{"interpreter, quoted drive path", "start_process", cmd(`python -c "import shutil; shutil.rmtree('` + cfg + `')"`), true},
		{"$env:USERPROFILE", "start_process", cmd(`Remove-Item -Recurse $env:USERPROFILE\` + spDir), true},
		{"%USERPROFILE%, quoted", "start_process", cmd(`rd /s /q "%USERPROFILE%\` + spDir + `"`), true},
		{"file:/// URI, %20", "write_file", map[string]interface{}{"path": "file:///" + strings.ReplaceAll(filepath.ToSlash(filepath.Join(cfg, "managed.json")), " ", "%20")}, true},
		// Unquoted, the shell reads two words, neither of them the directory.
		{"unquoted: two words", "start_process", cmd(`Remove-Item -Recurse ` + cfg), false},
	})
}

// resources/read and resources/subscribe of file: URIs on Windows (#5062).
// The guard's plain patterns are anchored to the home at package init.
func TestResourceGuard_WindowsFileURIs(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows file: URIs")
	}
	initHome := guardHome()
	if initHome == "" {
		t.Skip("no home directory")
	}
	native := func(rel string) string { return filepath.Join(initHome, filepath.FromSlash(rel)) }
	lowerDrive := func(rel string) string {
		return "file:///" + strings.ToLower(initHome[:1]) + filepath.ToSlash(native(rel))[1:]
	}
	encoded := func(rel string) string {
		return "file:///" + strings.ToLower(initHome[:1]) + "%3A" + filepath.ToSlash(native(rel))[2:]
	}
	ev := NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}})
	for _, r := range []struct {
		name, uri string
		want      policy.Decision
	}{
		{".bashrc", fileURI(native(".bashrc")), policy.DecisionBlock},
		{".gitconfig", fileURI(native(".gitconfig")), policy.DecisionBlock},
		{".kube/config", fileURI(native(".kube/config")), policy.DecisionBlock},
		{".docker/config.json", fileURI(native(".docker/config.json")), policy.DecisionBlock},
		{".ssh/config", fileURI(native(".ssh/config")), policy.DecisionBlock},
		{".claude/settings.json", fileURI(native(".claude/settings.json")), policy.DecisionBlock},
		{".cursor/mcp.json", fileURI(native(".cursor/mcp.json")), policy.DecisionBlock},
		{".codex/hooks.json", fileURI(native(".codex/hooks.json")), policy.DecisionBlock},
		{"config dir", fileURI(native(spDir + "/managed.json")), policy.DecisionBlock},
		{"lower-case drive (vscode-uri)", lowerDrive(".docker/config.json"), policy.DecisionBlock},
		{"encoded colon, lower-case drive (vscode-uri)", encoded(".kube/config"), policy.DecisionBlock},
		{"legacy drive |", "file:///" + initHome[:1] + "|" + filepath.ToSlash(native(".bashrc"))[2:], policy.DecisionBlock},
		{"control: without the slash before the drive", "file://" + filepath.ToSlash(native(".bashrc")), policy.DecisionBlock},
		{"near miss: a project file", fileURI(native("projects/app/.bashrc")), policy.DecisionAudit},
		{"near miss: another user's .bashrc", fileURI(filepath.Join(filepath.Dir(initHome), "other-user", ".bashrc")), policy.DecisionAudit},
		{"near miss: another drive", "file:///Q:/" + filepath.ToSlash(native(".bashrc"))[3:], policy.DecisionAudit},
		// As on unix, resources/read reads no authority: file://localhost/... is
		// AUDIT on every platform (unchanged, see the PR).
		{"unchanged: file://localhost/C:/", fileURIHost("localhost", native(".bashrc")), policy.DecisionAudit},
	} {
		if got := ev.EvaluateResourceRead(r.uri); got.Decision != r.want {
			t.Errorf("%s: EvaluateResourceRead(%s) = %s %v; want %s", r.name, r.uri, got.Decision, got.TriggeredRules, r.want)
		}
	}

	h := newMessageHandler(ev, nil, io.Discard, "t", t.TempDir(), nil, nil)
	for _, r := range []struct {
		uri   string
		block bool
	}{
		{fileURI(native(".docker/config.json")), true},
		{fileURI(native("projects/app/notes.md")), false},
	} {
		params, _ := json.Marshal(map[string]interface{}{"uri": r.uri})
		raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": MethodResourcesSubscribe, "params": json.RawMessage(params)})
		msg, _, _ := ParseMessage(raw)
		if blocked, _ := h.HandleResourceSubscribe(msg); blocked != r.block {
			t.Errorf("resources/subscribe %s: blocked = %v; want %v", r.uri, blocked, r.block)
		}
	}
}

// Codex pass on #5064, finding 1: main's reading runs first. On Windows a
// literal "$HOME" directory is a valid relative path. With the proxy's working
// directory inside the config directory, main resolves `$HOME\x` beneath it
// and refuses the write. Expanding `$HOME` first would check the profile's
// `x` instead and allow it, while the server writes inside the config dir.
func TestConfigGuard_WindowsLiteralHOMEUnderProtectedCwd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows spellings")
	}
	home := t.TempDir()
	cfg := filepath.Join(home, spDir)
	if err := os.MkdirAll(filepath.Join(cfg, "$HOME"), 0o700); err != nil {
		t.Fatal(err)
	}
	setTestHome(t, home)
	t.Chdir(cfg)
	w := func(p string) map[string]interface{} { return map[string]interface{}{"path": p, "content": "{}"} }
	runGuardRows(t, []guardRow{
		{"literal $HOME dir under the protected cwd", "write_file", w(`$HOME\notes.txt`), true},
		{"literal ${HOME} dir under the protected cwd", "write_file", w(`${HOME}\notes.txt`), true},
	})
	t.Chdir(home)
	runGuardRows(t, []guardRow{
		// The Windows reading still adds what #5064 added once main misses.
		{"$HOME\\ into the config dir, cwd elsewhere", "write_file", w(`$HOME\` + spDir + `\policy.yaml`), true},
		{"control: $HOME\\ to an unprotected file", "write_file", w(`$HOME\notes.txt`), false},
	})
}

// Codex pass on #5064, finding 2: a file: URL percent-encodes its path (a
// profile "John Smith" is John%20Smith) and the server decodes it, so the
// guard decodes the Windows drive path too.
func TestResourceGuardPath_WindowsDecodesPercentEncoding(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows file: URIs")
	}
	for _, r := range []struct{ uri, want string }{
		{"file:///Q:/Users/John%20Smith/x", "Q:/Users/John Smith/x"},
		{"file:///Q:/Users/u/%2E" + spDir[1:] + "/managed.json", "Q:/Users/u/" + spDir + "/managed.json"},
		{"file:///q%3A/Users/u/x", "q:/Users/u/x"},
	} {
		if got := resourceGuardPath(r.uri); !strings.EqualFold(got, r.want) {
			t.Errorf("resourceGuardPath(%q) = %q; want %q", r.uri, got, r.want)
		}
	}
}

// The same through resources/read: an encoded protected path still blocks.
func TestResourceGuard_WindowsPercentEncodedPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows file: URIs")
	}
	initHome := guardHome()
	if initHome == "" {
		t.Skip("no home directory")
	}
	native := filepath.ToSlash(filepath.Join(initHome, spDir, "managed.json"))
	enc := "file:///" + strings.Replace(strings.ReplaceAll(native, " ", "%20"), "/"+spDir+"/", "/%2E"+spDir[1:]+"/", 1)
	ev := NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}})
	if got := ev.EvaluateResourceRead(enc); got.Decision != policy.DecisionBlock {
		t.Fatalf("resources/read %q = %v; want BLOCK", enc, got.Decision)
	}
}
