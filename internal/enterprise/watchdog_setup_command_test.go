package enterprise

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/testhome"
)

// setupHookFiles writes the five non-Claude hook files the watchdog reads,
// each holding cmd where setup puts its command: Gemini CLI, Codex and
// Copilot CLI in the shape setup writes (internal/cli/setup.go,
// setup_copilot.go), Windsurf and Cursor in their template's shape.
func setupHookFiles(t *testing.T, home, cmd string) {
	t.Helper()
	writeHookFiles(t, home, cmd, nil)
}

// writeHookFiles is setupHookFiles with extra keys merged into each file's
// hook object, beside its command.
func writeHookFiles(t *testing.T, home, cmd string, extra map[string]interface{}) {
	t.Helper()
	t.Setenv("COPILOT_HOME", "")
	hook := func(kv ...interface{}) map[string]interface{} {
		m := map[string]interface{}{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	files := map[string]interface{}{
		filepath.Join(home, ".gemini", "settings.json"): map[string]interface{}{"hooks": map[string]interface{}{"BeforeTool": []interface{}{
			map[string]interface{}{"matcher": "run_shell_command", "hooks": []interface{}{
				hook("type", "command", "command", cmd, "name", "agentshield", "timeout", 10000),
			}},
		}}},
		filepath.Join(home, ".codex", "hooks.json"): map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
			map[string]interface{}{"matcher": "^Bash$", "hooks": []interface{}{
				hook("type", "command", "command", cmd, "timeout", 10, "statusMessage", "AgentShield: shell commands"),
			}},
		}}},
		filepath.Join(home, ".copilot", "hooks", "agentshield.json"): map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"PreToolUse": []interface{}{
			hook("type", "command", "bash", cmd, "env", map[string]interface{}{"AGENTSHIELD_AGENT_ID": "copilot-cli"}, "timeoutSec", 30),
		}}},
		filepath.Join(home, ".codeium", "windsurf", "hooks.json"): map[string]interface{}{"hooks": map[string]interface{}{"pre_run_command": []interface{}{
			hook("command", cmd, "show_output", true),
		}}},
		filepath.Join(home, ".cursor", "hooks.json"): map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"beforeShellExecution": []interface{}{
			hook("command", cmd),
		}}},
	}
	for path, doc := range files {
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

var nonClaudeHookChecks = []string{"hook-gemini-cli", "hook-codex", "hook-copilot-cli", "hook-windsurf", "hook-cursor"}

func hookChecks(t *testing.T, configDir string) map[string]WatchdogCheck {
	t.Helper()
	got := map[string]WatchdogCheck{}
	for _, c := range RunWatchdogOnce(configDir) {
		got[c.Name] = c
	}
	for _, name := range nonClaudeHookChecks {
		if _, ok := got[name]; !ok {
			t.Fatalf("the watchdog ran no %s check; the fixture did not reach it (checks: %v)", name, got)
		}
	}
	return got
}

// setupBinaryPath is where the installer puts the binary
// (scripts/install.ps1: %LOCALAPPDATA%\Programs\AgentShield), under home,
// with the name it has on this OS.
func setupBinaryPath(home string) string {
	p := filepath.Join(home, "AppData", "Local", "Programs", "AgentShield", "agentshield")
	if runtime.GOOS == "windows" {
		p += ".exe"
	}
	return p
}

// installBinary puts a non-empty file at setupBinaryPath(home), as the
// installer would, and returns its path.
func installBinary(t *testing.T, home string) string {
	t.Helper()
	bin := setupBinaryPath(home)
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

// TestWatchdog_SetupCommandOnThisOSIsHealthy (#5066): every hook file holds
// `<binPath> hook`, the command setup writes, with binPath an absolute path
// on this OS. On Windows that is `C:\...\agentshield.exe hook`, which the
// "agentshield hook" substring misses; before #5066 each pass reported all
// five hooks as possibly disabled on a managed Windows host. On macOS and
// Linux it pins the unchanged substring path.
func TestWatchdog_SetupCommandOnThisOSIsHealthy(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := installBinary(t, home) + " hook"
	setupHookFiles(t, home, cmd)

	got := hookChecks(t, configDir)
	for _, name := range nonClaudeHookChecks {
		if c := got[name]; !c.Passed {
			t.Errorf("%s failed for the command setup writes on %s (%q): %s", name, runtime.GOOS, cmd, c.Message)
		}
	}

	// What the loop does with it: a failing hook check is a flagged tamper
	// event (and webhook alert) on every tick (watchdog_events.go). Two
	// ticks of the real loop must log none for these hooks.
	tr := newWatchdogTracker(configDir)
	var tamper []string
	for tick := 0; tick < 2; tick++ {
		watchdogTick(configDir, tr, func(e logger.AuditEvent) error {
			for _, name := range nonClaudeHookChecks {
				if e.Flagged && strings.HasPrefix(e.Error, name+":") {
					tamper = append(tamper, e.Error)
				}
			}
			return nil
		}, func(watchdogEvent) {})
	}
	if len(tamper) > 0 {
		t.Errorf("%d flagged tamper events in 2 ticks for the hooks setup wrote:\n%s", len(tamper), strings.Join(tamper, "\n"))
	}
}

// TestWatchdog_SetupCommandWithItsBinaryGone (#5072 pass 2, finding 2): on
// Windows the watchdog reports `C:\...\agentshield.exe hook` healthy only
// while that program is a non-empty file. Deleted, an empty file, or a
// directory in its place, each of the five hooks is reported missing, as
// main reported it. Off Windows the command is main's `/.../agentshield hook`,
// judged by the substring as before, so it stays healthy with no binary.
func TestWatchdog_SetupCommandWithItsBinaryGone(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := installBinary(t, home)
	setupHookFiles(t, home, bin+" hook")
	want := runtime.GOOS != "windows"
	for _, state := range []struct {
		name   string
		change func() error
	}{
		{"deleted", func() error { return os.Remove(bin) }},
		{"an empty file", func() error { return os.WriteFile(bin, nil, 0o755) }},
		{"a directory named agentshield.exe", func() error {
			if err := os.Remove(bin); err != nil {
				return err
			}
			return os.Mkdir(bin, 0o755)
		}},
	} {
		if err := state.change(); err != nil {
			t.Fatal(err)
		}
		got := hookChecks(t, configDir)
		for _, name := range nonClaudeHookChecks {
			if c := got[name]; c.Passed != want {
				t.Errorf("binary %s: %s passed = %v on %s, want %v (%q): %s", state.name, name, c.Passed, runtime.GOOS, want, bin+" hook", c.Message)
			}
		}
	}
}

// TestWatchdog_SetupCommandOnlyInMetadataIsMissing (#5072 pass 2, finding
// 1): the hook each file runs is another program, and setup's command
// survives only beside it, in a key the harness does not run. On Windows the
// watchdog reports all five missing, as main did; the binary exists, so the
// verdict rests on where the command is. Off Windows the command is main's
// `/.../agentshield hook`, which main's substring finds anywhere in the
// file: that looseness is unchanged and pinned. The reverse control has the
// command where the harness runs it, and another value beside it.
func TestWatchdog_SetupCommandOnlyInMetadataIsMissing(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ours := installBinary(t, home) + " hook"
	other := filepath.Join(filepath.Dir(setupBinaryPath(home)), "other.exe")
	for _, tc := range []struct {
		name       string
		cmd, extra string
		want       bool
	}{
		{"setup's command only in statusMessage", other, ours, runtime.GOOS != "windows"},
		{"control: setup's command, statusMessage another value", ours, other, true},
	} {
		writeHookFiles(t, home, tc.cmd, map[string]interface{}{"statusMessage": tc.extra})
		got := hookChecks(t, configDir)
		for _, name := range nonClaudeHookChecks {
			if c := got[name]; c.Passed != tc.want {
				t.Errorf("%s: %s passed = %v on %s, want %v: %s", tc.name, name, c.Passed, runtime.GOOS, tc.want, c.Message)
			}
		}
	}
}

// TestWatchdog_SetupCommandLookalikesAreTamper: the wider Windows test must
// not hide a replaced hook. Each command names another program, or passes
// ours to another program, and fails the check on every OS.
func TestWatchdog_SetupCommandLookalikesAreTamper(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	configDir := filepath.Join(home, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	bin := setupBinaryPath(home)
	dir := filepath.Dir(bin)
	for _, cmd := range []string{
		filepath.Join(dir, "agentshield-helper.exe") + " hook",
		filepath.Join(dir, "notagentshield.exe") + " hook",
		"echo " + filepath.Join(dir, "agentshield.exe") + " hook",
		"cmd /c " + filepath.Join(dir, "agentshield.exe") + " hook",
		filepath.Join(dir, "agentshield.exe") + " hook --help",
		filepath.Join(dir, "other.exe"),
	} {
		setupHookFiles(t, home, cmd)
		got := hookChecks(t, configDir)
		for _, name := range nonClaudeHookChecks {
			if c := got[name]; c.Passed {
				t.Errorf("%s passed for %q on %s; a replaced hook must be reported", name, cmd, runtime.GOOS)
			}
		}
	}
}

// TestWatchdog_ClaudeCodeShellFormMustBeOneThatStarts (#5072 review): Claude
// Code on Windows runs a shell-form hook through Git Bash, which drops
// unquoted backslashes. `C:\...\agentshield.exe hook` then exits 127, a
// non-blocking error, and the tool call runs (measured with Claude Code
// 2.1.302 on Windows 10). The watchdog must report that entry as missing, as
// it did before #5066, so a hand edit that turns exec form into it (drop
// "args", append " hook") is still a tamper event. The forward-slash spelling,
// which setup writes into the shell form on Windows, and exec form both start
// and are healthy. Off Windows a backslash in an unquoted word is an escape
// too, so the table holds on every OS.
func TestWatchdog_ClaudeCodeShellFormMustBeOneThatStarts(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	configDir := filepath.Join(home, ".agentshield")
	for _, d := range []string{configDir, filepath.Join(home, ".claude")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bin := installBinary(t, home)
	backslashed := strings.ReplaceAll(bin, "/", `\`)
	// gone names a binary that does not exist. On Windows the forward-slash
	// shell form is the spelling only Windows accepts, so it must name a
	// file (#5072 pass 2); off Windows it is main's spelling, judged by its
	// words. Exec form is main's on every OS (#4717) and stays as it was.
	gone := filepath.Join(filepath.Dir(bin), "gone", filepath.Base(bin))
	cases := []struct {
		name string
		hook map[string]interface{}
		want bool
	}{
		{"exec form", map[string]interface{}{"type": "command", "command": bin, "args": []interface{}{"hook"}}, true},
		{"shell form, forward slashes", map[string]interface{}{"type": "command", "command": filepath.ToSlash(bin) + " hook"}, true},
		{"shell form, backslashes", map[string]interface{}{"type": "command", "command": backslashed + " hook"}, false},
		{"control: another program", map[string]interface{}{"type": "command", "command": filepath.ToSlash(filepath.Join(filepath.Dir(bin), "other.exe")) + " hook"}, false},
		{"shell form, forward slashes, binary missing", map[string]interface{}{"type": "command", "command": filepath.ToSlash(gone) + " hook"}, runtime.GOOS != "windows"},
		{"exec form, binary missing (main's form, unchanged)", map[string]interface{}{"type": "command", "command": gone, "args": []interface{}{"hook"}}, true},
	}
	for _, tc := range cases {
		doc := map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
			map[string]interface{}{"hooks": []interface{}{tc.hook}},
		}}}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}
		var check *WatchdogCheck
		for _, c := range RunWatchdogOnce(configDir) {
			if c.Name == "hook-claude-code" {
				c := c
				check = &c
			}
		}
		if check == nil {
			t.Fatalf("%s: the watchdog ran no hook-claude-code check", tc.name)
		}
		if check.Passed != tc.want {
			t.Errorf("%s on %s: hook-claude-code passed = %v, want %v (command %q): %s", tc.name, runtime.GOOS, check.Passed, tc.want, tc.hook["command"], check.Message)
		}
	}
}

// The managed-scope check (hook-claude-code-managed) and its report of the
// user scope read the settings the same way (hookentry.Present, #5072 pass
// 2): setup's forward-slash shell form counts while its binary is a file, and
// on Windows not once it is gone. Off Windows it is main's spelling, judged
// by its words.
func TestWatchdogManagedScope_ShellFormBinaryGone(t *testing.T) {
	f := newScopeFixture(t)
	f.managedJSON(t, `{"managed":true}`)
	bin := installBinary(t, f.home)
	settings, err := json.Marshal(map[string]interface{}{"hooks": map[string]interface{}{"PreToolUse": []interface{}{
		map[string]interface{}{"hooks": []interface{}{map[string]interface{}{"type": "command", "command": filepath.ToSlash(bin) + " hook"}}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	f.managedSettings(t, string(settings))
	f.userSettings(t, string(settings))

	c, ok := f.check(t, ClaudeManagedHookCheckName)
	if !ok || !c.Passed || !strings.Contains(c.Message, "managed present") || !strings.Contains(c.Message, "user present") {
		t.Fatalf("binary present: %s = %+v, want passed with both scopes present", ClaudeManagedHookCheckName, c)
	}
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	c, _ = f.check(t, ClaudeManagedHookCheckName)
	want, scopes := true, []string{"managed present", "user present"}
	if runtime.GOOS == "windows" {
		want, scopes = false, []string{"managed missing", "user missing"}
	}
	if c.Passed != want {
		t.Errorf("binary deleted on %s: %s passed = %v, want %v: %s", runtime.GOOS, ClaudeManagedHookCheckName, c.Passed, want, c.Message)
	}
	for _, s := range scopes {
		if !strings.Contains(c.Message, s) {
			t.Errorf("binary deleted on %s: message does not say %q: %s", runtime.GOOS, s, c.Message)
		}
	}
}
