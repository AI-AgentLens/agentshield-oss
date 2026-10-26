package enterprise

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Tests for the watchdog's Claude Code managed-scope check (#4292 PR B). The
// managed settings file is always a temp file (ClaudeManagedSettingsPath is
// pointed at it); the real /Library, /etc and C:\Program Files paths are
// never read.

const (
	execHookSettings  = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`
	shellHookSettings = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`
)

// scopeFixture is one machine: a HOME, an AgentShield config dir, and a
// managed settings path the watchdog reads.
type scopeFixture struct {
	home, configDir, managedPath string
}

func newScopeFixture(t *testing.T) scopeFixture {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("COPILOT_HOME", "")
	f := scopeFixture{
		home:        home,
		configDir:   filepath.Join(home, ".agentshield"),
		managedPath: filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json"),
	}
	prev := ClaudeManagedSettingsPath
	ClaudeManagedSettingsPath = func() string { return f.managedPath }
	t.Cleanup(func() { ClaudeManagedSettingsPath = prev })
	if err := os.MkdirAll(f.configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	return f
}

func writeFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f scopeFixture) managedJSON(t *testing.T, content string) {
	writeFixtureFile(t, filepath.Join(f.configDir, "managed.json"), content)
}

func (f scopeFixture) userSettings(t *testing.T, content string) {
	writeFixtureFile(t, filepath.Join(f.home, ".claude", "settings.json"), content)
}

func (f scopeFixture) managedSettings(t *testing.T, content string) {
	writeFixtureFile(t, f.managedPath, content)
}

// managedScopeChecks returns every check the watchdog reports under the
// managed-scope name.
func (f scopeFixture) managedScopeChecks() []WatchdogCheck {
	var out []WatchdogCheck
	for _, c := range RunWatchdogOnce(f.configDir) {
		if c.Name == ClaudeManagedHookCheckName {
			out = append(out, c)
		}
	}
	return out
}

func (f scopeFixture) check(t *testing.T, name string) (WatchdogCheck, bool) {
	t.Helper()
	for _, c := range RunWatchdogOnce(f.configDir) {
		if c.Name == name {
			return c, true
		}
	}
	return WatchdogCheck{}, false
}

// In managed mode with the hook only at user scope, the watchdog reports the
// managed scope as failing, and still passes the user-scope check.
func TestWatchdogManagedScope_UserScopeOnlyIsReported(t *testing.T) {
	f := newScopeFixture(t)
	f.managedJSON(t, `{"managed":true}`)
	f.userSettings(t, execHookSettings)

	checks := f.managedScopeChecks()
	if len(checks) != 1 {
		t.Fatalf("managed-scope checks = %d; want exactly 1: %+v", len(checks), checks)
	}
	c := checks[0]
	if c.Passed {
		t.Fatalf("hook at user scope only passed the managed-scope check: %s", c.Message)
	}
	for _, want := range []string{"managed missing", f.managedPath, "user present", "disableAllHooks", "--managed", "--write-managed"} {
		if !strings.Contains(c.Message, want) {
			t.Errorf("message does not say %q:\n%s", want, c.Message)
		}
	}
	if u, ok := f.check(t, "hook-claude-code"); !ok || !u.Passed {
		t.Errorf("the user-scope check must stay and pass: found=%v %+v", ok, u)
	}
}

// With the hook in managed settings, the check passes and names both scopes.
func TestWatchdogManagedScope_HookInManagedSettingsPasses(t *testing.T) {
	for _, tc := range []struct{ name, managed string }{
		{"exec form", execHookSettings},
		{"shell form", shellHookSettings},
		{"beside org keys and hooks", `{"model":"opus","permissions":{"deny":["Read(./.env)"]},"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"/usr/local/bin/banner"}]}],"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/org-audit"}]},{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`},
		{"UTF-8 BOM", "\xef\xbb\xbf" + execHookSettings},
		{"disableAllHooks false", `{"disableAllHooks":false,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScopeFixture(t)
			f.managedJSON(t, `{"managed":true}`)
			f.userSettings(t, execHookSettings)
			f.managedSettings(t, tc.managed)
			checks := f.managedScopeChecks()
			if len(checks) != 1 || !checks[0].Passed {
				t.Fatalf("checks = %+v; want one passing managed-scope check", checks)
			}
			if m := checks[0].Message; !strings.Contains(m, "managed present") || !strings.Contains(m, "user present") {
				t.Errorf("a passing check must still name the scopes: %s", m)
			}
		})
	}
}

// Every way the managed file can fail to carry a hook that runs is reported.
func TestWatchdogManagedScope_BrokenManagedSettingsReported(t *testing.T) {
	for _, tc := range []struct{ name, managed, want string }{
		{"no hooks", `{"model":"opus"}`, "managed missing"},
		{"hook under another event", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, "managed missing"},
		{"exec form with args removed", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield"}]}]}}`, "managed missing"},
		{"echo wrapper", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"echo agentshield hook"}]}]}}`, "managed missing"},
		{"malformed", `{"hooks":`, "managed broken"},
		// Claude Code reads an empty managed settings file as {}: valid JSON,
		// no hook. It is not "broken" (#4428 review).
		{"empty file", "", "managed empty (Claude Code reads it as {}): no AgentShield hook"},
		{"whitespace only", " \n", "managed empty (Claude Code reads it as {}): no AgentShield hook"},
		{"managed disableAllHooks", `{"disableAllHooks":true,"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, "managed off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScopeFixture(t)
			f.managedJSON(t, `{"managed":true}`)
			f.managedSettings(t, tc.managed)
			checks := f.managedScopeChecks()
			if len(checks) != 1 || checks[0].Passed {
				t.Fatalf("checks = %+v; want one failing managed-scope check", checks)
			}
			if !strings.Contains(checks[0].Message, tc.want) {
				t.Errorf("message does not say %q:\n%s", tc.want, checks[0].Message)
			}
			if strings.TrimSpace(tc.managed) == "" {
				if strings.Contains(checks[0].Message, "broken") || strings.Contains(checks[0].Message, "does not parse") {
					t.Errorf("an empty file is not broken JSON:\n%s", checks[0].Message)
				}
			}
		})
	}
}

// A managed settings file the watchdog cannot read is reported, not passed.
func TestWatchdogManagedScope_UnreadableReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("root ignores permission bits")
	}
	f := newScopeFixture(t)
	f.managedJSON(t, `{"managed":true}`)
	f.managedSettings(t, execHookSettings)
	if err := os.Chmod(f.managedPath, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(f.managedPath, 0o644) })
	checks := f.managedScopeChecks()
	if len(checks) != 1 || checks[0].Passed || !strings.Contains(checks[0].Message, "managed unreadable") {
		t.Fatalf("checks = %+v; want one failing check saying the file is unreadable", checks)
	}
}

// With no user settings file at all, the message says the user scope is
// missing too.
func TestWatchdogManagedScope_NoScopeCarriesTheHook(t *testing.T) {
	f := newScopeFixture(t)
	f.managedJSON(t, `{"managed":true}`)
	checks := f.managedScopeChecks()
	if len(checks) != 1 || checks[0].Passed {
		t.Fatalf("checks = %+v; want one failing check", checks)
	}
	if m := checks[0].Message; !strings.Contains(m, "managed missing") || !strings.Contains(m, "user missing") {
		t.Errorf("message must name both scopes as missing: %s", m)
	}
}

// Outside managed mode the watchdog adds no managed-scope check, so its
// output is what it was before #4292 PR B, even when the managed settings
// file is missing.
func TestWatchdogManagedScope_NotManagedUnchanged(t *testing.T) {
	for _, tc := range []struct{ name, managedJSON string }{
		{"no managed.json", ""},
		{"managed false", `{"managed":false}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newScopeFixture(t)
			if tc.managedJSON != "" {
				f.managedJSON(t, tc.managedJSON)
			}
			f.userSettings(t, execHookSettings)
			if checks := f.managedScopeChecks(); len(checks) != 0 {
				t.Errorf("outside managed mode the watchdog reported %+v", checks)
			}
			var names []string
			for _, c := range RunWatchdogOnce(f.configDir) {
				names = append(names, c.Name)
			}
			want := []string{"hook-claude-code", "policy-file", "managed-config", "bypass-env"}
			if strings.Join(names, ",") != strings.Join(want, ",") {
				t.Errorf("checks = %v; want %v", names, want)
			}
		})
	}
}

// A managed.json that does not parse counts as managed (fail closed, #3620),
// so the managed-scope check runs.
func TestWatchdogManagedScope_CorruptManagedJSONCountsAsManaged(t *testing.T) {
	f := newScopeFixture(t)
	f.managedJSON(t, `{"managed":`)
	if checks := f.managedScopeChecks(); len(checks) != 1 || checks[0].Passed {
		t.Errorf("checks = %+v; want the failing managed-scope check", checks)
	}
}

// The production path is Claude Code's documented one for this OS.
func TestClaudeManagedSettingsPath_Default(t *testing.T) {
	want := map[string]string{
		"darwin":  "/Library/Application Support/ClaudeCode/managed-settings.json",
		"linux":   "/etc/claude-code/managed-settings.json",
		"windows": `C:\Program Files\ClaudeCode\managed-settings.json`,
	}[runtime.GOOS]
	if want == "" {
		t.Skip("no documented path for", runtime.GOOS)
	}
	if got := ClaudeManagedSettingsPath(); got != want {
		t.Errorf("ClaudeManagedSettingsPath() = %q; want %q", got, want)
	}
}
