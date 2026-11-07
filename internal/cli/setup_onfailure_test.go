package cli

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/homedir"
)

// These tests pin the "onFailure": "block" key on AgentShield's Claude Code
// hook entry: written where the hook itself runs fail_closed, absent
// everywhere else, converging on re-run, and never touching a hook object
// that is not AgentShield's. Every test runs in a temp HOME.

const (
	managedFailClosed   = `{"managed": true, "fail_closed": true}`
	managedNoFailClosed = `{"managed": true}`
)

// setManagedJSON writes ~/.agentshield/managed.json under the HOME that
// setupClaudeHome set, or removes it when content is "".
func setManagedJSON(t *testing.T, settingsPath, content string) {
	t.Helper()
	home := filepath.Dir(filepath.Dir(settingsPath))
	path := filepath.Join(home, ".agentshield", "managed.json")
	if content == "" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// onFailureValues returns the "onFailure" value of every AgentShield hook
// object ("<absent>" when the key is missing).
func onFailureValues(settings map[string]interface{}) []string {
	var out []string
	for _, h := range agentShieldHooks(settings) {
		v, ok := h[claudeOnFailureKey]
		if !ok {
			out = append(out, "<absent>")
			continue
		}
		s, _ := v.(string)
		out = append(out, s)
	}
	return out
}

func requireOnFailure(t *testing.T, settings map[string]interface{}, want string) {
	t.Helper()
	got := onFailureValues(settings)
	if len(got) == 0 {
		t.Fatal("no AgentShield hook object in the settings")
	}
	for i, v := range got {
		if v != want {
			t.Errorf("AgentShield hook %d onFailure = %s; want %s (all: %v)", i, v, want, got)
		}
	}
}

// The key follows the hook's own fail_closed predicate (failClosedEnabled):
// managed fail_closed and an unreadable managed.json (#3620 reads it as
// fail_closed) get it; managed without fail_closed and unmanaged do not.
func TestSetupClaudeCode_OnFailureFollowsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name, managed, want string
	}{
		{"managed fail_closed", managedFailClosed, claudeOnFailureBlock},
		{"corrupt managed.json reads as fail_closed", `{not json`, claudeOnFailureBlock},
		{"managed without fail_closed", managedNoFailClosed, "<absent>"},
		{"unmanaged", "", "<absent>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settingsPath := setupClaudeHome(t)
			setManagedJSON(t, settingsPath, tc.managed)

			out := runSetupClaudeCode(t, false)

			settings := readSettingsFile(t, settingsPath)
			requireOneExecHook(t, settings)
			requireOnFailure(t, settings, tc.want)
			if tc.want == claudeOnFailureBlock && !strings.Contains(out, `"onFailure": "block"`) {
				t.Errorf("output does not say the key was written:\n%s", out)
			}
		})
	}
}

// The file carries Claude Code's spelling, byte for byte: the key
// "onFailure" and the value "block" (code.claude.com/docs/en/hooks). Every
// other test compares against the package constants, so this is the one that
// fails if a constant drifts from what Claude Code reads.
func TestSetupClaudeCode_OnFailureWireSpelling(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	setManagedJSON(t, settingsPath, managedFailClosed)
	runSetupClaudeCode(t, false)
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"onFailure": "block"`)) {
		t.Errorf("settings lack the literal \"onFailure\": \"block\":\n%s", data)
	}
}

// Re-running setup converges: the key arrives when fail_closed is turned on,
// goes when it is turned off, and a run with nothing to change rewrites
// nothing.
func TestSetupClaudeCode_OnFailureConverges(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	read := func() []byte {
		b, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	runSetupClaudeCode(t, false)
	requireOnFailure(t, readSettingsFile(t, settingsPath), "<absent>")

	setManagedJSON(t, settingsPath, managedFailClosed)
	out := runSetupClaudeCode(t, false)
	requireOnFailure(t, readSettingsFile(t, settingsPath), claudeOnFailureBlock)
	if !strings.Contains(out, "PreToolUse hook updated") {
		t.Errorf("turning fail_closed on did not report an update:\n%s", out)
	}
	on := read()
	runSetupClaudeCode(t, false)
	if again := read(); !bytes.Equal(on, again) {
		t.Errorf("idempotent re-run under fail_closed rewrote the file:\n%s\n%s", on, again)
	}

	setManagedJSON(t, settingsPath, managedNoFailClosed)
	runSetupClaudeCode(t, false)
	requireOnFailure(t, readSettingsFile(t, settingsPath), "<absent>")
	off := read()
	runSetupClaudeCode(t, false)
	if again := read(); !bytes.Equal(off, again) {
		t.Errorf("idempotent re-run without fail_closed rewrote the file:\n%s\n%s", off, again)
	}
	requireOneExecHook(t, readSettingsFile(t, settingsPath))
}

// Hook objects that are not AgentShield's keep their own onFailure (or lack
// of one), in a group of their own or in AgentShield's group, whichever way
// setup moves the key on ours. Every AgentShield object (a shell-form and an
// exec-form duplicate) gets the policy.
func TestSetupClaudeCode_OnFailureNeverTouchesForeignHooks(t *testing.T) {
	const initial = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [
        {"type": "command", "command": "/usr/local/bin/lint-guard", "onFailure": "block"},
        {"type": "command", "command": "/opt/homebrew/bin/agentshield hook"}
      ]},
      {"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"}]},
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "/usr/local/bin/fmt-check"}]}
    ],
    "PostToolUse": [{"hooks": [{"type": "command", "command": "/usr/local/bin/notify", "onFailure": "block"}]}]
  },
  "model": "opus"
}`
	for _, tc := range []struct {
		name, managed, want string
	}{
		{"fail_closed on", managedFailClosed, claudeOnFailureBlock},
		{"fail_closed off", "", "<absent>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settingsPath := setupClaudeHome(t)
			setManagedJSON(t, settingsPath, tc.managed)
			writeSettingsFile(t, settingsPath, initial)
			before := readSettingsFile(t, settingsPath)

			runSetupClaudeCode(t, false)

			after := readSettingsFile(t, settingsPath)
			if !reflect.DeepEqual(otherHooks(before), otherHooks(after)) {
				t.Errorf("foreign hooks changed:\nbefore %v\nafter  %v", otherHooks(before), otherHooks(after))
			}
			if after["model"] != "opus" {
				t.Errorf("a key outside hooks changed: %v", after["model"])
			}
			if n := len(agentShieldHooks(after)); n != 2 {
				t.Fatalf("AgentShield hook objects = %d; want the 2 already there", n)
			}
			requireOnFailure(t, after, tc.want)
		})
	}
}

// The shell-form fallback (exec form not allowed) carries the key too, and a
// shell-form entry migrated to exec form keeps the key it gets.
func TestInstallClaudeCodeHook_OnFailureOnEveryForm(t *testing.T) {
	t.Run("shell form, fresh", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		res, err := installClaudeCodeHook(path, "/opt/homebrew/bin/agentshield", false, onFailureBlock)
		if err != nil {
			t.Fatal(err)
		}
		if res.Form.String() != "shell form" || !res.Added {
			t.Fatalf("res = %+v; want a shell-form entry added", res)
		}
		requireOnFailure(t, readSettingsFile(t, path), claudeOnFailureBlock)
	})
	t.Run("shell form migrated to exec form", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		writeSettingsFile(t, path, `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield hook", "timeout": 30}]}]}}`)
		res, err := installClaudeCodeHook(path, "/opt/homebrew/bin/agentshield", true, onFailureBlock)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Migrated) != 1 || res.OnFailureChanged != 1 {
			t.Fatalf("res = %+v; want one migration and one onFailure change", res)
		}
		settings := readSettingsFile(t, path)
		h := requireOneExecHook(t, settings)
		requireOnFailure(t, settings, claudeOnFailureBlock)
		if h["timeout"] != float64(30) {
			t.Errorf("the entry's own timeout was not kept: %v", h)
		}
	})
	t.Run("keep leaves an existing key and writes none", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "settings.json")
		writeSettingsFile(t, path, `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"}]}]}}`)
		before, _ := os.ReadFile(path)
		res, err := installClaudeCodeHook(path, "/opt/homebrew/bin/agentshield", true, onFailureKeep)
		if err != nil {
			t.Fatal(err)
		}
		if res.changed() {
			t.Errorf("keep changed the document: %+v", res)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Errorf("keep rewrote the file")
		}
		fresh := filepath.Join(t.TempDir(), "settings.json")
		if _, err := installClaudeCodeHook(fresh, "/opt/homebrew/bin/agentshield", true, onFailureKeep); err != nil {
			t.Fatal(err)
		}
		requireOnFailure(t, readSettingsFile(t, fresh), "<absent>")
	})
}

// --disable (and so the Homebrew zap, which runs it) removes AgentShield's
// entry with its key. On a managed host it is refused and the entry, key
// included, stays: the file is not touched.
func TestSetupClaudeCode_DisableTakesTheKeyWithTheEntry(t *testing.T) {
	const withKey = `{"hooks": {"PreToolUse": [{"hooks": [
  {"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"},
  {"type": "command", "command": "/usr/local/bin/lint-guard", "onFailure": "block"}
]}]}}`
	t.Run("unmanaged", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		writeSettingsFile(t, settingsPath, withKey)
		runSetupClaudeCode(t, true)
		after := readSettingsFile(t, settingsPath)
		if ours := agentShieldHooks(after); len(ours) != 0 {
			t.Fatalf("AgentShield hook left after --disable: %v", ours)
		}
		other := otherHooks(after)["PreToolUse"]
		if len(other) != 1 || other[0].(map[string]interface{})[claudeOnFailureKey] != claudeOnFailureBlock {
			t.Errorf("the foreign hook or its onFailure did not survive: %v", other)
		}
	})
	t.Run("managed fail_closed refuses", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		setManagedJSON(t, settingsPath, managedFailClosed)
		writeSettingsFile(t, settingsPath, withKey)
		before, _ := os.ReadFile(settingsPath)
		disableFlag = true
		var err error
		captureStdout(t, func() { err = setupClaudeCodeCommand(setupClaudeCodeCmd, nil) })
		if err == nil {
			t.Fatal("--disable on a managed host succeeded")
		}
		if after, _ := os.ReadFile(settingsPath); !bytes.Equal(before, after) {
			t.Errorf("a refused --disable changed the settings file")
		}
	})
}

// managedHomes are the HOMEs a managed-settings command can run under: a
// fail_closed enrollment (an admin's own sudo with HOME kept), none (root's
// home in effect), and no HOME at all (an MDM script, #4565).
var managedHomes = []struct{ name, managed string }{
	{"enrolled fail_closed HOME", managedFailClosed},
	{"unenrolled HOME", ""},
	{"no HOME", "<no HOME>"},
}

// runClaudeCodeFlags runs `setup claude-code` with the given managed-path
// flags set and returns stdout, stderr and the error.
func runClaudeCodeFlags(t *testing.T, managed, writeManaged, onFailureBlock, removeManaged bool) (string, string, error) {
	t.Helper()
	resetManagedFlags(t)
	managedFlag, writeManagedFlag, onFailureBlockFlag, removeManagedFlag, disableFlag = managed, writeManaged, onFailureBlock, removeManaged, false
	var runErr error
	var stderr string
	stdout := captureStdout(t, func() {
		stderr = captureStderr(t, func() { runErr = setupClaudeCodeCommand(setupClaudeCodeCmd, nil) })
	})
	return stdout, stderr, runErr
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.String()
	}()
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	os.Stderr = orig
	return <-done
}

// enterManagedHome sets up the HOME a managedHomes row names.
func enterManagedHome(t *testing.T, managed string) {
	t.Helper()
	settingsPath := setupClaudeHome(t)
	switch managed {
	case "<no HOME>":
		t.Setenv("HOME", "")
	default:
		setManagedJSON(t, settingsPath, managed)
	}
}

// --managed writes the key only for --on-failure-block, whatever HOME's
// managed.json says (Codex pass 1, finding 1: it used to follow the HOME of
// whoever ran it, root's under sudo). Without the flag the snippet is main's,
// byte for byte, and stderr tells a fail_closed fleet to pass the flag.
func TestSetupManaged_OnFailureOnlyWithTheFlag(t *testing.T) {
	for _, h := range managedHomes {
		for _, flag := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/flag=%v", h.name, flag), func(t *testing.T) {
				enterManagedHome(t, h.managed)
				stdout, stderr, err := runClaudeCodeFlags(t, true, false, flag, false)
				if err != nil {
					t.Fatalf("--managed: %v\n%s", err, stderr)
				}
				hookPath := resolveAgentShieldPath()
				if !flag {
					requireOnFailure(t, decodeJSON(t, []byte(stdout)), "<absent>")
					mainSnippet, _, err := managedSettingsSnippet(hookPath, execFormBlocker(hookPath) == "", onFailureKeep)
					if err != nil {
						t.Fatal(err)
					}
					if stdout != string(mainSnippet) {
						t.Errorf("snippet without the flag differs from main's:\n%s\nmain:\n%s", stdout, mainSnippet)
					}
					if !strings.Contains(stderr, "add --on-failure-block") {
						t.Errorf("stderr does not tell a fail_closed fleet about the flag:\n%s", stderr)
					}
					return
				}
				requireOnFailure(t, decodeJSON(t, []byte(stdout)), claudeOnFailureBlock)
				if !strings.Contains(stderr, "--remove-managed") {
					t.Errorf("stderr does not say how to take the entry out:\n%s", stderr)
				}
			})
		}
	}
}

// --write-managed adds the key only for --on-failure-block, whatever HOME's
// managed.json says, and never removes one: the managed file is the
// organization's. Without the flag the file is what main writes.
func TestSetupWriteManaged_OnFailureOnlyWithTheFlag(t *testing.T) {
	const adminSet = `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"}]}]}, "permissions": {"deny": ["WebFetch"]}}`
	const noKey = `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"]}]}]}}`
	for _, h := range managedHomes {
		for _, tc := range []struct {
			name, initial, want string
			flag, rewrites      bool
		}{
			{"flag adds", noKey, claudeOnFailureBlock, true, true},
			{"flag on a fresh file", "", claudeOnFailureBlock, true, true},
			{"no flag writes none", noKey, "<absent>", false, false},
			{"no flag keeps an admin's key", adminSet, claudeOnFailureBlock, false, false},
			{"no flag on a fresh file", "", "<absent>", false, true},
		} {
			t.Run(h.name+"/"+tc.name, func(t *testing.T) {
				enterManagedHome(t, h.managed)
				managedPath := pinManagedSettingsPath(t)
				if tc.initial != "" {
					writeSettingsFile(t, managedPath, tc.initial)
				}
				before, _ := os.ReadFile(managedPath)
				stdout, _, err := runClaudeCodeFlags(t, false, true, tc.flag, false)
				if err != nil {
					t.Fatalf("--write-managed: %v\n%s", err, stdout)
				}
				after, _ := os.ReadFile(managedPath)
				requireOnFailure(t, decodeJSON(t, after), tc.want)
				if rewrote := !bytes.Equal(before, after); rewrote != tc.rewrites {
					t.Errorf("rewrote = %v; want %v\n%s", rewrote, tc.rewrites, stdout)
				}
				if !tc.flag {
					// main's merge: the same writer with no policy.
					mainPath := filepath.Join(t.TempDir(), "managed-settings.json")
					if tc.initial != "" {
						writeSettingsFile(t, mainPath, tc.initial)
					}
					hookPath := resolveAgentShieldPath()
					if _, err := writeManagedClaudeHook(mainPath, hookPath, execFormBlocker(hookPath) == "", onFailureKeep); err != nil {
						t.Fatal(err)
					}
					if mainBytes, _ := os.ReadFile(mainPath); !bytes.Equal(mainBytes, after) {
						t.Errorf("file without the flag differs from main's:\n%s\nmain:\n%s", after, mainBytes)
					}
				}
			})
		}
	}
}

// --on-failure-block means nothing without --managed or --write-managed: the
// user-scope entry follows fail_closed.
func TestSetupClaudeCode_OnFailureBlockNeedsAManagedFlag(t *testing.T) {
	setupClaudeHome(t)
	_, _, err := runClaudeCodeFlags(t, false, false, true, false)
	if err == nil || !strings.Contains(err.Error(), "applies to --managed and --write-managed") {
		t.Fatalf("--on-failure-block alone: err = %v", err)
	}
}

// --remove-managed (Codex pass 1, finding 2) takes only AgentShield's hook
// objects out of the managed settings file: other hooks, groups and keys
// stay, an emptied group goes, and a second run changes nothing.
func TestRemoveManagedClaudeHook(t *testing.T) {
	const ours = `{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"}`
	const oursShell = `{"type": "command", "command": "/opt/homebrew/bin/agentshield hook"}`
	const foreign = `{"type": "command", "command": "/usr/local/bin/lint-guard", "onFailure": "block"}`
	for _, tc := range []struct {
		name, initial string
		removed       int
		wantFile      string // decoded and compared; "" = file unchanged
	}{
		{"ours alone", `{"hooks": {"PreToolUse": [{"hooks": [` + ours + `]}]}, "permissions": {"deny": ["WebFetch"]}, "big": 9007199254740993}`,
			1, `{"permissions": {"deny": ["WebFetch"]}, "big": 9007199254740993}`},
		{"ours beside a foreign hook", `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [` + foreign + `, ` + ours + `]}]}}`,
			1, `{"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [` + foreign + `]}]}}`},
		{"both forms, other groups and events", `{"hooks": {"PreToolUse": [{"hooks": [` + oursShell + `]}, {"matcher": "Edit", "hooks": [` + foreign + `]}, {"hooks": [` + ours + `]}], "PostToolUse": [{"hooks": [` + ours + `]}]}}`,
			2, `{"hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [` + foreign + `]}], "PostToolUse": [{"hooks": [` + ours + `]}]}}`},
		{"nothing of ours", `{"hooks": {"PreToolUse": [{"hooks": [` + foreign + `]}]}}`, 0, ""},
		{"no hooks", `{"model": "opus"}`, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json")
			writeSettingsFile(t, path, tc.initial)
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			res, err := removeManagedClaudeHook(path)
			if err != nil {
				t.Fatal(err)
			}
			if res.Removed != tc.removed {
				t.Errorf("removed %d; want %d", res.Removed, tc.removed)
			}
			after, _ := os.ReadFile(path)
			if tc.wantFile == "" {
				if !bytes.Equal(before, after) {
					t.Errorf("nothing to remove, but the file changed:\n%s", after)
				}
			} else {
				if got, want := decodeJSONNumbers(t, after), decodeJSONNumbers(t, []byte(tc.wantFile)); !reflect.DeepEqual(got, want) {
					t.Errorf("after removal:\n%s\nwant:\n%s", after, tc.wantFile)
				}
				if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
					t.Errorf("mode = %#o; want 0640 kept", fi.Mode().Perm())
				}
			}
			again, err := removeManagedClaudeHook(path)
			if err != nil || again.Removed != 0 {
				t.Errorf("second run: removed %d, err %v; want 0, nil", again.Removed, err)
			}
			if final, _ := os.ReadFile(path); !bytes.Equal(final, after) {
				t.Errorf("second run changed the file")
			}
		})
	}
	t.Run("missing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ClaudeCode", "managed-settings.json")
		res, err := removeManagedClaudeHook(path)
		if err != nil || !res.Missing || res.Removed != 0 {
			t.Fatalf("res %+v err %v; want Missing", res, err)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("a missing file was created")
		}
	})
	t.Run("malformed file refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "managed-settings.json")
		writeSettingsFile(t, path, `{"hooks": {"PreToolUse": [`+ours+`]`)
		before, _ := os.ReadFile(path)
		if _, err := removeManagedClaudeHook(path); err == nil || !strings.Contains(err.Error(), "refusing") {
			t.Fatalf("err = %v; want a refusal", err)
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Errorf("a refused file changed")
		}
	})
}

// --remove-managed is refused wherever --disable is (an enrolled HOME), and
// also when the account that ran sudo is enrolled, which --disable's check
// does not see under sudo. Otherwise it removes, and a second run says there
// is nothing left.
func TestSetupRemoveManaged_RefusedWhenManaged(t *testing.T) {
	const withOurs = `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "block"}]}]}}`
	sudoHome := func(t *testing.T, managed string) {
		t.Helper()
		h := t.TempDir()
		if managed != "" {
			if err := os.MkdirAll(filepath.Join(h, ".agentshield"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(h, ".agentshield", "managed.json"), []byte(managed), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Cleanup(homedir.SetSudoInvokerLookupForTest(func() (string, error) { return h, nil }))
	}
	for _, tc := range []struct {
		name, home, sudoInvoker string
		sudo, refused           bool
	}{
		{"enrolled HOME", managedFailClosed, "", false, true},
		{"enrolled without fail_closed", managedNoFailClosed, "", false, true},
		{"sudo by an enrolled account, root's HOME", "", managedFailClosed, true, true},
		{"sudo by an account with a corrupt managed.json", "", `{not json`, true, true},
		{"sudo by an unenrolled account", "", "", true, false},
		{"no sudo, unenrolled", "", "", false, false},
		{"no HOME (MDM), no sudo", "<no HOME>", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enterManagedHome(t, tc.home)
			if tc.sudo {
				sudoHome(t, tc.sudoInvoker)
			} else {
				t.Cleanup(homedir.SetSudoInvokerLookupForTest(func() (string, error) { return "", homedir.ErrNotSudo }))
			}
			managedPath := pinManagedSettingsPath(t)
			writeSettingsFile(t, managedPath, withOurs)
			before, _ := os.ReadFile(managedPath)
			stdout, _, err := runClaudeCodeFlags(t, false, false, false, true)
			after, _ := os.ReadFile(managedPath)
			if tc.refused {
				if err == nil {
					t.Fatalf("--remove-managed succeeded on a managed host:\n%s", stdout)
				}
				if !bytes.Equal(before, after) {
					t.Errorf("a refused removal changed the file")
				}
				return
			}
			if err != nil {
				t.Fatalf("--remove-managed: %v", err)
			}
			if ours := agentShieldHooks(decodeJSON(t, after)); len(ours) != 0 {
				t.Errorf("AgentShield hook left: %v", ours)
			}
			if !strings.Contains(stdout, "removed from Claude Code managed settings") {
				t.Errorf("stdout:\n%s", stdout)
			}
			again, _, err := runClaudeCodeFlags(t, false, false, false, true)
			if err != nil || !strings.Contains(again, "hold no AgentShield hook") {
				t.Errorf("second run: err %v\n%s", err, again)
			}
		})
	}
}

// Fitness function: on a managed fail_closed host, no path that writes a
// Claude Code hook entry writes one without "onFailure": "block". It drives
// every writer from every starting shape, and
// TestClaudeHookWriters_AreTheOnesTheFitnessTestDrives fails when a new
// writer appears that this sweep does not drive.
func TestFitness_ManagedFailClosedNeverWritesAnEntryWithoutOnFailure(t *testing.T) {
	starts := map[string]string{
		"fresh":                  "",
		"empty object":           `{}`,
		"shell form":             `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield hook"}]}]}}`,
		"exec form, no key":      `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"]}]}]}}`,
		"exec form, other value": `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"], "onFailure": "continue"}]}]}}`,
		"both forms":             `{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield hook"}]}, {"matcher": "Bash", "hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"]}]}]}}`,
	}
	names := make([]string, 0, len(starts))
	for n := range starts {
		names = append(names, n)
	}
	sort.Strings(names)

	checked := 0
	check := func(t *testing.T, writer, start string, doc map[string]interface{}) {
		t.Helper()
		got := onFailureValues(doc)
		if len(got) == 0 {
			t.Fatalf("%s from %s: no AgentShield entry written", writer, start)
		}
		for _, v := range got {
			checked++
			if v != claudeOnFailureBlock {
				t.Errorf("%s from %s: an AgentShield entry with onFailure %s under managed fail_closed", writer, start, v)
			}
		}
	}

	for _, start := range names {
		for _, execOK := range []bool{true, false} {
			form := "/exec allowed"
			if !execOK {
				form = "/shell only"
			}
			t.Run(start+form, func(t *testing.T) {
				settingsPath := setupClaudeHome(t)
				setManagedJSON(t, settingsPath, managedFailClosed)
				if !execOK {
					// A binary that is not the one running setup keeps shell form.
					pinSelfExecutable(t, filepath.Join(t.TempDir(), "agentshield"))
				}

				// User scope: `agentshield setup claude-code`.
				if starts[start] != "" {
					writeSettingsFile(t, settingsPath, starts[start])
				}
				runSetupClaudeCode(t, false)
				check(t, "setup claude-code", start, readSettingsFile(t, settingsPath))

				// --managed --on-failure-block (the snippet starts from an
				// empty document). Without the flag the managed paths write no
				// key by design: TestSetupManaged_OnFailureOnlyWithTheFlag.
				stdout, stderr, err := runClaudeCodeFlags(t, true, false, true, false)
				if err != nil {
					t.Fatalf("--managed --on-failure-block: %v\n%s", err, stderr)
				}
				check(t, "--managed --on-failure-block", start, decodeJSON(t, []byte(stdout)))

				// --write-managed --on-failure-block.
				managedPath := pinManagedSettingsPath(t)
				if starts[start] != "" {
					writeSettingsFile(t, managedPath, starts[start])
				}
				if out, _, err := runClaudeCodeFlags(t, false, true, true, false); err != nil {
					t.Fatalf("--write-managed --on-failure-block: %v\n%s", err, out)
				}
				data, err := os.ReadFile(managedPath)
				if err != nil {
					t.Fatal(err)
				}
				check(t, "--write-managed --on-failure-block", start, decodeJSON(t, data))

				// The teardown leaves no AgentShield entry, key or not.
				if _, err := removeManagedClaudeHook(managedPath); err != nil {
					t.Fatal(err)
				}
				data, _ = os.ReadFile(managedPath)
				if left := agentShieldHooks(decodeJSON(t, data)); len(left) != 0 {
					t.Errorf("--remove-managed from %s left %v", start, left)
				}
			})
		}
	}
	// Vacuity floor: 6 starts x 2 forms x 3 writers, at least one entry each.
	if checked < 36 {
		t.Fatalf("checked %d AgentShield entries; the sweep did not run (want >= 36)", checked)
	}
}

// The fitness sweep above drives three commands. This pins that they are the
// only ways a Claude Code hook object is built and written: hookentry's
// constructors are called only by claudeCodeHook, claudeCodeHook only by
// mergeClaudeCodeHook (which applies the onFailure policy), and the merge only
// by the three writers whose callers the sweep runs. A new caller anywhere in
// the package fails here until it is added to the sweep.
func TestClaudeHookWriters_AreTheOnesTheFitnessTestDrives(t *testing.T) {
	want := map[string][]string{
		"hookentry.ExecHook":        {"claudeCodeHook"},
		"hookentry.ShellHook":       {"claudeCodeHook"},
		"claudeCodeHook":            {"mergeClaudeCodeHook"},
		"mergeClaudeCodeHook":       {"installClaudeCodeHook", "managedSettingsSnippet", "writeManagedClaudeHook"},
		"installClaudeCodeHook":     {"setupClaudeCodeCommand"},
		"managedSettingsSnippet":    {"printManagedClaudeSnippet"},
		"writeManagedClaudeHook":    {"runWriteManaged"},
		"printManagedClaudeSnippet": {"setupClaudeCodeCommand"},
		"runWriteManaged":           {"setupClaudeCodeCommand"},
		// The managed policy comes from the flag, in one place.
		"managedOnFailure":   {"setupClaudeCodeCommand"},
		"userScopeOnFailure": {"setupClaudeCodeCommand"},
		// Removal: the two writers that take entries out, each behind its
		// refusal (behaviour in TestSetupRemoveManaged_RefusedWhenManaged).
		"removeAgentShieldHooks":                {"disableClaudeCodeHook", "removeManagedClaudeHook"},
		"removeManagedClaudeHook":               {"runRemoveManaged"},
		"runRemoveManaged":                      {"setupClaudeCodeCommand"},
		"enterprise.CheckManagedRemovalAllowed": {"setupClaudeCodeCommand"},
	}
	got := map[string][]string{}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	parsed := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.Ident:
					name = fun.Name
				case *ast.SelectorExpr:
					if x, ok := fun.X.(*ast.Ident); ok {
						name = x.Name + "." + fun.Sel.Name
					}
				}
				if _, tracked := want[name]; tracked {
					got[name] = append(got[name], fn.Name.Name)
				}
				return true
			})
		}
	}
	if parsed < 10 {
		t.Fatalf("parsed %d source files; the scan did not run", parsed)
	}
	for callee, callers := range want {
		g := got[callee]
		sort.Strings(g)
		w := append([]string(nil), callers...)
		sort.Strings(w)
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s is called from %v; want %v. A new writer of Claude Code hook entries must apply the onFailure policy and be driven by TestFitness_ManagedFailClosedNeverWritesAnEntryWithoutOnFailure", callee, g, w)
		}
	}
}
