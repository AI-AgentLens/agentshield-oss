package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/hookentry"
)

// These tests pin how `agentshield setup claude-code` registers the hook
// (#4292): exec form on a fresh install, an in-place migration of an existing
// shell-form entry, idempotent re-runs, and a --disable that removes either
// form without touching anyone else's hooks. Every test runs in a temp HOME;
// none touches the real ~/.claude.

// setupClaudeHome points HOME at a fresh directory and lays out a stand-in
// install the way Homebrew does: the real binary in one directory, and a
// symlink named `agentshield` to it in a directory on PATH. The real install
// locations (/opt/homebrew/bin, /usr/local/bin) are taken out of reach, so
// resolveAgentShieldPath finds the symlink, and setup runs "as" the real
// binary behind it. It returns the settings path setup writes.
func setupClaudeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	cellar := t.TempDir()
	real := filepath.Join(cellar, "agentshield")
	if err := os.WriteFile(real, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if err := os.Symlink(real, filepath.Join(bin, "agentshield")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	prevCandidates := agentShieldPathCandidates
	agentShieldPathCandidates = nil
	t.Cleanup(func() { agentShieldPathCandidates = prevCandidates })
	pinSelfExecutable(t, real)

	prev := disableFlag
	t.Cleanup(func() { disableFlag = prev })
	return filepath.Join(home, ".claude", "settings.json")
}

// pinSelfExecutable makes setup believe the binary running it is path.
func pinSelfExecutable(t *testing.T, path string) {
	t.Helper()
	prev := selfExecutable
	selfExecutable = func() (string, error) { return path, nil }
	t.Cleanup(func() { selfExecutable = prev })
}

// runSetupClaudeCode runs `agentshield setup claude-code [--disable]` and
// returns what it printed.
func runSetupClaudeCode(t *testing.T, disable bool) string {
	t.Helper()
	disableFlag = disable
	var runErr error
	out := captureStdout(t, func() { runErr = setupClaudeCodeCommand(setupClaudeCodeCmd, nil) })
	if runErr != nil {
		t.Fatalf("setup claude-code (disable=%v): %v\n%s", disable, runErr, out)
	}
	return out
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdout
	os.Stdout = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	defer func() {
		os.Stdout = orig
	}()
	fn()
	_ = w.Close()
	os.Stdout = orig
	return <-done
}

func writeSettingsFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readSettingsFile(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]interface{}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("settings do not parse: %v\n%s", err, data)
	}
	return s
}

// agentShieldHooks returns every AgentShield hook object under
// hooks.PreToolUse[*].hooks, as the shared recognizer sees them.
func agentShieldHooks(settings map[string]interface{}) []map[string]interface{} {
	var found []map[string]interface{}
	hooks, _ := settings["hooks"].(map[string]interface{})
	groups, _ := hooks["PreToolUse"].([]interface{})
	for _, g := range groups {
		gm, _ := g.(map[string]interface{})
		subs, _ := gm["hooks"].([]interface{})
		for _, h := range subs {
			if hookentry.IsAgentShieldHook(h) {
				found = append(found, h.(map[string]interface{}))
			}
		}
	}
	return found
}

// otherHooks returns, per event, every hook object that is not AgentShield's,
// so a test can assert they survive a setup run unchanged.
func otherHooks(settings map[string]interface{}) map[string][]interface{} {
	out := map[string][]interface{}{}
	hooks, _ := settings["hooks"].(map[string]interface{})
	for event, v := range hooks {
		groups, _ := v.([]interface{})
		for _, g := range groups {
			gm, _ := g.(map[string]interface{})
			subs, _ := gm["hooks"].([]interface{})
			for _, h := range subs {
				if !hookentry.IsAgentShieldHook(h) {
					out[event] = append(out[event], h)
				}
			}
		}
	}
	return out
}

func requireOneExecHook(t *testing.T, settings map[string]interface{}) map[string]interface{} {
	t.Helper()
	ours := agentShieldHooks(settings)
	if len(ours) != 1 {
		t.Fatalf("AgentShield PreToolUse hook objects = %d; want exactly 1: %v", len(ours), ours)
	}
	h := ours[0]
	if got := hookentry.Classify(h); got != hookentry.Exec {
		t.Fatalf("AgentShield hook is %v; want exec form: %v", got, h)
	}
	cmd, _ := h["command"].(string)
	if !filepath.IsAbs(cmd) || filepath.Base(cmd) != "agentshield" {
		t.Errorf("exec-form command = %q; want an absolute path to agentshield", cmd)
	}
	return h
}

// A fresh install writes exec form. On main this wrote shell form,
// "command": "<path> hook", which a project-set CLAUDE_CODE_SHELL_PREFIX wraps.
func TestSetupClaudeCode_FreshInstallWritesExecForm(t *testing.T) {
	settingsPath := setupClaudeHome(t)

	out := runSetupClaudeCode(t, false)

	requireOneExecHook(t, readSettingsFile(t, settingsPath))
	if !strings.Contains(out, "installed in exec form") {
		t.Errorf("setup output does not say which form it installed:\n%s", out)
	}
}

const shellFormSettings = `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-guard --strict"}]},
      {"hooks": [{"type": "command", "command": "/opt/homebrew/bin/agentshield hook", "timeout": 30}]}
    ],
    "PostToolUse": [
      {"hooks": [{"type": "command", "command": "/usr/local/bin/notify"}]}
    ]
  }
}`

// Re-running setup on a shell-form install rewrites that entry to exec form in
// place: one AgentShield entry, its own extra keys kept, every other hook and
// setting untouched. On main the re-run said "already configured" and left the
// shell-form entry.
func TestSetupClaudeCode_MigratesShellFormInPlace(t *testing.T) {
	settingsPath := setupClaudeHome(t)
	writeSettingsFile(t, settingsPath, shellFormSettings)
	before := readSettingsFile(t, settingsPath)

	out := runSetupClaudeCode(t, false)

	after := readSettingsFile(t, settingsPath)
	h := requireOneExecHook(t, after)
	if h["timeout"] != float64(30) {
		t.Errorf("migrated entry lost its timeout: %v", h)
	}
	if !reflect.DeepEqual(otherHooks(before), otherHooks(after)) {
		t.Errorf("other hooks changed:\nbefore %v\nafter  %v", otherHooks(before), otherHooks(after))
	}
	if after["model"] != "opus" {
		t.Errorf("unrelated setting lost: model = %v", after["model"])
	}
	groups := after["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
	if len(groups) != 2 {
		t.Errorf("PreToolUse groups = %d; want 2 (migration must not add or drop a group)", len(groups))
	}
	if !strings.Contains(out, "migrated from shell form to exec form") {
		t.Errorf("setup output does not report the migration:\n%s", out)
	}
}

// A second re-run changes nothing: the recognizer accepts the exec-form entry
// setup wrote, so setup neither appends a duplicate nor rewrites the file.
func TestSetupClaudeCode_ReRunIsIdempotent(t *testing.T) {
	for _, tc := range []struct{ name, initial string }{
		{"fresh", ""},
		{"from shell form", shellFormSettings},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settingsPath := setupClaudeHome(t)
			if tc.initial != "" {
				writeSettingsFile(t, settingsPath, tc.initial)
			}
			runSetupClaudeCode(t, false)
			first, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}

			out := runSetupClaudeCode(t, false)

			second, err := os.ReadFile(settingsPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(first, second) {
				t.Errorf("second run rewrote the file:\nfirst  %s\nsecond %s", first, second)
			}
			requireOneExecHook(t, readSettingsFile(t, settingsPath))
			if !strings.Contains(out, "already configured (exec form)") {
				t.Errorf("second run output:\n%s", out)
			}
		})
	}
}

// --disable removes AgentShield's hook in either form and leaves every other
// hook, including one sharing a matcher group with ours. On main an exec-form
// entry was "not found", and a group holding ours was removed whole.
func TestSetupClaudeCode_DisableRemovesEitherForm(t *testing.T) {
	for _, tc := range []struct{ name, ours string }{
		{"exec form", `{"type": "command", "command": "/opt/homebrew/bin/agentshield", "args": ["hook"]}`},
		{"shell form", `{"type": "command", "command": "/opt/homebrew/bin/agentshield hook"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settingsPath := setupClaudeHome(t)
			writeSettingsFile(t, settingsPath, `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-guard"}, `+tc.ours+`]},
      {"hooks": [`+tc.ours+`]},
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "/usr/local/bin/fmt-check"}]}
    ]
  }
}`)
			before := readSettingsFile(t, settingsPath)

			out := runSetupClaudeCode(t, true)

			after := readSettingsFile(t, settingsPath)
			if ours := agentShieldHooks(after); len(ours) != 0 {
				t.Fatalf("AgentShield hooks left after --disable: %v\n%s", ours, out)
			}
			if !reflect.DeepEqual(otherHooks(before), otherHooks(after)) {
				t.Errorf("--disable changed other hooks:\nbefore %v\nafter  %v", otherHooks(before), otherHooks(after))
			}
			groups := after["hooks"].(map[string]interface{})["PreToolUse"].([]interface{})
			if len(groups) != 2 {
				t.Errorf("PreToolUse groups = %d; want 2 (the AgentShield-only group dropped, the shared one kept)", len(groups))
			}
			if first := groups[0].(map[string]interface{}); first["matcher"] != "Bash" {
				t.Errorf("shared group lost its matcher: %v", first)
			}
		})
	}
}

// installClaudeCodeHook without exec form allowed keeps shell form, and never
// downgrades or rewrites an entry that is already there.
func TestInstallClaudeCodeHook_NonAbsolutePathKeepsShellForm(t *testing.T) {
	dir := t.TempDir()

	fresh := filepath.Join(dir, "fresh.json")
	res, err := installClaudeCodeHook(fresh, "agentshield", false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Added || res.Form != hookentry.Shell {
		t.Fatalf("fresh install with a bare name: %+v; want an added shell-form entry", res)
	}
	ours := agentShieldHooks(readSettingsFile(t, fresh))
	if len(ours) != 1 || ours[0]["command"] != "agentshield hook" {
		t.Fatalf("hooks = %v; want one shell-form \"agentshield hook\"", ours)
	}

	for _, tc := range []struct {
		name, initial string
		want          hookentry.Form
	}{
		{"shell form stays", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`, hookentry.Shell},
		{"exec form is not downgraded", `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`, hookentry.Exec},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			writeSettingsFile(t, path, tc.initial)
			res, err := installClaudeCodeHook(path, "agentshield", false)
			if err != nil {
				t.Fatal(err)
			}
			if res.Added || len(res.Migrated) != 0 || res.Form != tc.want {
				t.Errorf("result = %+v; want already configured in %v", res, tc.want)
			}
			if data, _ := os.ReadFile(path); string(data) != tc.initial {
				t.Errorf("file rewritten:\n%s", data)
			}
		})
	}
}

// A broken entry that only looks like ours (shell-form string plus "args",
// which Claude Code 2.1.296 spawns as a program that does not exist) is not
// counted as installed: setup adds a working entry beside it.
func TestInstallClaudeCodeHook_BrokenLookalikeIsNotInstalled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	writeSettingsFile(t, path, `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook","args":["--help"]}]}]}}`)

	res, err := installClaudeCodeHook(path, "/opt/homebrew/bin/agentshield", true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Added {
		t.Fatalf("result = %+v; want a working entry added", res)
	}
	requireOneExecHook(t, readSettingsFile(t, path))
}

// `agentshield scan` reports the exec-form Claude Code hook setup now writes,
// and points a shell-form install at the migration. Codex keeps its own
// command-suffix check, so an exec-form object in hooks.json is still not
// reported there.
func TestScanDetectsExecFormClaudeCodeHook(t *testing.T) {
	execForm := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`
	shellForm := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield hook"}]}]}}`
	dir := t.TempDir()
	execPath, shellPath := filepath.Join(dir, "exec.json"), filepath.Join(dir, "shell.json")
	writeSettingsFile(t, execPath, execForm)
	writeSettingsFile(t, shellPath, shellForm)

	var claudeExec, claudeShell, codexExec bool
	out := captureStdout(t, func() {
		claudeExec = detectPreToolUseHook("Claude Code", execPath, describeClaudeCodeHook)
		claudeShell = detectPreToolUseHook("Claude Code", shellPath, describeClaudeCodeHook)
		codexExec = detectPreToolUseHook("Codex CLI", execPath, describeCodexHook)
	})
	if !claudeExec || !claudeShell {
		t.Errorf("scan missed a Claude Code hook: exec=%v shell=%v\n%s", claudeExec, claudeShell, out)
	}
	if !strings.Contains(out, "/opt/homebrew/bin/agentshield hook (exec form)") {
		t.Errorf("scan output does not show the exec-form command:\n%s", out)
	}
	if !strings.Contains(out, "run `agentshield setup claude-code` to switch to exec form") {
		t.Errorf("scan output does not point the shell-form install at the migration:\n%s", out)
	}
	if codexExec {
		t.Error("the Codex detector changed: it now accepts an exec-form object")
	}
}

// otherBinary is a second agentshield, with the same bytes as the stand-in but
// at another path: an older copy left in /usr/local/bin, say.
func otherBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "agentshield")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// Exec form is written only for the binary running setup (#4292 review pass 1,
// C1). Claude Code 2.1.138 and earlier run an exec-form entry bare, and only a
// binary with the backstop evaluates a bare run; an older copy at the path
// setup prefers prints help and exits 0. The comparison resolves symlinks, so
// the brew link to the running binary counts as the same binary.
func TestSetupClaudeCode_ExecFormOnlyForTheRunningBinary(t *testing.T) {
	t.Run("same binary through a symlink: exec form", func(t *testing.T) {
		settingsPath := setupClaudeHome(t) // PATH holds a symlink; setup runs as its target

		out := runSetupClaudeCode(t, false)

		h := requireOneExecHook(t, readSettingsFile(t, settingsPath))
		if fi, err := os.Lstat(h["command"].(string)); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("exec-form command %v is not the PATH symlink (stat err %v); setup must keep the stable link, not the resolved target", h["command"], err)
		}
		if strings.Contains(out, "not the binary running setup") {
			t.Errorf("same binary warned about skew:\n%s", out)
		}
	})

	t.Run("different binary: shell form and a warning", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		exe := otherBinary(t)
		pinSelfExecutable(t, exe)
		hookPath := resolveAgentShieldPath()

		out := runSetupClaudeCode(t, false)

		ours := agentShieldHooks(readSettingsFile(t, settingsPath))
		if len(ours) != 1 || hookentry.Classify(ours[0]) != hookentry.Shell || ours[0]["command"] != hookPath+" hook" {
			t.Fatalf("hooks = %v; want one shell-form %q", ours, hookPath+" hook")
		}
		want := "agentshield at " + hookPath + " is not the binary running setup (" + exe + "); keeping shell form — update or remove " + hookPath + ", or re-run setup with it once it is current"
		if !strings.Contains(out, want) {
			t.Errorf("setup output lacks the skew warning %q:\n%s", want, out)
		}
	})

	t.Run("migration under skew keeps shell form", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		pinSelfExecutable(t, otherBinary(t))
		writeSettingsFile(t, settingsPath, shellFormSettings)
		before, _ := os.ReadFile(settingsPath)

		out := runSetupClaudeCode(t, false)

		after, _ := os.ReadFile(settingsPath)
		if !bytes.Equal(before, after) {
			t.Errorf("settings rewritten under skew:\nbefore %s\nafter  %s", before, after)
		}
		if !strings.Contains(out, "already configured (shell form)") || !strings.Contains(out, "not the binary running setup") {
			t.Errorf("setup output:\n%s", out)
		}
	})

	t.Run("exec form is never downgraded under skew", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		pinSelfExecutable(t, otherBinary(t))
		initial := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`
		writeSettingsFile(t, settingsPath, initial)

		out := runSetupClaudeCode(t, false)

		if data, _ := os.ReadFile(settingsPath); string(data) != initial {
			t.Errorf("exec-form entry rewritten under skew:\n%s", data)
		}
		if !strings.Contains(out, "already configured (exec form)") {
			t.Errorf("setup output:\n%s", out)
		}
	})

	t.Run("running binary unknown: shell form", func(t *testing.T) {
		settingsPath := setupClaudeHome(t)
		prev := selfExecutable
		selfExecutable = func() (string, error) { return "", errors.New("no executable path") }
		t.Cleanup(func() { selfExecutable = prev })

		out := runSetupClaudeCode(t, false)

		ours := agentShieldHooks(readSettingsFile(t, settingsPath))
		if len(ours) != 1 || hookentry.Classify(ours[0]) != hookentry.Shell {
			t.Fatalf("hooks = %v; want one shell-form entry", ours)
		}
		if !strings.Contains(out, "not the binary running setup") {
			t.Errorf("setup output lacks the warning:\n%s", out)
		}
	})
}

// writeStandIn writes an executable stand-in agentshield at path.
func writeStandIn(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// pinClaudeHome points HOME at a fresh directory, PATH at dirOnPath, and the
// preferred install locations at candidates. Unlike setupClaudeHome it lays
// out no binaries: the caller builds the install it wants to model.
func pinClaudeHome(t *testing.T, dirOnPath string, candidates []string) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PATH", dirOnPath+string(os.PathListSeparator)+os.Getenv("PATH"))
	prevCandidates := agentShieldPathCandidates
	agentShieldPathCandidates = candidates
	t.Cleanup(func() { agentShieldPathCandidates = prevCandidates })
	prev := disableFlag
	t.Cleanup(func() { disableFlag = prev })
	return filepath.Join(home, ".claude", "settings.json")
}

// K12 (#4314 pass 2): on darwin os.Executable returns the PATH symlink a cask
// install runs through (/opt/homebrew/bin/agentshield), not its Caskroom
// target. Both sides of the gate must be resolved, or every macOS brew install
// would get shell form. The other setup tests pin selfExecutable to the
// resolved target, the Linux shape, so only this one sees that case.
func TestSetupClaudeCode_DarwinCaskLayoutGetsExecForm(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "Caskroom", "agentshield", "1.2.3", "agentshield")
	writeStandIn(t, real)
	bin := filepath.Join(root, "opt", "homebrew", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "agentshield")
	if err := os.Symlink(filepath.Join("..", "..", "..", "Caskroom", "agentshield", "1.2.3", "agentshield"), link); err != nil {
		t.Fatal(err)
	}
	settingsPath := pinClaudeHome(t, bin, []string{link})
	pinSelfExecutable(t, link) // darwin: the symlink, not its target

	out := runSetupClaudeCode(t, false)

	h := requireOneExecHook(t, readSettingsFile(t, settingsPath))
	if h["command"] != link {
		t.Errorf("exec-form command = %v; want the cask link %s", h["command"], link)
	}
	if strings.Contains(out, "not the binary running setup") {
		t.Errorf("a cask install was treated as skew:\n%s", out)
	}
}

// K7 (#4314 pass 2): setup writes resolveAgentShieldPath(), which prefers the
// candidate locations over whatever exec.LookPath finds first on PATH. The
// gate must judge the path written into the hook, not the LookPath one.
func TestSetupClaudeCode_GateJudgesThePathWrittenNotLookPath(t *testing.T) {
	t.Run("candidate is the running binary, PATH has an older one: exec form", func(t *testing.T) {
		root := t.TempDir()
		candidate := filepath.Join(root, "preferred", "agentshield")
		writeStandIn(t, candidate)
		onPath := filepath.Join(root, "pathdir")
		writeStandIn(t, filepath.Join(onPath, "agentshield")) // an older copy, first on PATH
		settingsPath := pinClaudeHome(t, onPath, []string{candidate})
		pinSelfExecutable(t, candidate)

		out := runSetupClaudeCode(t, false)

		h := requireOneExecHook(t, readSettingsFile(t, settingsPath))
		if h["command"] != candidate {
			t.Errorf("exec-form command = %v; want the candidate %s", h["command"], candidate)
		}
		if strings.Contains(out, "not the binary running setup") {
			t.Errorf("warned about skew for the binary that is running:\n%s", out)
		}
	})

	t.Run("candidate is an older binary, PATH has the running one: shell form", func(t *testing.T) {
		root := t.TempDir()
		candidate := filepath.Join(root, "preferred", "agentshield")
		writeStandIn(t, candidate) // an older copy at the preferred location
		onPath := filepath.Join(root, "pathdir")
		running := filepath.Join(onPath, "agentshield")
		writeStandIn(t, running)
		settingsPath := pinClaudeHome(t, onPath, []string{candidate})
		pinSelfExecutable(t, running)

		out := runSetupClaudeCode(t, false)

		ours := agentShieldHooks(readSettingsFile(t, settingsPath))
		if len(ours) != 1 || hookentry.Classify(ours[0]) != hookentry.Shell || ours[0]["command"] != candidate+" hook" {
			t.Fatalf("hooks = %v; want one shell-form %q (exec form would run the older binary bare)", ours, candidate+" hook")
		}
		if !strings.Contains(out, "agentshield at "+candidate+" is not the binary running setup ("+running+")") {
			t.Errorf("setup output lacks the skew warning naming both paths:\n%s", out)
		}
	})
}
