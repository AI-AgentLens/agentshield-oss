package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/testhome"
	"github.com/spf13/cobra"
)

// #5066: every cli call site that decides "this Codex, Gemini CLI, Copilot
// CLI, Windsurf, Cursor or Claude Code hook is AgentShield's" goes through
// hookentry. Each site gets the command setup writes on this OS,
// `<binPath> hook` with binPath an absolute path to agentshield
// (agentshield.exe on Windows, C:\...; forward slashes for Claude Code's
// shell form), and three commands that are not our hook on any OS.
//
// On Windows the first row is the fix: before #5066 every site here missed
// it. Off Windows it passes through the suffix and substring tests those
// sites always had, which this change leaves byte-identical.
//
// #5072 pass 2 adds two rows. With the binary deleted, setup's sites still
// find the entry (to rewrite or remove it) and the reporters, scan and
// status, do not on Windows. With setup's command only in a key beside the
// hook's real command, no site takes it on Windows; off Windows the sites
// that always used the whole-file substring still do, as on main.
func TestHookRecognisers_EveryCallSiteAcceptsSetupsCommand_5066(t *testing.T) {
	home := t.TempDir()
	testhome.Set(t, home)
	installDir := filepath.Join(home, "AppData", "Local", "Programs", "AgentShield")
	bin := filepath.Join(installDir, exeName("agentshield"))
	ours := bin + " hook"
	other := filepath.Join(installDir, "other.exe")
	notOurs := []string{
		filepath.Join(installDir, "agentshield-helper.exe") + " hook",
		filepath.Join(installDir, "notagentshield.exe") + " hook",
		"echo " + filepath.Join(installDir, "agentshield.exe") + " hook",
	}
	onWindows := runtime.GOOS == "windows"

	// standIn puts an agentshield binary on PATH for setup windsurf|cursor,
	// which stop early without one.
	standIn := t.TempDir()
	if err := os.WriteFile(filepath.Join(standIn, exeName("agentshield")), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", standIn+string(os.PathListSeparator)+os.Getenv("PATH"))
	prevDisable := disableFlag
	t.Cleanup(func() { disableFlag = prevDisable })

	writeJSON := func(t *testing.T, path string, doc interface{}) {
		t.Helper()
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
	// hook is one hook object: field set to cmd, and extra beside it.
	hook := func(field, cmd string, extra map[string]interface{}) map[string]interface{} {
		h := map[string]interface{}{"type": "command", field: cmd}
		for k, v := range extra {
			h[k] = v
		}
		return h
	}
	group := func(cmd string, extra map[string]interface{}) interface{} {
		return map[string]interface{}{"matcher": "^Bash$", "hooks": []interface{}{hook("command", cmd, extra)}}
	}
	windsurfFile := func(cmd string, extra map[string]interface{}) interface{} {
		return map[string]interface{}{"hooks": map[string]interface{}{"pre_run_command": []interface{}{hook("command", cmd, extra)}}}
	}
	cursorFile := func(cmd string, extra map[string]interface{}) interface{} {
		return map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"beforeShellExecution": []interface{}{hook("command", cmd, extra)}}}
	}
	// disable runs the real `setup windsurf|cursor --disable` on doc,
	// written where that command looks, and reports whether it set the
	// file aside.
	disable := func(t *testing.T, doc interface{}, path string, run func(*cobra.Command, []string) error, c *cobra.Command) bool {
		writeJSON(t, path, doc)
		_ = os.Remove(path + ".bak")
		disableFlag = true
		out := captureStdout(t, func() {
			if err := run(c, nil); err != nil {
				t.Fatal(err)
			}
		})
		disableFlag = false
		_, statErr := os.Stat(path + ".bak")
		if moved := statErr == nil; moved != strings.Contains(out, "hook disabled") {
			t.Fatalf("setup --disable printed %q but moved the file = %v", out, moved)
		}
		return statErr == nil
	}
	// status runs the real `agentshield status` over doc, written where it
	// looks, and reports whether its line for name says "hook active".
	status := func(t *testing.T, doc interface{}, path, name string) bool {
		writeJSON(t, path, doc)
		out := captureStdout(t, func() {
			if err := statusCommand(statusCmd, nil); err != nil {
				t.Fatal(err)
			}
		})
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, name+":") {
				return strings.Contains(line, "hook active")
			}
		}
		t.Fatalf("status printed no %s line:\n%s", name, out)
		return false
	}
	windsurfPath := filepath.Join(home, ".codeium", "windsurf", "hooks.json")
	cursorPath := filepath.Join(home, ".cursor", "hooks.json")

	sites := []struct {
		name string
		// reporter: the site reports the hook as present (scan, status),
		// so on Windows it also wants the binary to be a file.
		reporter bool
		// substring: main judged the whole file by the "agentshield hook"
		// substring, so off Windows a copy anywhere in it still counts.
		substring bool
		// recognised feeds cmd to the call site, with extra keys beside it
		// in the hook object, and reports whether it took the command for
		// AgentShield's hook.
		recognised func(t *testing.T, cmd string, extra map[string]interface{}) bool
	}{
		{"setup gemini-cli (isAgentShieldGeminiHookEntry)", false, false, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return isAgentShieldGeminiHookEntry(group(cmd, extra))
		}},
		{"setup codex (isAgentShieldCodexHookEntry)", false, false, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return isAgentShieldCodexHookEntry(group(cmd, extra))
		}},
		{"scan, Codex (describeCodexHook)", true, false, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			_, ok := describeCodexHook(hook("command", cmd, extra))
			return ok
		}},
		// Claude Code's shell form, which setup writes with forward slashes
		// on Windows (hookentry.ShellHook).
		{"scan, Claude Code shell form (describeClaudeCodeHook)", true, false, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			_, ok := describeClaudeCodeHook(hook("command", filepath.ToSlash(cmd), extra))
			return ok
		}},
		{"setup copilot-cli, no marker (isAgentShieldCopilotHookFile)", false, false, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			path := filepath.Join(t.TempDir(), "agentshield.json")
			writeJSON(t, path, map[string]interface{}{"version": 1, "hooks": map[string]interface{}{"PreToolUse": []interface{}{hook("bash", cmd, extra)}}})
			ours, err := isAgentShieldCopilotHookFile(path)
			if err != nil {
				t.Fatal(err)
			}
			return ours
		}},
		{"setup windsurf --disable (disableHook)", false, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return disable(t, windsurfFile(cmd, extra), windsurfPath, setupWindsurfCommand, setupWindsurfCmd)
		}},
		{"setup cursor --disable (disableHook)", false, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return disable(t, cursorFile(cmd, extra), cursorPath, setupCursorCommand, setupCursorCmd)
		}},
		{"setup windsurf, already configured", false, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			writeJSON(t, windsurfPath, windsurfFile(cmd, extra))
			disableFlag = false
			out := captureStdout(t, func() {
				if err := setupWindsurfCommand(setupWindsurfCmd, nil); err != nil {
					t.Fatal(err)
				}
			})
			return strings.Contains(out, "Cascade Hook already configured")
		}},
		{"setup cursor, already configured", false, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			writeJSON(t, cursorPath, cursorFile(cmd, extra))
			disableFlag = false
			out := captureStdout(t, func() {
				if err := setupCursorCommand(setupCursorCmd, nil); err != nil {
					t.Fatal(err)
				}
			})
			return strings.Contains(out, "Cursor Hook already configured")
		}},
		{"status, Windsurf (checkShellHook)", true, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return status(t, windsurfFile(cmd, extra), windsurfPath, "Windsurf")
		}},
		{"status, Cursor (checkShellHook)", true, true, func(t *testing.T, cmd string, extra map[string]interface{}) bool {
			return status(t, cursorFile(cmd, extra), cursorPath, "Cursor")
		}},
	}
	installBin := func(t *testing.T) {
		t.Helper()
		if err := os.MkdirAll(installDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bin, []byte("MZ"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			installBin(t)
			if !s.recognised(t, ours, nil) {
				t.Errorf("does not recognise the command setup writes: %q", ours)
			}
			for _, cmd := range notOurs {
				if s.recognised(t, cmd, nil) {
					t.Errorf("recognises %q, which is not AgentShield's hook", cmd)
				}
			}
			metaWant := s.substring && !onWindows
			if got := s.recognised(t, other, map[string]interface{}{"statusMessage": ours}); got != metaWant {
				t.Errorf("setup's command only in statusMessage, the hook running %q: recognised = %v on %s, want %v", other, got, runtime.GOOS, metaWant)
			}
			if err := os.Remove(bin); err != nil {
				t.Fatal(err)
			}
			goneWant := !(s.reporter && onWindows)
			if got := s.recognised(t, ours, nil); got != goneWant {
				t.Errorf("binary deleted: recognised %q = %v on %s, want %v", ours, got, runtime.GOOS, goneWant)
			}
		})
	}
}
