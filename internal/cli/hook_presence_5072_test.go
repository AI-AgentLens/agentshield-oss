package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
)

// TestHookFile_LayoutsAreWhatSetupWrites (#5072 pass 2): on Windows the
// watchdog, status and setup's Windsurf and Cursor checks read a hook file's
// command only where hookentry.HookFile says the integration keeps it. Each
// layout must be where the real `setup <surface>` puts its command, or the
// narrowing would make setup miss its own entry, which is #5066 again. The
// files here are written by the real enables, in child processes, with a
// stand-in agentshield on PATH. Commands is read the same way on every OS, so
// this holds on macOS and Linux too; on Windows the command is the stand-in's
// own `C:\...\agentshield.exe hook`, which only the structural test finds.
//
// Then the watchdog runs over the same home. Every hook check passes. With
// the stand-in deleted, on Windows the four surfaces whose command names it
// (Claude Code's forward-slash shell form, Gemini CLI, Codex, Copilot CLI)
// are reported missing; Windsurf and Cursor keep the bare `agentshield hook`
// their templates write and still pass. Off Windows every command is main's
// spelling, judged by its words, and all six still pass.
func TestHookFile_LayoutsAreWhatSetupWrites(t *testing.T) {
	home := newSetupHome(t)
	standIn, err := exec.LookPath("agentshield")
	if err != nil {
		t.Fatal(err)
	}
	installAllSurfaces(t, home)
	onWindows := runtime.GOOS == "windows"

	surfaces := []struct {
		name string
		file hookentry.HookFile
		// bare: the template writes `agentshield hook`, not a path.
		bare bool
	}{
		{"windsurf", hookentry.WindsurfHookFile, true},
		{"cursor", hookentry.CursorHookFile, true},
		{"gemini-cli", hookentry.GeminiCLIHookFile, false},
		{"codex", hookentry.CodexHookFile, false},
		{"copilot-cli", hookentry.CopilotCLIHookFile, false},
	}
	for _, s := range surfaces {
		path := filepath.Join(home, installedSurfaceFiles[s.name])
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cmds := s.file.Commands(data)
		found := false
		for _, c := range cmds {
			switch {
			case s.bare:
				found = found || c == hookentry.HookCommand
			case onWindows:
				// On Windows setup writes LookPath's result, the stand-in.
				found = found || c == standIn+" hook"
			default:
				found = found || hookentry.MatchesHookCommand(c)
			}
		}
		if !found {
			t.Errorf("%s: the layout %+v locates %q in %s, none of which is the command setup wrote (stand-in %s):\n%s", s.name, s.file, cmds, path, standIn, data)
		}
		if !s.file.Has(data) || !s.file.Present(data) {
			t.Errorf("%s: Has = %v, Present = %v for the file setup wrote, want both true:\n%s", s.name, s.file.Has(data), s.file.Present(data), data)
		}
	}

	configDir := filepath.Join(home, ".agentshield")
	watchdog := func() map[string]enterprise.WatchdogCheck {
		got := map[string]enterprise.WatchdogCheck{}
		for _, c := range enterprise.RunWatchdogOnce(configDir) {
			got[c.Name] = c
		}
		return got
	}
	hookChecks := []string{"hook-claude-code", "hook-windsurf", "hook-cursor", "hook-gemini-cli", "hook-codex", "hook-copilot-cli"}
	got := watchdog()
	for _, name := range hookChecks {
		c, ok := got[name]
		if !ok || !c.Passed {
			t.Errorf("watchdog %s over the files setup wrote on %s: ran %v, passed %v: %s", name, runtime.GOOS, ok, c.Passed, c.Message)
		}
	}

	if err := os.Remove(standIn); err != nil {
		t.Fatal(err)
	}
	gone := map[string]bool{"hook-claude-code": onWindows, "hook-gemini-cli": onWindows, "hook-codex": onWindows, "hook-copilot-cli": onWindows}
	got = watchdog()
	for _, name := range hookChecks {
		if c := got[name]; c.Passed == gone[name] {
			t.Errorf("watchdog %s with the binary setup named deleted, on %s: passed = %v, want %v: %s", name, runtime.GOOS, c.Passed, !gone[name], c.Message)
		}
	}
}
