package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `agentshield scan` on a managed host reports which Claude Code scopes carry
// the hook (#4292 PR B), and counts the line: a hook missing from managed
// settings moves the denominator, never only the text.
func TestScanTamper_ClaudeHookScopeLine(t *testing.T) {
	const execHook = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/opt/homebrew/bin/agentshield","args":["hook"]}]}]}}`
	// The managed section counts six checks here: managed mode (pass),
	// AGENTSHIELD_BYPASS (pass), policy file (fail: the fixture writes no
	// policy.yaml), self-protection rules (pass), hook integrity (pass: the
	// user-scope hook is installed) and the hook scope line. The audit chain
	// has no entries yet, which is not counted. Absolute numbers, so dropping
	// the scope line's total++ cannot hide behind a delta (#4428 review, R10).
	const wantTotal = 6
	for _, tc := range []struct {
		name        string
		managed     string // "" = no managed settings file
		wantMark    string
		wantPassed  bool
		wantPassedN int
	}{
		{"user scope only", "", "❌ Claude Code hook scope:", false, 4},
		{"managed settings carry the hook", execHook, "✅ Claude Code hook scope:", true, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			managedPath := pinManagedSettingsPath(t)
			cfg := tamperTestConfig(t, true)
			home := os.Getenv("HOME")
			writeSettingsFile(t, filepath.Join(home, ".claude", "settings.json"), execHook)
			if tc.managed != "" {
				writeSettingsFile(t, managedPath, tc.managed)
			}
			out, passed, total := captureTamperSection(t, cfg)
			var line string
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "Claude Code hook scope:") {
					line = l
				}
			}
			if !strings.Contains(line, tc.wantMark) || !strings.Contains(line, managedPath) {
				t.Fatalf("scope line = %q; want %q naming %s\n%s", line, tc.wantMark, managedPath, out)
			}
			if !strings.Contains(line, "user present") {
				t.Errorf("scope line does not name the user scope: %q", line)
			}
			if total != wantTotal || passed != tc.wantPassedN {
				t.Errorf("passed/total = %d/%d; want %d/%d\n%s", passed, total, tc.wantPassedN, wantTotal, out)
			}

			// The same host with the scope line's outcome flipped moves the
			// counts by exactly one pass.
			if tc.wantPassed {
				if err := os.Remove(managedPath); err != nil {
					t.Fatal(err)
				}
			} else {
				writeSettingsFile(t, managedPath, execHook)
			}
			_, passed2, total2 := captureTamperSection(t, cfg)
			if total2 != total {
				t.Errorf("total moved %d → %d; the scope check is counted either way", total, total2)
			}
			if d := passed - passed2; (tc.wantPassed && d != 1) || (!tc.wantPassed && d != -1) {
				t.Errorf("passed %d → %d; want the scope check to move it by one", passed, passed2)
			}
		})
	}
}
