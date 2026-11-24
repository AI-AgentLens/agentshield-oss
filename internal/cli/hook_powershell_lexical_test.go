package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestPowerShellLane_LexicalReading_4830: the PowerShell lane's second,
// stricter-wins reading of its facts (policy.factsLexicalReading) through the
// real hook, on Claude Code's PowerShell row and Copilot's native powershell
// row: a comma-array item and a path spelled with `.` or `..` segments decide
// as the clean spelling does, naming the same rule.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).
func TestPowerShellLane_LexicalReading_4830(t *testing.T) {
	as := ".agent" + "shield"
	key := "id_" + "ed25519"
	rows := []struct {
		name, ps, rule string
	}{
		{"array item: log tamper", `Remove-Item x.txt, ~\` + as + `\audit.jsonl`, "ps-block-agentshield-log-tamper"},
		{"dot-dot segment: log tamper", `Clear-Content ~\x\..\` + as + `\audit.jsonl`, "ps-block-agentshield-log-tamper"},
		{"dot segment: log tamper", `Clear-Content ~\.\` + as + `\audit.jsonl`, "ps-block-agentshield-log-tamper"},
		// Select-String has no cmdlet-bridge twin, so the lane's own reading
		// is the only layer on Claude Code's row (Get-Content's `cat` twin
		// already BLOCKs by sec-block-ssh-private on main). The path is
		// written in the loop: it needs the test's home.
		{"slash-dot root: key read", "", "protected-path"},
	}
	// No comma in a row's name: t.TempDir spells the home with it, and an
	// unquoted comma makes PowerShell read the path as a two-item array.
	for _, r := range rows {
		for _, row := range []string{"claude-code PowerShell", "copilot native powershell"} {
			t.Run(r.name+"/"+row, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, false, "")
				if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
					t.Fatal(err)
				}
				cmd := r.ps
				if r.rule == "protected-path" {
					cmd = "Select-String -Pattern x -Path " + dotRootSpelling(home) + "/.ssh/" + key
				}
				payload := psCall(t, cmd)
				if row != "claude-code PowerShell" {
					payload = copilotNativePayload(t, "lexical", "powershell", shellArgs(cmd))
				}
				code, _, stderr := runHookChild(t, home, payload)
				if code != 2 {
					t.Fatalf("%q exits %d, want 2 (BLOCK by %s). stderr:\n%s", cmd, code, r.rule, stderr)
				}
				e := oneEvent(t, configDir)
				if e.Decision != "BLOCK" {
					t.Errorf("event decision=%q rules=%v, want BLOCK", e.Decision, e.TriggeredRules)
				}
				// On Copilot's row POSIX reads the text first and keeps its
				// record on a tie, so only Claude Code's row names the lane's rule.
				if row == "claude-code PowerShell" && !containsStr(e.TriggeredRules, r.rule) {
					t.Errorf("rules %v, want %s", e.TriggeredRules, r.rule)
				}
			})
		}
	}
}
