package cli

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Windows rules, round 4: the lane's two new readings, through the lane the
// hook builds (community packs, the native-command bridge on).
//
// A cmd line has no lane, so it keeps its routing_gap note, but each of its
// commands is read once more: cmd's delete built-ins as the Remove-Item call
// with their effect, and every other command's words through the
// native-command bridge. Before, every row below decided AUDIT.
func TestPSLane_Round4_CmdLineCommands(t *testing.T) {
	wev := "wevtutil " + "cl Security"
	cases := []struct {
		name, cmd string
		decision  policy.Decision
		rule      string
	}{
		{"rd /s /q on a drive root", `cmd /c rd /s /q C:\`, policy.DecisionBlock, "ps-block-remove-drive-root"},
		{"rmdir, cmd.exe, quoted system dir", `cmd.exe /c rmdir /s /q "C:\Program Files"`, policy.DecisionBlock, "ps-block-remove-system-dir"},
		{"del /s /q on a drive's files", `cmd /c del /s /q C:\*`, policy.DecisionBlock, "ps-block-remove-drive-root"},
		{"joined switches", `cmd /c rd/s/q C:\Windows`, policy.DecisionBlock, "ps-block-remove-system-dir"},
		{"after another command", `cmd /c "echo x & rd /s /q C:\"`, policy.DecisionBlock, "ps-block-remove-drive-root"},
		{"a native program, through the bridge", "cmd /c " + wev, policy.DecisionBlock, "ts-block-wevtutil-clear-log"},
		{"a native program after &&", "cmd /c dir && " + wev, policy.DecisionBlock, "ts-block-wevtutil-clear-log"},
		// Neighbours bash leaves below BLOCK, and ordinary cmd lines.
		{"rd /s without /q", `cmd /c rd /s C:\`, policy.DecisionAudit, ""},
		{"a build directory", `cmd /c rd /s /q build`, policy.DecisionAudit, ""},
		{"one file", `cmd /c del /q C:\temp\x.txt`, policy.DecisionAudit, ""},
		{"dir", `cmd /c dir C:\`, policy.DecisionAudit, ""},
		{"a native read", "cmd /c wevtutil qe Security /c:5", policy.DecisionAudit, ""},
	}
	l := testPSLane(t, 2)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := l.read(c.cmd)
			if r.Decision != c.decision || (c.rule != "" && !containsStr(r.TriggeredRules, c.rule)) {
				t.Errorf("decision %s rules %v, want %s %s", r.Decision, r.TriggeredRules, c.decision, c.rule)
			}
			if !hasNote(r.Notes, analyzer.NoteRoutingGap) {
				t.Errorf("notes %+v lack the routing_gap note: cmd's grammar is still unread", r.Notes)
			}
		})
	}
}

// TestPSLane_Round4_SubexpressionPath (#4765 item 3): `"$($HOME)\…"` names
// the file `"$HOME\…"` does, so a key read through the subexpression BLOCKs
// as the plain spelling does, with the same rule.
func TestPSLane_Round4_SubexpressionPath(t *testing.T) {
	l := testPSLane(t, 2)
	l.engine = mustEngineWithProtectedSSH(t)
	key := `\.ssh\id_` + "rsa"
	for _, text := range []string{
		`Get-Content "$HOME` + key + `"`, // control
		`Get-Content "$($HOME)` + key + `"`,
		`Get-Content "$( $HOME )` + key + `"`,
		`Copy-Item "$($env:USERPROFILE)` + key + `" C:\t\k`,
	} {
		r := l.read(text)
		if r.Decision != policy.DecisionBlock || !containsStr(r.TriggeredRules, policy.ProtectedPathRuleID) {
			t.Errorf("%s: %s %v, want BLOCK by %s", text, r.Decision, r.TriggeredRules, policy.ProtectedPathRuleID)
		}
	}
	if r := l.read(`Get-Content "$($HOME)\notes.txt"`); r.Decision == policy.DecisionBlock {
		t.Errorf("a home file that is not protected BLOCKs: %v", r.TriggeredRules)
	}
}
