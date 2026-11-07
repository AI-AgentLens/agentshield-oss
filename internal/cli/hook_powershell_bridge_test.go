package cli

import (
	"slices"
	"strings"
	"testing"
)

// The native-command bridge at the hook entry point (#4768).
//
// Claude Code's PowerShell row is Structured + PowerShell, with no POSIX
// lane, so before the bridge the shell rules for cross-platform programs
// never read it: `git push --force origin main` BLOCKed through the Bash tool
// and decided AUDIT through the PowerShell tool. The bridge reads the argv
// each native program receives with the POSIX lane, so the PowerShell call
// now carries the Bash call's receipt: the same rule ids and taxonomy.
//
// The attack strings are assembled at run time: the hook on a developer
// machine reads test sources it is asked to run as commands.

func bridgeCLICommands() []string {
	return []string{
		"git push " + "--force origin main",
		"terraform " + "destroy -auto-approve",
		"kubectl delete " + "namespace production",
		"git credential " + "fill",
		"gh auth " + "token",
	}
}

// bridgeOnlySpelling is a native call only the bridge reads: the call
// operator, a quoted Windows path and `.exe`, which the bash parser reading
// the raw text does not see as git.
func bridgeOnlySpelling() string {
	return `& 'C:\Program Files\Git\bin\git.exe' push ` + "--force origin main"
}

// TestPowerShellLane_NativeBridge_ClaudeCodeRow: each CLI command decides as
// the Bash tool does, with the Bash receipt's rules and taxonomy, and the
// PowerShell lane's reading is the one kept.
func TestPowerShellLane_NativeBridge_ClaudeCodeRow(t *testing.T) {
	for _, cmd := range append(bridgeCLICommands(), bridgeOnlySpelling()) {
		t.Run(cmd, func(t *testing.T) {
			bashCmd := cmd
			if cmd == bridgeOnlySpelling() {
				bashCmd = "git push " + "--force origin main"
			}
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(bashCmd), nil))
			bash := routingEvents(t, configDir)

			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(cmd), nil))
			ps := routingEvents(t, configDir)
			if len(bash) != 1 || len(ps) != 1 {
				t.Fatalf("events: Bash %d, PowerShell %d; want one each (stderr %s)", len(bash), len(ps), stderr)
			}
			b, p := bash[0], ps[0]
			if b.Decision != "BLOCK" {
				t.Fatalf("control: the Bash tool decides %s %v, want BLOCK", b.Decision, b.TriggeredRules)
			}
			if code != 2 || p.Decision != "BLOCK" {
				t.Fatalf("PowerShell: exit %d, %s %v; want BLOCK (exit 2)", code, p.Decision, p.TriggeredRules)
			}
			if !slices.Equal(p.TriggeredRules, b.TriggeredRules) || !slices.Equal(p.Taxonomy, b.Taxonomy) {
				t.Errorf("PowerShell receipt %v %v, want the Bash receipt %v %v", p.TriggeredRules, p.Taxonomy, b.TriggeredRules, b.Taxonomy)
			}
			if readings := laneReadingsDetail(p); !strings.Contains(readings, "kept=powershell") {
				t.Errorf("lane_readings %q: want the PowerShell lane's reading kept", readings)
			}
		})
	}
}

// TestPowerShellLane_NativeBridge_EveryHookRow: the hook runs the bridge on
// every row the PowerShell lane is on, Copilot's two included (Kai,
// 2026-11-04). There POSIX reads the raw text too. The CLI commands BLOCK
// through POSIX, which keeps its record on the tie, as on main. A Windows
// spelling of the program, which POSIX reads as a different program
// (`git.exe`, a quoted path behind `&`), now BLOCKs through the bridge with
// the Bash tool's rule, where main decided AUDIT. shield-server's half of
// the split, no bridge beside POSIX, is TestRoutedRequest_NativeBridge.
func TestPowerShellLane_NativeBridge_EveryHookRow(t *testing.T) {
	copilotOnWindows := append([]string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, onWindows...)
	rows := []struct {
		name    string
		payload func(cmd string) string
		env     []string
	}{
		{"compat Bash on Windows", func(cmd string) string { return copilotCompatPayload(t, "bridge", "Bash", shellArgs(cmd)) }, copilotOnWindows},
		{"native powershell", func(cmd string) string { return copilotNativePayload(t, "bridge", "powershell", shellArgs(cmd)) }, nil},
	}
	windows := map[string]bool{bridgeOnlySpelling(): true, bridgeExeSpelling(): true}
	for _, r := range rows {
		for _, cmd := range append(bridgeCLICommands(), bridgeOnlySpelling(), bridgeExeSpelling()) {
			t.Run(r.name+"/"+cmd, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				_, _, stderr := runHookChild(t, home, r.payload(cmd), r.env...)
				events := routingEvents(t, configDir)
				if len(events) != 1 || events[0].Decision != "BLOCK" {
					t.Fatalf("events %+v (stderr %s); want one BLOCK", events, stderr)
				}
				readings := laneReadingsDetail(events[0])
				switch {
				case !windows[cmd] && !strings.Contains(readings, "kept=posix"):
					t.Errorf("lane_readings %q: want POSIX's reading kept, as on main", readings)
				case windows[cmd] && (!strings.Contains(readings, "posix=AUDIT") || !strings.Contains(readings, "kept=powershell") ||
					!slices.Contains(events[0].TriggeredRules, "ts-block-git-force-push-main")):
					t.Errorf("rules %v, lane_readings %q: want POSIX's AUDIT, and the bridge's BLOCK by the Bash tool's rule kept",
						events[0].TriggeredRules, readings)
				}
			})
		}
	}
}

// bridgeExeSpelling is the force push with the program written `git.exe`,
// which the bash parser reads as a program other than git.
func bridgeExeSpelling() string { return "git.exe push " + "--force origin main" }

func laneReadingsDetail(e routingEvent) string {
	for _, n := range e.Notes {
		if n.Kind == "lane_readings" {
			return n.Detail
		}
	}
	return ""
}
