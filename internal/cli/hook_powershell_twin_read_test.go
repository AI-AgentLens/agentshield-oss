package cli

import (
	"strings"
	"testing"
)

// The falsification test for the twin's plain-read exception
// (psLane.readTwin, Kai 2026-11-07): on a managed host the cmdlet bridge now
// reads a twin that is one plain read without the config directory's
// pattern. If that exception reached anything but a read, a config write,
// delete, move or copy written through PowerShell would decide lower. Every
// row here BLOCKs on both PowerShell rows the hook reads with the cmdlet
// bridge: Claude Code's PowerShell tool (no POSIX lane) and Copilot's native
// powershell (POSIX first). Every row also BLOCKs on 12acb39e, before the
// exception. Paths and verbs are assembled at run time: the hook reads test
// sources as commands.

// configSpellings are the ways a Windows agent names AgentShield's config
// directory, each with a trailing separator.
func configSpellings() map[string]string {
	dir := ".agent" + "shield"
	return map[string]string{
		`~\`:                `~\` + dir + `\`,
		`$HOME\`:            `$HOME\` + dir + `\`,
		`$env:USERPROFILE\`: `$env:USERPROFILE\` + dir + `\`,
		"forward slash":     "~/" + dir + "/",
	}
}

// managedTwinRows runs each call on both rows on a managed host, with the
// cmdlet bridge on, and wants BLOCK.
func managedTwinRows(t *testing.T, calls map[string]string) {
	t.Helper()
	for name, cmd := range calls {
		for _, row := range []struct{ name, payload string }{
			{"claude-code PowerShell", psCall(t, cmd)},
			{"copilot native powershell", copilotNativePayload(t, "twin", "powershell", shellArgs(cmd))},
		} {
			t.Run(name+"/"+row.name, func(t *testing.T) {
				home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
				code, _, stderr := runHookChild(t, home, row.payload)
				if code != 2 {
					t.Fatalf("exit %d, want 2 (BLOCK). call: %s\nstderr:\n%s", code, cmd, stderr)
				}
				if e := oneEvent(t, configDir); e.Decision != "BLOCK" {
					t.Errorf("decision %q rules %v, want BLOCK", e.Decision, e.TriggeredRules)
				}
			})
		}
	}
}

// TestPowerShellLane_ManagedTwinRead_NoConfigWriteLowers: every config write,
// delete, move and copy, in every spelling, BLOCKs; so do a known read beside
// a delete in one call, and a read of a credential file outside the
// directory, whose twin is a plain read too.
func TestPowerShellLane_ManagedTwinRead_NoConfigWriteLowers(t *testing.T) {
	rm := "Remove" + "-Item "
	calls := map[string]string{}
	for spelling, d := range configSpellings() {
		p := d + "policy.yaml"
		for op, cmd := range map[string]string{
			"Set-Content":        "Set-Content " + p + " 'x'",
			"Add-Content":        "Add-Content " + p + " 'x'",
			"Out-File":           "'x' | Out-File " + p,
			"Out-File -Append":   "'x' | Out-File -Append " + p,
			"Remove-Item":        rm + p,
			"Remove-Item -Force": rm + "-Recurse -Force " + d,
			"Move-Item in":       "Move-Item C:\\tmp\\y " + p,
			"Move-Item out":      "Move-Item " + p + " C:\\tmp\\y",
			"Copy-Item in":       "Copy-Item C:\\tmp\\y " + p,
			"Copy-Item out":      "Copy-Item " + p + " C:\\tmp\\y",
			"redirect >":         "Get-Date > " + p,
			"redirect >>":        "Get-Date >> " + p,
		} {
			calls[op+" "+spelling] = cmd
		}
		// A file no sp-* text rule names: only the lane's own reading and
		// the twin's path layer stand in front of it.
		calls["Set-Content notes.txt "+spelling] = "Set-Content " + d + "notes.txt 'x'"
		calls["Remove-Item audit.jsonl "+spelling] = rm + d + "audit.jsonl"
		// A known read and a delete of the config in one call.
		calls["read then delete "+spelling] = "Get-Content " + p + "; " + rm + d + "managed.json"
	}
	calls["ssh key read"] = "Get-Content $env:USERPROFILE" + strings.ReplaceAll(sshKeyPath()[1:], "/", `\`)
	managedTwinRows(t, calls)
}

// TestPowerShellLane_ManagedTwinRead_SecondStatementKeepsBlock: a known read
// of the policy beside a harmless second statement still BLOCKs. Parity with
// the Bash tool, which BLOCKs `cat <policy>; rm x` because the whole command
// is not a plain read: the twin text `cat <policy>` + newline + `rm ./x` is
// not one either, so readTwin reads it with the pattern. (The lane's own
// reading BLOCKs it first: two commands are not a known read.)
//
// A second statement with no twin (`Get-Date`) leaves the twin text one
// plain read, so readTwin reads it without the pattern; the call still
// BLOCKs, by the lane's own reading, as the Bash tool BLOCKs `cat <policy>;
// date`.
func TestPowerShellLane_ManagedTwinRead_SecondStatementKeepsBlock(t *testing.T) {
	rm := "r" + "m"
	for _, bash := range []string{
		"cat ~/.agent" + "shield/policy.yaml; " + rm + " x",
		"cat ~/.agent" + "shield/policy.yaml; date",
	} {
		home, _ := newFailSafeHome(t, true, failSafePolicyGood)
		if code, _, stderr := runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(bash), nil)); code != 2 {
			t.Fatalf("control: the Bash tool's %q exits %d, want 2. stderr:\n%s", bash, code, stderr)
		}
	}
	calls := map[string]string{}
	for spelling, d := range configSpellings() {
		calls["Remove-Item "+spelling] = "Get-Content " + d + "policy.yaml; Remove" + `-Item .\x`
		calls["Get-Date "+spelling] = "Get-Content " + d + "policy.yaml; Get-Date"
	}
	managedTwinRows(t, calls)
}

// TestPowerShellLane_ManagedTwinRead_UntwinnedWriteBesideARead (#4841, Codex
// pass 1): a read and a write the cmdlet bridge has no twin for, in a
// spelling of the config path the lane's own reading does not resolve
// (`/./` before the home directory). The twin text is the read's `cat`
// alone, one plain read, and the twin's config pattern is the only layer that
// BLOCKs the call. The exception applies only to a call that is a known read,
// so it still BLOCKs. Before that gate it decided AUDIT on Claude Code's row,
// and the policy file was emptied. The write alone was the gap the twin
// covered: it decided AUDIT on that row (the lane's resolver). Since #4830's
// lexical reading the lane's own reading BLOCKs it too, which the first
// assertion now pins; the combined row stays.
func TestPowerShellLane_ManagedTwinRead_UntwinnedWriteBesideARead(t *testing.T) {
	clear := "Clear" + "-Content "
	for _, row := range []string{"claude-code PowerShell", "copilot native powershell"} {
		t.Run(row, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			p := dotRootSpelling(home) + "/.agent" + "shield/policy.yaml"
			payload := func(cmd string) string {
				if row == "claude-code PowerShell" {
					return psCall(t, cmd)
				}
				return copilotNativePayload(t, "twin", "powershell", shellArgs(cmd))
			}
			if row == "claude-code PowerShell" {
				if code, _, stderr := runHookChild(t, home, payload(clear+p)); code != 2 {
					t.Fatalf("%s alone exits %d; want 2, the lane's lexical reading (#4830). stderr:\n%s", clear+p, code, stderr)
				}
				if e := oneEvent(t, configDir); e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, "enterprise-self-protect") {
					t.Errorf("write alone: decision %q rules %v, want BLOCK by enterprise-self-protect", e.Decision, e.TriggeredRules)
				}
				home, configDir = newFailSafeHome(t, true, failSafePolicyGood)
				p = dotRootSpelling(home) + "/.agent" + "shield/policy.yaml"
			}
			cmd := "Get-Content " + p + "; " + clear + p
			code, _, stderr := runHookChild(t, home, payload(cmd))
			if code != 2 {
				t.Fatalf("exit %d, want 2 (BLOCK). call: %s\nstderr:\n%s", code, cmd, stderr)
			}
			if e := oneEvent(t, configDir); e.Decision != "BLOCK" {
				t.Errorf("decision %q rules %v, want BLOCK", e.Decision, e.TriggeredRules)
			}
		})
	}
}
