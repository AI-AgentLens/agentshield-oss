package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The cmdlet bridge at the hook entry point (assembly.PowerShellLane.
// CmdletBridge). A file cmdlet call or an output redirection is read as its
// POSIX twin (`cat`, `cp`, `mv`, `rm`, `echo x > f`) in a second POSIX text
// beside the native bridge's, on every row the PowerShell lane is on, so the
// bash rules for file operations reach Claude Code's PowerShell tool and
// Copilot's Windows rows with the bash rule's receipt.
//
// Each test reads its call twice: with the cmdlet bridge switched off
// (AGENTSHIELD_TEST_CMDLET_BRIDGE=off, which only this test binary reads:
// pinTestCmdletBridge), the control that shows main does not decide it, and
// with it on. The attack strings are assembled at run time: the hook on a
// developer machine reads test sources it is asked to run as commands.

// envTestCmdletBridge switches the cmdlet bridge off in this test binary and
// every child it re-execs. The agentshield binary has no such switch.
const envTestCmdletBridge = "AGENTSHIELD_TEST_CMDLET_BRIDGE"

func pinTestCmdletBridge() {
	if os.Getenv(envTestCmdletBridge) == "off" {
		cmdletBridge = false
	}
}

var cmdletBridgeOff = []string{envTestCmdletBridge + "=off"}

// TestCmdletBridgeSwitch_TestBinaryOnly: no Go file the agentshield binary
// is built from names the switch, and none but its declaration assigns
// cmdletBridge, so an agent cannot turn the bridge off.
func TestCmdletBridgeSwitch_TestBinaryOnly(t *testing.T) {
	assign := regexp.MustCompile(`\bcmdletBridge\s*=[^=]`)
	files, assigns := 0, 0
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "node_modules") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		if strings.Contains(string(data), envTestCmdletBridge) {
			t.Errorf("%s names %s", path, envTestCmdletBridge)
		}
		assigns += len(assign.FindAllIndex(data, -1))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 500 || assigns != 1 {
		t.Errorf("%d non-test Go files, %d assignments to cmdletBridge; want hundreds of files and only the declaration", files, assigns)
	}
}

// cmdletBridgeCase is a PowerShell call the bridge BLOCKs by a bash rule.
type cmdletBridgeCase struct {
	name, ps, rule, node string
}

func cmdletBridgeCases() []cmdletBridgeCase {
	s3 := ".s3" + "cfg"
	rc := ".bash" + "rc"
	read, readNode := "sec-block-cloud-storage-creds", "credential-exposure/cloud-credentials/cloud-storage-credential-access"
	write, writeNode := "ts-block-shell-profile-append", "persistence-evasion/shell-startup/shell-profile-backdoor"
	return []cmdletBridgeCase{
		{"read, POSIX spelling", "Get-Content ~/" + s3, read, readNode},
		{"read, ~\\", `Get-Content ~\` + s3, read, readNode},
		{"read, $env:USERPROFILE\\", `gc $env:USERPROFILE\` + s3, read, readNode},
		{"redirection write, POSIX spelling", "Get-Date >> ~/" + rc, write, writeNode},
		{"redirection write, $HOME\\", `'x' >> $HOME\` + rc, write, writeNode},
		{"redirection write, $env:USERPROFILE\\", `Get-Date >> $env:USERPROFILE\` + rc, write, writeNode},
	}
}

// TestPowerShellLane_CmdletBridge_ClaudeCodeRow: on Claude Code's
// PowerShell row (Structured + PowerShell, no POSIX lane), a file cmdlet's
// read of a credential file and a redirection's write to a shell profile
// BLOCK by the bash rule, with its taxonomy node, and the PowerShell lane's
// reading is kept. Without the bridge, neither BLOCKs.
func TestPowerShellLane_CmdletBridge_ClaudeCodeRow(t *testing.T) {
	for _, c := range cmdletBridgeCases() {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, psCall(t, c.ps), cmdletBridgeOff...)
			off := routingEvents(t, configDir)
			if len(off) != 1 || off[0].Decision == "BLOCK" || slices.Contains(off[0].TriggeredRules, c.rule) {
				t.Fatalf("control, bridge off: events %+v; want one event that is not %s's BLOCK", off, c.rule)
			}

			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, psCall(t, c.ps))
			on := routingEvents(t, configDir)
			if len(on) != 1 {
				t.Fatalf("events %+v (stderr %s); want one", on, stderr)
			}
			e := on[0]
			if code != 2 || e.Decision != "BLOCK" || !slices.Contains(e.TriggeredRules, c.rule) || !slices.Contains(e.Taxonomy, c.node) {
				t.Fatalf("exit %d, %s %v %v; want BLOCK (exit 2) by %s with %s", code, e.Decision, e.TriggeredRules, e.Taxonomy, c.rule, c.node)
			}
			if readings := laneReadingsDetail(e); !strings.Contains(readings, "kept=powershell") {
				t.Errorf("lane_readings %q: want the PowerShell lane's reading kept", readings)
			}
		})
	}
}

// TestPowerShellLane_CmdletBridge_CopilotNativeRow: the same on Copilot's
// native powershell row (POSIX + PowerShell). POSIX reads the raw text and
// does not see a Windows spelling as the file, so the PowerShell lane's
// BLOCK by the bash rule is kept.
func TestPowerShellLane_CmdletBridge_CopilotNativeRow(t *testing.T) {
	for _, c := range cmdletBridgeCases() {
		if !strings.Contains(c.ps, `\`) {
			continue // POSIX reads a POSIX spelling itself; this row's gap is the Windows one
		}
		t.Run(c.name, func(t *testing.T) {
			payload := copilotNativePayload(t, "cmdlet-bridge", "powershell", shellArgs(c.ps))
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, payload, cmdletBridgeOff...)
			off := routingEvents(t, configDir)
			if len(off) != 1 || off[0].Decision == "BLOCK" {
				t.Fatalf("control, bridge off: events %+v; want one event that is not a BLOCK", off)
			}

			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, payload)
			on := routingEvents(t, configDir)
			if len(on) != 1 {
				t.Fatalf("events %+v (stderr %s); want one", on, stderr)
			}
			e := on[0]
			if code != 2 || e.Decision != "BLOCK" || !slices.Contains(e.TriggeredRules, c.rule) || !slices.Contains(e.Taxonomy, c.node) {
				t.Fatalf("exit %d, %s %v %v; want BLOCK (exit 2) by %s with %s", code, e.Decision, e.TriggeredRules, e.Taxonomy, c.rule, c.node)
			}
			if readings := laneReadingsDetail(e); !strings.Contains(readings, "kept=powershell") {
				t.Errorf("lane_readings %q: want the PowerShell lane's reading kept", readings)
			}
		})
	}
}

// TestPowerShellLane_CmdletBridge_PinnedBashOverMatch pins two harmless
// calls the bridge BLOCKs (Gary, 2026-11-07: pin, don't fix). Each is a
// PowerShell rule's TN whose twin a bash rule over-matches on bash too, so
// the bridge imports that bash false positive:
//
//   - `Add-Content ~/.bashrc.bak 'x'` is `echo x >> ~/.bashrc.bak`:
//     ts-block-shell-profile-append's echo/printf/cat alternative keeps main's
//     unbounded tail on purpose (#4699), so `.bashrc.bak` matches `.bashrc`.
//   - `Set-Content ~/.claude/settings.json.bak '{}'` is the same class:
//     ts-block-agent-settings-write's `settings(?:\.local)?\.json` has no end
//     anchor.
//
// Fixing either is a narrowing of the bash rule (the critical set), not
// this change. TestPowerShellRuleYAMLTests grades only the PowerShell rule's
// own matcher, so it cannot see these; this test and
// assembly.TestCmdletBridge_NoNewBlockOnHarmlessInputs do. When a bash rule
// is fixed, its row here fails, and the pin goes.
func TestPowerShellLane_CmdletBridge_PinnedBashOverMatch(t *testing.T) {
	for _, c := range []struct{ ps, bash, rule string }{
		{"Add-Content ~/.bash" + "rc.bak 'x'", "echo x >> ~/.bash" + "rc.bak", "ts-block-shell-profile-append"},
		{"Set-Content ~/.claude/" + "settings.json.bak '{}'", "echo x > ~/.claude/" + "settings.json.bak", "ts-block-agent-settings-write"},
	} {
		t.Run(c.rule, func(t *testing.T) {
			// The bash rule BLOCKs the twin's own text through the Bash tool.
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, claudeShaped(t, "PreToolUse", "Bash", routingCmd(c.bash), nil))
			if b := routingEvents(t, configDir); len(b) != 1 || b[0].Decision != "BLOCK" || !slices.Contains(b[0].TriggeredRules, c.rule) {
				t.Fatalf("the Bash tool on %q: %+v; want %s's BLOCK (the over-match this pins)", c.bash, b, c.rule)
			}
			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, psCall(t, c.ps), cmdletBridgeOff...)
			if off := routingEvents(t, configDir); len(off) != 1 || off[0].Decision == "BLOCK" {
				t.Fatalf("control, bridge off: %+v; want no BLOCK, as on main", off)
			}
			home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
			runHookChild(t, home, psCall(t, c.ps))
			if on := routingEvents(t, configDir); len(on) != 1 || on[0].Decision != "BLOCK" || !slices.Contains(on[0].TriggeredRules, c.rule) {
				t.Errorf("bridge on: %+v; want the pinned BLOCK by %s", on, c.rule)
			}
		})
	}
}

// TestPowerShellLane_CmdletBridge_AuditOnlyKeepsLogDelete: with paths
// resolved, `Remove-Item ~\.agentshield\a\b\c.jsonl` is `rm
// ~/.agentshield/a/b/c.jsonl`, which ts-block-agentshield-log-delete
// BLOCKs, and audit-only mode keeps that BLOCK (a self-protection decision,
// mcp.ShellSelfProtectionKeep), as it does for the Bash tool. No PowerShell
// rule names that path, so without the bridge the call is not a BLOCK.
func TestPowerShellLane_CmdletBridge_AuditOnlyKeepsLogDelete(t *testing.T) {
	ps := `Remove-Item ~\.agent` + `shield\a\b\c.jsonl`
	const rule = "ts-block-agentshield-log-delete"
	for _, mode := range []string{"enforce", "audit-only"} {
		t.Run(mode, func(t *testing.T) {
			home := func() (string, string) {
				home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				if err := os.WriteFile(filepath.Join(configDir, "agentshield.yaml"), []byte("mode: "+mode+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return home, configDir
			}
			h, configDir := home()
			runHookChild(t, h, psCall(t, ps), cmdletBridgeOff...)
			if off := routingEvents(t, configDir); len(off) != 1 || off[0].Decision == "BLOCK" {
				t.Fatalf("control, bridge off: %+v; want no BLOCK, as on main", off)
			}
			h, configDir = home()
			code, _, stderr := runHookChild(t, h, psCall(t, ps))
			on := routingEvents(t, configDir)
			if code != 2 || len(on) != 1 || on[0].Decision != "BLOCK" || !slices.Contains(on[0].TriggeredRules, rule) {
				t.Fatalf("exit %d, events %+v (stderr %s); want BLOCK (exit 2) by %s, kept in %s mode", code, on, stderr, rule, mode)
			}
		})
	}
}
