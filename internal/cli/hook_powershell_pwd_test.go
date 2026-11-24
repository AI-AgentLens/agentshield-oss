package cli

import "testing"

// TestPowerShellLane_PWDReading_4830: on a managed host with the payload's
// cwd at home, a write of the config directory spelled through `$PWD` BLOCKs
// on Claude Code's PowerShell row. The reader keeps `$PWD` as written, so
// these decided AUDIT on main (#4830); the lane's second reading reads a
// leading `$PWD` as the call's cwd. After a location change `$PWD` is another
// directory, so the control is not read that way and decides as on main.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).
func TestPowerShellLane_PWDReading_4830(t *testing.T) {
	as := ".agent" + "shield"
	rows := []struct {
		name, cmd string
		want      int
	}{
		{"Set-Content", `Set-Content "$PWD\` + as + `\notes.txt" x`, 2},
		{"redirect", `'x' > "$PWD\` + as + `\notes.txt"`, 2},
		{"Out-File", `'x' | Out-File $PWD\` + as + `\notes.txt`, 2},
		{"control: after Set-Location", `Set-Location C:\proj; Set-Content $PWD\` + as + `\notes.txt x`, 0},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, psCallIn(t, r.cmd, home))
			if code != r.want {
				t.Fatalf("%q with cwd at home exits %d, want %d. stderr:\n%s", r.cmd, code, r.want, stderr)
			}
			if r.want == 2 {
				if e := oneEvent(t, configDir); e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, "enterprise-self-protect") {
					t.Errorf("event decision %q rules %v, want BLOCK by enterprise-self-protect", e.Decision, e.TriggeredRules)
				}
			}
		})
	}
}
