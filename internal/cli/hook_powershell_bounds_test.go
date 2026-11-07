package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// The PowerShell lane's work on a long text is bounded (Opus pass 2 on
// #4245, F1): it runs inside a hook Copilot times out at 30 s, failing open.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).

// psBudgetTexts are the reviewer's shapes at 64 KiB: a destructive prefix
// the POSIX lane BLOCKs on main, then one long word of tilde, dollar or `=~`
// units, plain and inside two nested iex strings (the PowerShell lane reads
// the word three times). Before the bounds the lane alone took 3.6 s to
// 110 s on them. Two more fill the dimension the bounds leave uncapped,
// whole values: many short paths, and many bare names read under cwd.
func psBudgetTexts() map[string]string {
	prefix := routingDestructive() + "; "
	out := map[string]string{}
	for name, unit := range map[string]string{"tilde-long": "ab=~/a/b/c.", "dollar": "a=$x", "eqtilde": "a=~x"} {
		word := strings.Repeat(unit, 64*1024/len(unit))
		out[name+"-plain"] = prefix + "Write-Output " + word
		out[name+"-iex2"] = prefix + "iex 'iex ''Write-Output " + word + "'''"
	}
	for name, format := range map[string]string{"many-paths": "~/p%d", "many-bare": "b%d"} {
		var ws []string
		for size, i := 0, 0; size < 64*1024; i++ {
			w := fmt.Sprintf(format, i)
			ws = append(ws, w)
			size += len(w) + 1
		}
		out[name+"-plain"] = prefix + "Write-Output " + strings.Join(ws, " ")
	}
	return out
}

// The budgets are wall-clock, on a CI VM other jobs share (an identical
// commit has measured 1.5x slower there, #3505), so each leaves a margin of
// 3x or more over what it measured on an M-series Mac; the failure they pin
// is quadratic, 5x to 100x.
//
// psLaneBudget is what the PowerShell lane alone may spend on one of the
// reviewer's 64 KiB texts: reading it, its nested texts, and deciding on
// each. Measured: 0.03-0.21 s. Before the bounds: 3.6-110 s.
const psLaneBudget = 2 * time.Second

// psLaneWholeValueBudget is the same for the two texts made of whole values,
// which no bound caps (a cap could drop a path that BLOCKs): their cost is
// linear in the number of values, about 0.1-0.2 ms each, so 64 KiB of them
// measured 1.1 s (paths) and 1.9 s (bare names, also read under cwd), and
// the reader's 128 KiB text bound caps them at about twice that.
const psLaneWholeValueBudget = 10 * time.Second

// psHookBudget is what the whole hook may spend on one 64 KiB call on
// Copilot's row, the bash pipeline included (main's own cost, 1.5-4 s here
// on these texts). Measured: 2.2-4.5 s. Half of Copilot's 30 s timeoutSec,
// which fails open; before the bounds these calls took 15-110 s.
const psHookBudget = 15 * time.Second

// TestPSLane_ReadBudget (Opus pass 2 on #4245, F1): the lane's own work on
// each budget text is bounded.
func TestPSLane_ReadBudget(t *testing.T) {
	l := testPSLane(t, 2)
	for name, text := range psBudgetTexts() {
		budget := psLaneBudget
		if strings.HasPrefix(name, "many-") {
			budget = psLaneWholeValueBudget
		}
		start := time.Now()
		r := l.read(text)
		d := time.Since(start)
		t.Logf("%s (%d bytes): %v, %s", name, len(text), d, r.Decision)
		if d > budget {
			t.Errorf("%s: the PowerShell lane took %v, budget %v", name, d, budget)
		}
	}
}

// TestPowerShellLane_VerdictBudgetOnCopilot (Opus pass 2 on #4245, F1): on
// Copilot's native powershell row each budget text reaches a verdict inside
// psHookBudget through the real hook, and the verdict is main's: the POSIX
// lane's BLOCK of the destructive prefix.
func TestPowerShellLane_VerdictBudgetOnCopilot(t *testing.T) {
	for name, text := range psBudgetTexts() {
		if strings.HasPrefix(name, "eqtilde") {
			continue // the lane test covers it; the hook test is about 3 s a row
		}
		t.Run(name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			start := time.Now()
			code, _, stderr := runHookChild(t, home, copilotNativePayload(t, "budget", "powershell", shellArgs(text)))
			d := time.Since(start)
			t.Logf("%s (%d bytes): %v", name, len(text), d)
			if code != 2 {
				t.Fatalf("exit %d, want 2 (main's BLOCK). stderr:\n%.400s", code, stderr)
			}
			e := oneEvent(t, configDir)
			if e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, "ts-block-rm-root") {
				t.Errorf("decision %s rules %v, want main's BLOCK by ts-block-rm-root", e.Decision, e.TriggeredRules)
			}
			if d > psHookBudget {
				t.Errorf("verdict after %v, budget %v (Copilot fails open at 30 s)", d, psHookBudget)
			}
		})
	}
}
