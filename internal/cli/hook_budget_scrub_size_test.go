package cli

// Gary, 2026-11-06: the budget's answer withholds a labelled record's agent
// text instead of scrubbing it when scrubbing would land the answer past the
// harness timeout (scrubOrWithhold).

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// TestScrubOrWithhold_TooLargeToScrubInTime is the decision: withheld only
// when labels would scrub the record and the estimate does not fit in the
// time left before the timeout less the exit guard.
func TestScrubOrWithhold_TooLargeToScrubInTime(t *testing.T) {
	scrub := &recordLabels{scrub: func(string) []datalabel.Span { return nil }}
	none := &recordLabels{}
	already := &recordLabels{withheld: "data labels unreadable: x"}
	b := &hookBudget{timeout: 10 * time.Second}
	mib := 1 << 20
	// The elapsed time at which a size's estimate exactly fills what is left.
	edge := func(size int) time.Duration {
		return b.timeout - hookAnswerExitGuard - time.Duration(size)*budgetScrubCostPerKiB/1024
	}
	for _, c := range []struct {
		name     string
		l        *recordLabels
		size     int
		elapsed  time.Duration
		withheld bool
	}{
		{"labelled, 1 MiB, past what is left", scrub, mib, edge(mib) + time.Millisecond, true},
		{"labelled, 1 MiB, exactly what is left", scrub, mib, edge(mib), false},
		{"labelled, small command near the deadline", scrub, 200, b.timeout - hookAnswerExitGuard - 50*time.Millisecond, false},
		{"labelled, already past the exit guard", scrub, 200, b.timeout - time.Second, true},
		{"no labels, 1 MiB, at the timeout", none, mib, b.timeout, false},
		{"labels already withheld", already, mib, b.timeout, false},
		{"no label set at all", nil, mib, b.timeout, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := b.scrubOrWithhold(c.l, c.size, c.elapsed)
			if !c.withheld {
				if got != c.l {
					t.Fatalf("labels replaced with %+v; want them unchanged", got)
				}
				return
			}
			if got == c.l || got.withheld == "" || got.scrub != nil {
				t.Fatalf("got %+v; want the agent text withheld", got)
			}
			if !strings.Contains(got.withheld, "too large to scrub before the harness timeout") {
				t.Errorf("detail %q does not say why", got.withheld)
			}
		})
	}
}

// TestFailSafeRecord_TooLargeToScrub_AnsweredOnTime runs the hook as Codex
// does on a managed fail_closed host with data labels, its budget set to
// answer 2 s before Codex's 10 s timeout and the policy load past it. A
// 1 MiB command carrying a label value is withheld, not scrubbed, and the
// BLOCK arrives before the timeout with no label value in the line or the
// wire. Scrubbing it instead took 1.7 s or more on an idle Mac, past the
// time left. Controls: a small labelled command is still scrubbed, and a
// 1 MiB command on a host with no labels is recorded as before. The wall
// time is held as checkBudgetAnswerTime says: strictly before the timeout
// only on the nightly perf run (make test-perf).
func TestFailSafeRecord_TooLargeToScrub_AnsweredOnTime(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out an 8 s budget per row")
	}
	value := labelValue4805()
	big := "echo '" + strings.Repeat("ticket "+value+" notes ", (1<<20)/25) + "' > notes.txt"
	for _, c := range []struct {
		name, policy, cmd string
		want              string // "withheld", "scrubbed" or "verbatim"
	}{
		{"labelled, 1 MiB", labelledPolicy4805, big, "withheld"},
		{"labelled, small (control)", labelledPolicy4805, labelCmd4805(), "scrubbed"},
		{"no labels, 1 MiB (control)", failSafePolicyGood, big, "verbatim"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, true, c.policy)
			wire.enroll(t)
			start := time.Now()
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, c.cmd), budgetEnv("8s", "load=30s")...)
			took := time.Since(start)
			t.Logf("%d KiB command answered after %s (Codex timeout 10s)", len(c.cmd)>>10, took)
			if c.want == "verbatim" {
				// The fixed 8 s budget skips the record reserve production
				// takes off a 1 MiB command on an enrolled host (about 1.2 s,
				// hookBudgetFor), so this control runs later than production
				// would, and Codex's timeout is not its bound. Only the CI
				// tail is.
				checkBudgetAnswerTime(t, took, 8*time.Second, 0)
			} else {
				checkBudgetAnswerTime(t, took, 8*time.Second, 10*time.Second)
			}
			if r.exit != 2 || r.decision != "BLOCK" {
				t.Fatalf("exit %d decision %s, want the managed fail_closed BLOCK (exit 2)", r.exit, r.decision)
			}
			switch c.want {
			case "scrubbed":
				checkRecord4805(t, r, "BLOCK", "scrubbed", true)
			case "withheld":
				checkRecord4805(t, r, "BLOCK", "withheld", true)
				if !strings.Contains(r.line, "too large to scrub before the harness timeout") || !strings.Contains(r.wireText(), "too large to scrub before the harness timeout") {
					t.Errorf("the %s note does not say the text was too large to scrub:\n%.2000s", withheldKind, r.line)
				}
			case "verbatim":
				var e logger.AuditEvent
				if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
					t.Fatalf("line: %v", err)
				}
				if e.Command != c.cmd || fmt.Sprint(r.wire[0]["command"]) != c.cmd {
					t.Errorf("a no-label host's command was not recorded as written (line %d bytes, wire %d bytes, want %d)", len(e.Command), len(fmt.Sprint(r.wire[0]["command"])), len(c.cmd))
				}
				if strings.Contains(r.line+r.wireText(), withheldKind) {
					t.Errorf("a no-label host's record carries %s", withheldKind)
				}
			}
		})
	}
}

// checkBudgetAnswerTime holds a budget answer's wall time to the two bounds
// TestHookBudget_ProductionBinaryAtCodexTimeout uses. Always: within
// hookCITailTolerance of the budget. With SHIELD_PERF_BUDGET (the nightly
// perf workflow, make test-perf, on a quiet machine): strictly before the
// harness's timeout, the guarantee itself. A fixed "before 10 s" on every
// run failed inside a full `go test ./...` at load 20-26 (10.25 s on the
// 1 MiB no-labels control, #4827), where it measures the machine, as #3505
// found for the pipeline budget. What makes the answer on time, the record
// being withheld rather than scrubbed, is asserted on every run. A zero
// timeout means the row has no harness bound, only the CI tail.
func checkBudgetAnswerTime(t *testing.T, took, budget, timeout time.Duration) {
	t.Helper()
	if took > budget+hookCITailTolerance {
		t.Errorf("answered after %s, more than %s past its %s budget", took, hookCITailTolerance, budget)
	}
	if timeout > 0 && os.Getenv(hookPerfBudgetEnv) != "" && took >= timeout {
		t.Errorf("answered after %s, at or past Codex's %s timeout: the harness would have run the call", took, timeout)
	}
}
