package cli

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/abandon"
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// #4785: on a slower host with every CPU busy, the budget's answer reached
// the harness after its hook timeout. The watchdog now stops the evaluation
// it pre-empts (abandon) and switches the GC off, the budget counts from
// process creation on Windows, and a record the watchdog writes too close to
// the timeout says so (markLate).

// TestHookBudget_MarkLate pins markLate's contract for a call the watchdog
// answers: marked only once its record starts within hookAnswerExitGuard of
// the harness's timeout, only on the analysis_budget_exceeded note, and the
// redacted fields are untouched.
func TestHookBudget_MarkLate(t *testing.T) {
	secret := "pass" + "word=" + "pw" + "Secret99xyz"
	budgetDetail := "budget=8.87s; harness=codex; harness_timeout=10s; tool=Bash"
	ev := logger.AuditEvent{
		Command: "echo " + secret, Args: []string{"echo", secret}, Decision: "BLOCK",
		Notes: []logger.Note{
			{Kind: analyzer.NotePayloadCwdUnusable, Detail: "cwd note"},
			{Kind: analyzer.NoteAnalysisBudgetExceeded, Detail: budgetDetail},
		},
	}
	red := ev.RedactOnce()
	watchdog := &hookBudget{owner: budgetWatchdog, timeout: 10 * time.Second}
	evaluation := &hookBudget{owner: budgetEvaluation, timeout: 10 * time.Second}
	onTime := 10*time.Second - hookAnswerExitGuard - time.Millisecond
	late := 10*time.Second - hookAnswerExitGuard

	same := func(name string, got logger.RedactedEvent) {
		t.Helper()
		if fmt.Sprint(got.Event()) != fmt.Sprint(red.Event()) {
			t.Errorf("%s: the record changed:\n got %+v\nwant %+v", name, got.Event().Notes, red.Event().Notes)
		}
	}
	var none *hookBudget
	same("no budget armed", none.markLate(red, 11*time.Second))
	// An evaluation's late record gets its own note (#4818,
	// TestHookBudget_MarkLate_Evaluation_4818); on time it is untouched.
	same("the evaluation answered on time", evaluation.markLate(red, onTime))
	same("watchdog, on time", watchdog.markLate(red, onTime))

	for _, at := range []time.Duration{late, 10 * time.Second, 12 * time.Second} {
		got := watchdog.markLate(red, at).Event()
		if got.Command != red.Event().Command || strings.Join(got.Args, " ") != strings.Join(red.Event().Args, " ") || strings.Contains(got.Command, secret) {
			t.Errorf("at %s: the redacted fields changed: %q %q", at, got.Command, got.Args)
		}
		if got.Notes[0] != ev.Notes[0] {
			t.Errorf("at %s: a note other than the budget's changed: %+v", at, got.Notes[0])
		}
		verdict := "possible"
		if at >= 10*time.Second {
			verdict = "true"
		}
		want := fmt.Sprintf("%s; answered_after_harness_timeout=%s; recorded_at=%s; exit_guard=%s", budgetDetail, verdict, at.Truncate(time.Millisecond), hookAnswerExitGuard)
		if got.Notes[1].Detail != want {
			t.Errorf("at %s: budget note\n got %q\nwant %q", at, got.Notes[1].Detail, want)
		}
	}
	// The input is never modified: markLate copies the notes.
	if red.Event().Notes[1].Detail != budgetDetail {
		t.Errorf("markLate modified its input's notes: %q", red.Event().Notes[1].Detail)
	}
}

// TestHookBudget_LateAnswerIsMarked runs the hook end to end on a managed
// fail_closed host as Codex runs it (10 s timeout), the budget answering at
// once. The test-only before-record slow point holds the watchdog just before
// it writes, the way a starved host does: past hookAnswerExitGuard before the
// timeout the BLOCK record says the answer may be late; the control, with no
// delay, says nothing. Either way the verdict is the same BLOCK, exit 2 with
// the reason on stderr.
func TestHookBudget_LateAnswerIsMarked(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a hook call for most of Codex's 10 s timeout")
	}
	timeout := hookTimeouts[route.Codex].timeout
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingDestructive()), map[string]interface{}{"turn_id": "turn-1"})
	cases := []struct {
		name string
		slow time.Duration
		late bool
	}{
		{"on time", 0, false},
		{"held past the guard", timeout - hookAnswerExitGuard + 200*time.Millisecond, true},
	}
	var mu sync.Mutex
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mu.Lock()
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			mu.Unlock()
			env := []string{envTestHookBudget + "=1ns"}
			if c.slow > 0 {
				env = append(env, envTestHookSlow+"=before-record="+c.slow.String())
			}
			code, _, stderr := runHookChild(t, home, payload, env...)
			if code != 2 || !strings.Contains(stderr, "Reason:") {
				t.Fatalf("exit %d; want Codex's BLOCK (exit 2 with a Reason line). stderr:\n%s", code, stderr)
			}
			e := oneEvent(t, configDir)
			notes := budgetNotes(e.Notes)
			if e.Decision != "BLOCK" || len(notes) != 1 {
				t.Fatalf("event %s with budget notes %v; want the budget's BLOCK", e.Decision, notes)
			}
			marked := strings.Contains(notes[0], "answered_after_harness_timeout=")
			if marked != c.late {
				t.Errorf("budget note %q: marked late %v, want %v", notes[0], marked, c.late)
			}
			if c.late && !strings.Contains(notes[0], "recorded_at=") {
				t.Errorf("late note %q does not say when it was recorded", notes[0])
			}
		})
	}
}

// TestHookBudget_WatchdogStopsTheEvaluation: once the watchdog holds the
// claim, the evaluation it pre-empted stops using the CPU. The child's own
// CPU time shows it. The watchdog is held 4 s before it writes (the
// before-record slow point), on a command whose analysis takes far longer;
// the evaluation stopped, the child spends a fraction of the CPU that the
// same analysis spends in the same wall time when nothing stops it (the
// control, budget off, killed after the same time).
func TestHookBudget_WatchdogStopsTheEvaluation(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a slow analysis twice")
	}
	const hold = 4 * time.Second
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(slowBraceCommand(24<<10)), nil)

	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	control := hookChildCPU(t, home, payload, 300*time.Millisecond+hold, envTestHookBudget+"=off")

	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	stopped := hookChildCPU(t, home, payload, 0, envTestHookBudget+"=300ms", envTestHookSlow+"=before-record="+hold.String())
	if n := budgetNotes(oneEvent(t, configDir).Notes); len(n) != 1 {
		t.Fatalf("the budget did not answer the call (notes %v)", n)
	}
	t.Logf("CPU over ~%s: analysis left running %s, analysis stopped by the watchdog %s", hold, control, stopped)
	if control < 2*time.Second {
		t.Skipf("control: the unstopped analysis used only %s of CPU in %s; the machine is too busy to tell", control, hold)
	}
	if stopped > control/2 {
		t.Errorf("with the evaluation stopped the hook used %s of CPU, more than half of the %s it uses unstopped", stopped, control)
	}
}

// hookChildCPU runs the hook in a child and returns its user plus system CPU
// time. killAfter > 0 kills the child after that long (the control, which
// would otherwise analyse for minutes).
func hookChildCPU(t *testing.T, home, payload string, killAfter time.Duration, extraEnv ...string) time.Duration {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHookProcess$")
	cmd.Env = append(append(withoutEnv(os.Environ(), "AGENTSHIELD_AGENT_ID="), "AGENTSHIELD_FAILSAFE_HOOK_HELPER=1", "HOME="+home), extraEnv...)
	cmd.Stdin = strings.NewReader(payload)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if killAfter > 0 {
		timer := time.AfterFunc(killAfter, func() { _ = cmd.Process.Kill() })
		defer timer.Stop()
	}
	_ = cmd.Wait()
	return cmd.ProcessState.UserTime() + cmd.ProcessState.SystemTime()
}

// envTestStopHelper runs TestHelperStopEvaluation's body in a child: it
// stops this process's GC for good, so it cannot run in the test binary.
const envTestStopHelper = "AGENTSHIELD_TEST_STOP_EVALUATION_HELPER"

func TestHelperStopEvaluation(t *testing.T) {
	if os.Getenv(envTestStopHelper) != "1" {
		return
	}
	before := gcPercentNow()
	stopEvaluation()
	deadline := time.Now().Add(5 * time.Second)
	for gcPercentNow() != -1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Printf("before=%d after=%d stopped=%v\n", before, gcPercentNow(), abandon.Stopped())
	os.Exit(0)
}

// gcPercentNow reads the GC percent without changing it (runtime/metrics
// reports -1, GC off, as the uint64 of -1).
func gcPercentNow() int64 {
	s := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(s)
	return int64(s[0].Value.Uint64())
}

// TestStopEvaluation_StopsAndSwitchesOffGC: stopEvaluation marks the
// evaluation abandoned and switches the GC off (in a child process).
func TestStopEvaluation_StopsAndSwitchesOffGC(t *testing.T) {
	if gcPercentNow() == -1 {
		t.Fatal("control: the GC is already off in this test binary")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperStopEvaluation$")
	cmd.Env = append(os.Environ(), envTestStopHelper+"=1", "GOGC=100")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, out)
	}
	if got := strings.TrimSpace(string(out)); got != "before=100 after=-1 stopped=true" {
		t.Errorf("stopEvaluation: %q; want the GC off and the evaluation stopped", got)
	}
}

// TestProcessStart: the budget's zero point is the process's creation time
// when the OS gives a plausible one, else Go's start, and it keeps Go's
// monotonic clock either way.
func TestProcessStart(t *testing.T) {
	goStart := time.Now()
	created := func(c time.Time, ok bool) func() (time.Time, bool) {
		return func() (time.Time, bool) { return c, ok }
	}
	wall := goStart.Round(0)
	cases := []struct {
		name    string
		created func() (time.Time, bool)
		lead    time.Duration
	}{
		{"no creation time", created(time.Time{}, false), 0},
		{"created 1.4 s before Go started", created(wall.Add(-1400*time.Millisecond), true), 1400 * time.Millisecond},
		{"created after Go started (clock moved)", created(wall.Add(time.Second), true), 0},
		{"created at the same instant", created(wall, true), 0},
		{"created more than the max lead before", created(wall.Add(-processStartMaxLead-time.Second), true), 0},
		{"created exactly the max lead before", created(wall.Add(-processStartMaxLead), true), processStartMaxLead},
	}
	for _, c := range cases {
		got := processStart(goStart, c.created)
		if lead := goStart.Sub(got); lead != c.lead {
			t.Errorf("%s: zero point %s before Go's start, want %s", c.name, lead, c.lead)
		}
		if !strings.Contains(got.String(), "m=") {
			t.Errorf("%s: the zero point lost the monotonic clock: %s", c.name, got)
		}
	}
	if _, ok := processCreated(); ok && runtime.GOOS != "windows" {
		t.Errorf("processCreated reports a creation time on %s; only the Windows build reads one", runtime.GOOS)
	}
}

// TestHookBudget_ConstantsPinned_4785 pins the numbers the box measured
// (#4785; see hookBudgetMargin, hookRecordReservePerKiB and
// hookAnswerExitGuard for the measurements). A change here is a change to
// what the guarantee rests on, to be re-measured on the slow host.
func TestHookBudget_ConstantsPinned_4785(t *testing.T) {
	pins := []struct {
		name      string
		got, want time.Duration
	}{
		{"hookBudgetMargin", hookBudgetMargin, 1500 * time.Millisecond},
		{"hookRecordReservePerKiB", hookRecordReservePerKiB, time.Millisecond},
		{"hookRecordReserveEnrolledPerKiB", hookRecordReserveEnrolledPerKiB, 1200 * time.Microsecond},
		{"hookAnswerExitGuard", hookAnswerExitGuard, 1400 * time.Millisecond},
		{"processStartMaxLead", processStartMaxLead, 60 * time.Second},
	}
	for _, p := range pins {
		if p.got != p.want {
			t.Errorf("%s = %s; pinned at %s", p.name, p.got, p.want)
		}
	}
	// The guard must leave an answer the budget times normally unmarked: the
	// record of a call answered at its budget starts at least the margin
	// before the timeout, and the guard is less than that.
	if hookAnswerExitGuard >= hookBudgetMargin {
		t.Errorf("hookAnswerExitGuard %s is not below hookBudgetMargin %s: every budget answer would be marked late", hookAnswerExitGuard, hookBudgetMargin)
	}
	if hookRecordReserveEnrolledPerKiB <= hookRecordReservePerKiB {
		t.Errorf("the enrolled reserve %s is not above the local-only %s", hookRecordReserveEnrolledPerKiB, hookRecordReservePerKiB)
	}
}

// TestAbandon_ForTestFunctionsOnlyInTests: the abandon package's ForTest
// functions (which replace what a parked goroutine does, and clear a stop)
// are called from no non-test file of the build.
func TestAbandon_ForTestFunctionsOnlyInTests(t *testing.T) {
	root := filepath.Join("..", "..")
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "build", "dist", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "abandon.Checkpoint()") {
			seen++
		}
		for _, f := range []string{"ResetForTest(", "SetParkForTest(", "SetCheckpointHookForTest("} {
			if strings.Contains(string(src), f) && filepath.Base(filepath.Dir(path)) != "abandon" {
				t.Errorf("%s calls abandon.%s: only tests may", path, f)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Control: the walk reaches the evaluating packages.
	if seen < 6 {
		t.Fatalf("found abandon.Checkpoint in %d files; the walk did not reach the evaluation", seen)
	}
}
