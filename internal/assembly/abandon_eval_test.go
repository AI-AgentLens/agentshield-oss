package assembly

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"runtime/metrics"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/abandon"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// The hook's watchdog stops an evaluation it has answered (#4785): the
// evaluating goroutine parks at its next abandon.Checkpoint. These tests
// measure, on the real engine and the shipped community packs, how much work
// an evaluation can still do after the stop, in bytes allocated (wall time
// on a shared runner is noise, #3505): at most the largest unit of work
// between two consecutive checkpoints.

// abandonShapes are commands slow enough that the budget fires on them on a
// real host, in four shapes that stress different stages: the brace command
// the box measurements use (one long simple command, every regex rule
// rescanning each whole-command form), a long pipeline, a long && chain
// (per-statement retry candidates) and a heredoc body.
func abandonShapes() map[string]string {
	repeat := func(head, unit string, size int) string {
		var sb strings.Builder
		sb.WriteString(head)
		for sb.Len() < size {
			sb.WriteString(unit)
		}
		return strings.TrimSpace(sb.String())
	}
	return map[string]string{
		"brace":    repeat("echo x{a,b,c,d} y{a,b,c,d} z{a,b,c,d} w{a,b,c} ", "cat file.txt ", 6<<10),
		"pipeline": repeat("cat file.txt", " | grep a", 16<<10),
		"chain":    repeat("cat file.txt", " && cat b.txt", 4<<10),
		"heredoc":  repeat("cat > notes.md <<'EOF'\n", "some notes about the build and a path /usr/local/bin here\n", 128<<10) + "\nEOF",
	}
}

func abandonEngine(t *testing.T) *policy.Engine {
	t.Helper()
	pol, _, err := policy.LoadEmbeddedShellPacks(policy.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ShellEngine(pol, 0, "enforce")
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

// evaluateAsHook evaluates cmd the way the hook's POSIX lane does.
func evaluateAsHook(eng *policy.Engine, cmd string) policy.EvalResult {
	n := normalize.NormalizeCommand(cmd, "/tmp")
	return eng.EvaluateWithParsedCwd(cmd, n.Paths, n.Parsed, "/tmp")
}

var allocSample = []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}

func allocBytes() uint64 {
	metrics.Read(allocSample)
	return allocSample[0].Value.Uint64()
}

// checkpointProfile is one evaluation seen from its checkpoints.
type checkpointProfile struct {
	checkpoints int
	total       uint64 // bytes allocated from the first checkpoint to the last
	maxGap      uint64 // most bytes allocated between two consecutive checkpoints
}

func profileCheckpoints(t *testing.T, eng *policy.Engine, cmd string) (checkpointProfile, policy.EvalResult) {
	t.Helper()
	var p checkpointProfile
	var first, last uint64
	restore := abandon.SetCheckpointHookForTest(func() {
		now := allocBytes()
		if p.checkpoints == 0 {
			first = now
		} else if gap := now - last; gap > p.maxGap {
			p.maxGap = gap
		}
		last = now
		p.checkpoints++
	})
	defer restore()
	r := evaluateAsHook(eng, cmd)
	p.total = last - first
	return p, r
}

// TestAbandon_CheckpointsCutTheEvaluationIntoSmallUnits: on every shape, the
// largest piece of work between two consecutive checkpoints is a small
// fraction of the evaluation. That fraction is what the evaluation can still
// do after the watchdog stops it. Removing the regex stage's per-rule or
// per-form checkpoints, the stage that dominates, leaves one unit as large as
// the stage, and this fails.
func TestAbandon_CheckpointsCutTheEvaluationIntoSmallUnits(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates slow commands")
	}
	eng := abandonEngine(t)
	for name, cmd := range abandonShapes() {
		t.Run(name, func(t *testing.T) {
			p, _ := profileCheckpoints(t, eng, cmd)
			t.Logf("%s (%d KiB): %d checkpoints, %d KiB allocated between the first and the last, largest unit %d KiB (%.2f%%)",
				name, len(cmd)>>10, p.checkpoints, p.total>>10, p.maxGap>>10, 100*float64(p.maxGap)/float64(max(p.total, 1)))
			// Vacuity: the evaluation passed through the checkpoints and did
			// real work between them.
			if p.checkpoints < 500 || p.total < 4<<20 {
				t.Fatalf("%d checkpoints, %d bytes: the probe saw no evaluation", p.checkpoints, p.total)
			}
			unit := parseUnit(cmd)
			bound := maxUnitParses*unit + maxUnitCopies*uint64(len(cmd))
			t.Logf("one parse allocates %d KiB; largest unit %.1f parses, bound %d KiB", unit>>10, float64(p.maxGap)/float64(max(unit, 1)), bound>>10)
			if p.maxGap > bound {
				t.Errorf("largest unit between checkpoints is %d bytes; want at most %d (%d parses of the command plus %d copies of its text)", p.maxGap, bound, maxUnitParses, maxUnitCopies)
			}
		})
	}
}

// A unit of work between two checkpoints may parse the command a few times
// and copy its text a few dozen times, and no more: that is what one helper
// that parses the whole command and walks the tree allocates
// (ExecutedTextReport, AttributionStatements, the guardian's form setup; the
// parser itself has no checkpoints), and what building a few rendered forms
// of a heredoc-sized text allocates. The bound grows with the command, as
// the work does; the regex stage's rule loop without its checkpoints is
// hundreds of parses (measured on the brace shape: 300 MB against a 4.5 MB
// parse).
const (
	maxUnitParses = 4
	maxUnitCopies = 64
)

// parseUnit is what one parse of cmd allocates: shellparse.Parse, the
// structural stage's reading of the whole command.
func parseUnit(cmd string) uint64 {
	before := allocBytes()
	_ = shellparse.Parse(cmd, 0)
	return allocBytes() - before
}

// TestAbandon_StoppedEvaluationParksWithinOneUnit stops a running evaluation
// from another goroutine at a random moment, as the watchdog does, and
// measures the work the evaluating goroutine does between the stop and its
// park: at most one unit (the largest gap the profile above measured), and
// the evaluation never returns a result. The control evaluates the same
// command to completion with the goroutine bound and nothing stopped.
func TestAbandon_StoppedEvaluationParksWithinOneUnit(t *testing.T) {
	if testing.Short() {
		t.Skip("evaluates slow commands")
	}
	eng := abandonEngine(t)
	cmd := abandonShapes()["brace"]
	p, want := profileCheckpoints(t, eng, cmd)

	// Control: bound, never stopped, the evaluation completes with the
	// result it has unbound.
	t.Cleanup(abandon.ResetForTest)
	var got policy.EvalResult
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); abandon.Bind(); got = evaluateAsHook(eng, cmd) }()
	wg.Wait()
	if got.Decision != want.Decision || strings.Join(got.TriggeredRules, ",") != strings.Join(want.TriggeredRules, ",") {
		t.Fatalf("control: bound and not stopped, the evaluation decided %s %v; unbound %s %v", got.Decision, got.TriggeredRules, want.Decision, want.TriggeredRules)
	}

	for i := 0; i < 5; i++ {
		abandon.ResetForTest()
		parkedAt := make(chan uint64, 1)
		restorePark := abandon.SetParkForTest(func() {
			parkedAt <- allocBytes()
			runtime.Goexit()
		})
		returned := make(chan policy.EvalResult, 1)
		started := make(chan struct{})
		go func() {
			abandon.Bind()
			close(started)
			returned <- evaluateAsHook(eng, cmd)
		}()
		<-started
		time.Sleep(time.Duration(50+rand.IntN(400)) * time.Millisecond)
		stoppedAt := allocBytes()
		abandon.Stop()
		select {
		case at := <-parkedAt:
			after := at - stoppedAt
			t.Logf("run %d: %d KiB allocated between the stop and the park (largest unit %d KiB)", i, after>>10, p.maxGap>>10)
			if after > p.maxGap+(64<<10) {
				t.Errorf("run %d: %d bytes allocated after the stop; want at most one unit (%d)", i, after, p.maxGap)
			}
		case r := <-returned:
			t.Fatalf("run %d: the evaluation returned (%s) instead of parking: the stop came too late to test, or nothing parks", i, r.Decision)
		case <-time.After(30 * time.Second):
			t.Fatalf("run %d: the evaluation neither parked nor returned within 30 s of the stop", i)
		}
		select {
		case r := <-returned:
			t.Fatalf("run %d: a parked evaluation returned %s", i, r.Decision)
		default:
		}
		restorePark()
	}
}

// TestAbandon_PowerShellLaneStopsBetweenReadings: the PowerShell lane, which
// the Copilot CLI rows on Windows and Claude Code's PowerShell tool run,
// stops at its next reading once the watchdog has stopped the evaluation.
// Fifty nested sh texts, the stop arriving inside the first one's POSIX
// reading: the lane reads no second one, and never returns. The control,
// never stopped, reads all fifty.
func TestAbandon_PowerShellLaneStopsBetweenReadings(t *testing.T) {
	t.Cleanup(abandon.ResetForTest)
	const n = 50
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "sh -c a%d; ", i)
	}
	text := b.String()
	run := func(stopAtFirst bool) (calls int, returned bool) {
		abandon.ResetForTest()
		parked := make(chan struct{})
		restore := abandon.SetParkForTest(func() { close(parked); runtime.Goexit() })
		defer restore()
		done := make(chan struct{})
		go func() {
			abandon.Bind()
			l := &PowerShellLane{Engine: abandonEngine(t), Env: psreader.Env{Home: "/home/u"}, Opts: policy.FactsOptions{Home: "/home/u"},
				Cwd: "/home/u", MaxDepth: 2,
				POSIX: func(string) policy.EvalResult {
					calls++
					if stopAtFirst {
						abandon.Stop()
					}
					return policy.EvalResult{Decision: policy.DecisionAudit}
				}}
			_, _ = l.Read(text)
			close(done)
		}()
		select {
		case <-done:
			return calls, true
		case <-parked:
			return calls, false
		case <-time.After(30 * time.Second):
			t.Fatal("the lane neither returned nor parked")
		}
		return calls, false
	}
	if calls, returned := run(false); !returned || calls != n {
		t.Fatalf("control: never stopped, the lane read %d nested texts (returned %v); want all %d", calls, returned, n)
	}
	if calls, returned := run(true); returned || calls != 1 {
		t.Errorf("stopped inside the first nested reading, the lane read %d nested texts (returned %v); want 1 and parked", calls, returned)
	}
}
