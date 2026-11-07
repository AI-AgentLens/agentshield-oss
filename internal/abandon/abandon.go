// Package abandon stops an evaluation whose call has already been answered
// (#4785).
//
// The hook's decision budget (internal/cli/hook_budget.go) answers a call
// whose analysis outlasts it: the watchdog claims the call, records the
// fail-safe reading and exits the process. Before #4785 the evaluating
// goroutine kept running and allocating after that claim. On a slower host
// with every CPU busy, the answer then competed with it and with the garbage
// collector its allocations kept triggering, and reached the harness after
// the harness's hook timeout, when the harness had already run the call.
//
// Stop marks the evaluation abandoned. The evaluating goroutine parks at the
// next Checkpoint it reaches, so its CPU and its allocations stop. The hot
// loops of the evaluation call Checkpoint: each analyzer in the pipeline,
// each rule and each match form in the regex stage, each heuristic in the
// guardian stage, each statement the candidate builders read.
//
// Three properties keep it from changing anything else, and the tests pin
// each one:
//
//   - Before Stop, Checkpoint is one atomic load that returns: an evaluation
//     that is never abandoned runs exactly as it did before #4785.
//   - Only the goroutine Bind named parks. The watchdog's own answer, and
//     anything else running in the process, can pass a Checkpoint without
//     stopping; a goroutine id that cannot be read parks nothing.
//   - Only the hook calls Bind and Stop, and it calls Stop only once its
//     watchdog holds the call's claim. shield-server, the MCP proxies,
//     mcp-eval and check never do, so for them every Checkpoint returns.
//
// The package imports only the standard library: every evaluating package
// can depend on it.
package abandon

import (
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var (
	// stopped is set once, by Stop, and never cleared in a process that
	// exits after its one call.
	stopped atomic.Bool
	// evaluator is the id of the goroutine Bind named, 0 for none.
	evaluator atomic.Int64
)

// Bind names the calling goroutine as the one evaluating the call: the only
// goroutine a Checkpoint will park. The hook calls it when it arms the
// call's budget, on the goroutine that then evaluates.
func Bind() {
	evaluator.Store(goid())
}

// Stop marks the evaluation abandoned: from now on the bound goroutine parks
// at its next Checkpoint. Called by the decision budget's watchdog after it
// holds the call's claim, and by nothing else.
func Stop() {
	stopped.Store(true)
}

// Stopped reports whether Stop has been called.
func Stopped() bool {
	return stopped.Load()
}

// Checkpoint parks the calling goroutine for good when the evaluation has
// been abandoned and the caller is the bound evaluating goroutine; otherwise
// it returns at once. Call it only where the goroutine holds no lock and no
// half-written shared state, so that the goroutine answering the call can
// never wait on what the parked one holds: at the head of a loop in the
// evaluation, never inside a sync.Once, a mutex or a write.
func Checkpoint() {
	if checkpointHook != nil {
		checkpointHook()
	}
	if !stopped.Load() {
		return
	}
	id := evaluator.Load()
	if id == 0 || id != goid() {
		return
	}
	park()
}

// park holds the abandoned goroutine until the process exits. It sleeps
// rather than blocking on nothing, so the runtime's deadlock detector never
// mistakes it for a hang while the answering goroutine waits on I/O. A
// variable only so a test can unwind the goroutine instead.
var park = func() {
	for {
		time.Sleep(time.Hour)
	}
}

// checkpointHook, when set, runs at every Checkpoint. A test seam: tests use
// it to measure the work between consecutive checkpoints. nil in production.
var checkpointHook func()

// goid is the calling goroutine's id, read from the first line of its stack
// trace ("goroutine 18 [running]:"), or 0 when that line does not parse. It
// runs once per call in Bind, and in Checkpoint only after Stop.
func goid() int64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	rest, ok := strings.CutPrefix(string(buf[:n]), "goroutine ")
	if !ok {
		return 0
	}
	i := strings.IndexByte(rest, ' ')
	if i <= 0 {
		return 0
	}
	id, err := strconv.ParseInt(rest[:i], 10, 64)
	if err != nil || id <= 0 {
		return 0
	}
	return id
}

// ResetForTest clears Stop and Bind, for a test that abandons an evaluation
// and then runs another in the same process. Only tests call the ForTest
// functions (TestForTestFunctionsOnlyInTests).
func ResetForTest() {
	stopped.Store(false)
	evaluator.Store(0)
}

// SetParkForTest replaces what a parked goroutine does, so a test can unwind
// it (runtime.Goexit) instead of leaving it asleep, and returns the restore.
func SetParkForTest(f func()) (restore func()) {
	old := park
	park = f
	return func() { park = old }
}

// SetCheckpointHookForTest installs f to run at every Checkpoint and returns
// the restore.
func SetCheckpointHookForTest(f func()) (restore func()) {
	old := checkpointHook
	checkpointHook = f
	return func() { checkpointHook = old }
}
