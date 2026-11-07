package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/abandon"
	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The hook's decision budget (#4772, Gary 2026-11-04: "AUDIT, BLOCK if
// fail_closed").
//
// A harness runs `agentshield hook` as a short-lived process and waits for it
// up to its own hook timeout. Past that timeout the harnesses we know of run
// the tool call anyway: unevaluated, and with no audit record, because the
// hook never got to write one. That is true on a managed fail_closed host
// too. fail_closed is a decision the hook makes, and a hook that has not
// answered has made none.
//
// So the hook keeps its own budget, set just under the harness's timeout and
// measured from this process's start (hookProcessStart: its creation on
// Windows, where a loaded host takes over a second to reach Go's first
// instruction): startup, the engine build, the evaluation and the audit write
// all count. When the budget runs out before
// the evaluation has claimed the call, a watchdog decides it the way every
// other evaluation failure is decided (failSafeReading): BLOCK
// (enterprise-fail-closed) under managed fail_closed, AUDIT
// (agentshield-eval-error) with a flagged, error-carrying event otherwise. Its
// one event carries an analysis_budget_exceeded note naming the budget, the
// harness, its timeout and the tool, and its output is the harness's own
// verdict for that decision, written by the same function the evaluation
// would have used. A call decided within the budget is untouched: same
// event, same output, same exit code.
//
// Exactly one side answers a call. The evaluation claims it before it writes
// anything a harness or an auditor reads (claimForEvaluation: the audit line,
// the SaaS queue, stdout, its exit code); the watchdog claims it before it
// writes its own (fire). The first claim wins. An evaluation that loses parks
// until the watchdog exits the process; a watchdog that loses returns without
// writing. What follows a claim is not covered by the budget, so the margin
// below has to hold the winner's tail: the audit write, the SaaS queue, the
// verdict and the exit.
//
// The watchdog's tail is kept short (#4785). On a 4-core host with all 8
// logical CPUs busy, the answer used to compete with the evaluation it had
// pre-empted, which kept running and allocating, and with the GC cycles that
// allocation triggered: a Codex call whose budget fired at 8.9 s answered at
// 10.1-13 s. Now, once it holds the claim, the watchdog stops the evaluation
// (stopEvaluation: the evaluating goroutine parks at its next
// abandon.Checkpoint) and switches the GC off; the record is redacted once
// for both its copies (redactForRecord, #4781), behind a prescan that skips
// every secret pattern the text cannot match (internal/redact); and a record
// written too close to the timeout says the answer may be late (markLate).
//
// Not covered:
//   - a payload whose read and parse alone outlast the timeout: the budget
//     counts from process start, but arming waits for the harness to be
//     known (stdin is read once, and a payload is parsed in milliseconds);
//   - a harness whose timeout we do not know (Cursor, Windsurf) has no
//     budget and decides exactly as before;
//   - a harness configured with a shorter timeout than the one below (a
//     hand-written hook entry, or an older Claude Code, see
//     claudeCodeHookTimeout);
//   - shield-server's /v1/evaluate and its thin clients, which time out at 5 s
//     and fail open (#4772: the remaining gap);
//   - a winner's tail that outlasts the margin and the record reserve, as
//     measured in hookBudgetMargin: the first exec of a binary macOS has not
//     seen (its signature check runs before Go starts, and outside Windows
//     the budget counts from Go's start). The watchdog's record says so when
//     it starts within hookAnswerExitGuard of the timeout (markLate); one
//     written earlier whose exit still lands late is not marked. The
//     synchronous upload (AGENTSHIELD_AUDIT_UPLOAD=sync, or an enrolled host
//     whose audit queue cannot be written, #4782) is no longer part of that
//     tail: uploadTimeout cuts it to the time left, at the cost of the SaaS
//     copy of that event (#4803);
//   - an evaluation that does not reach a checkpoint: the PowerShell lane and
//     MCP policy have none (each bounds its own work, #4766), and the shell
//     parser has none inside one parse, so a stopped evaluation finishes the
//     parse it is in.

// hookTimeout is how long one harness waits for the hook before it runs the
// call without it, and where that number comes from.
type hookTimeout struct {
	timeout time.Duration
	source  string
}

// claudeCodeHookTimeout is Claude Code's hook timeout. `agentshield setup
// claude-code` has never written a "timeout" key (every revision of
// internal/cli/setup.go and scripts/install.ps1; the 10 s entry in
// setup_managed_test.go is a hypothetical migration fixture), so Claude Code's
// default applies: 600 s for a command hook since Claude Code 2.1.3, whose
// changelog reads "Changed tool hook execution timeout from 60 seconds to 10
// minutes"; https://code.claude.com/docs/en/hooks ("Defaults: 600 for
// `command`"). On PreToolUse a timed-out hook does not block the call unless
// the entry sets onFailure "block" (same page, "Timeouts"), which setup does
// not write.
//
// A decision for Gary (#4772), implemented here as Kai's recommendation, 600 s:
// it is the only choice that cannot lower a decision a default install of a
// current Claude Code would have made. Budgeting for 60 s (the pre-2.1.3
// default) would also cover Claude Code older than 2.1.3, at the price of
// deciding AUDIT, on an unmanaged host, a call whose analysis takes 59-600 s
// and which main decides by analysis. Reading the configured timeout from
// the harness settings at hook time cannot tell which of several scopes'
// entries started this process, and a repository's committed settings is one
// of those scopes.
const claudeCodeHookTimeout = 600 * time.Second

// hookTimeouts is every harness's hook timeout the budget is set under. A
// harness absent from the table has no budget: its timeout is not known, and
// a budget below an unknown timeout could lower a decision that would have
// been made in time.
var hookTimeouts = map[route.Harness]hookTimeout{
	route.ClaudeCode: {claudeCodeHookTimeout, "Claude Code default since 2.1.3 (setup writes no timeout); see claudeCodeHookTimeout"},
	// Codex: `setup codex` writes "timeout": 10 (seconds) on both of its
	// entries (agentshieldCodexHookGroup). Codex's own default when the key
	// is absent is 600 s (https://learn.chatgpt.com/docs/hooks: "timeout is in
	// seconds", "If timeout is omitted, Codex uses 600 seconds for most
	// hooks"). Its PreToolUse contract, in source (openai/codex,
	// codex-rs/hooks/src/events/pre_tool_use.rs): exit 2 blocks only when
	// stderr carries a reason ("PreToolUse hook exited with code 2 but did
	// not write a blocking reason to stderr" is a failure, not a block), and a
	// timeout is a failure, after which the tool runs. emitShellVerdict
	// writes the reason on every BLOCK, the budget's included
	// (TestHookBudget_ManagedFailClosedBLOCKs).
	route.Codex: {10 * time.Second, `setup codex writes "timeout": 10 (agentshieldCodexHookGroup)`},
	// Copilot CLI: `setup copilot-cli` writes "timeoutSec": 30, Copilot's
	// default (copilotHookFile), and a timeout is the one hook failure Copilot
	// treats as allow (captured live on Copilot CLI 1.0.93, #4251). The
	// native dialect reads the same key.
	route.CopilotCLI:       {30 * time.Second, `setup copilot-cli writes "timeoutSec": 30 (copilotHookFile); a timeout fails open`},
	route.CopilotCLINative: {30 * time.Second, `Copilot CLI default "timeoutSec": 30, as setup writes it; a timeout fails open`},
	// Gemini CLI: `setup gemini-cli` writes "timeout": 10000 (milliseconds,
	// agentshieldGeminiHookEntry). Gemini's default is 60000 ms
	// (google-gemini/gemini-cli docs/hooks/reference.md). Exit 2 blocks with
	// stderr as the reason, a {"decision": "deny"} on stdout blocks too (the
	// form this hook writes), and any other failure, a timeout included, is a
	// warning after which the tool runs (docs/hooks/index.md; hookRunner.ts).
	route.GeminiCLI: {10 * time.Second, `setup gemini-cli writes "timeout": 10000 ms (agentshieldGeminiHookEntry)`},
	// Cursor: setup writes no timeout, and Cursor documents a per-hook
	// "timeout" in seconds whose default is only "platform default"; a
	// timeout fails open unless the entry sets failClosed
	// (https://cursor.com/docs/agent/hooks). Unknown, so no budget.
	// Windsurf: setup writes no timeout and its hook docs say nothing about
	// one. Unknown, so no budget.
}

// hookBudgetMargin is how far under its harness's timeout the budget fires,
// before the record reserve (hookRecordReservePerKiB) is taken off. It holds
// the part of the winner's tail that does not grow with the command: the
// timer firing late, loading the config and opening the log, re-reading the
// log's last line to chain to it (as large as the previous call's command),
// the SaaS queue entry and its uploader's start, the verdict, and the exit,
// whose teardown of a large heap the harness waits for too.
//
// Sized on the slowest host we have (#4785): a Win10 i7-4770, 4 cores and 8
// logical CPUs, about half an M-series Mac's single-core speed, with all 8
// logical CPUs busy (8 PowerShell burners), the budget firing on calls whose
// analysis was still running, timed by the harness's side from spawn to
// exit. The size-independent part of the tail (time from the budget firing
// to the exit, less the reserve) measured up to 1.02 s; its pieces measured
// up to 0.30 s (config), 0.94 s (re-reading a 3 MB last line after a 1 MiB
// call) and 1.06 s (exit to the harness seeing it). 1.5 s holds the measured
// tail with half a second to spare. With it, wall time from spawn to exit,
// three calls per row, "enrolled" a managed fail_closed host with fake
// credentials (its BLOCK), the other an unmanaged host (its AUDIT):
//
//	                         8 logical CPUs busy          idle
//	                         not enrolled  enrolled       not enrolled  enrolled
//	Codex (10 s)    48 KiB   8.68-8.86 s   8.62-8.78 s    8.47-8.51 s   8.47-8.49 s
//	               256 KiB   8.57-8.70 s   8.54-9.13 s    8.29-8.30 s   8.26-8.27 s
//	                 1 MiB   8.08-8.61 s   7.95-8.80 s    7.65 s        7.49-7.53 s
//	Copilot (30 s) 128 KiB  28.77-28.95 s 28.78-29.51 s  28.45 s       28.44-28.47 s
//
// Before #4785 the busy rows answered at 11.5-42.5 s (Codex) and 31.5-35.4 s
// (Copilot), and the idle ones at 9.06-9.86 s and 29.11-29.15 s.
//
// Idle, the same tail measured 0.03-0.21 s on the box and 0.1-0.3 s on an
// M-series Mac (#4772): there the margin is mostly unused, and that is its
// cost. A call whose analysis ends
// inside the margin, which main would have answered in time, is decided by
// the fail-safe instead (AUDIT on an unmanaged host). Gary's rule is that the
// margin holds the measured tail; it is sized to the slow host's, not padded
// past it.
const hookBudgetMargin = 1500 * time.Millisecond

// hookProcessStart is the zero point of every budget: when the operating
// system created this process where it says (Windows), else when its Go code
// started. A harness's hook timeout starts when it spawns the hook, and on a
// slower host with every CPU busy the time from spawn to Go's package
// initialisation is not small: 0.7-2.3 s on a 4-core i7-4770 with all 8
// logical CPUs busy (#4785), against 18 ms warm on an idle Mac. Counting from
// Go's start, the budget could not see that second, and every loaded call
// answered about that much later than the budget had planned.
var hookProcessStart = processStart(time.Now(), processCreated)

// processStartMaxLead bounds how far before Go's start the creation time may
// lie and still be believed. A larger lead means a clock that moved between
// the two readings, and then Go's start is used, as before #4785.
const processStartMaxLead = 60 * time.Second

// processStart is goStart moved back to the process's creation time when the
// OS reports one within processStartMaxLead before it. It keeps goStart's
// monotonic reading, so the budget's timer is not affected by a wall-clock
// change after this point.
func processStart(goStart time.Time, created func() (time.Time, bool)) time.Time {
	c, ok := created()
	if !ok {
		return goStart
	}
	lead := goStart.Sub(c)
	if lead <= 0 || lead > processStartMaxLead {
		return goStart
	}
	return goStart.Add(-lead)
}

// hookRecordReservePerKiB is the time the budget keeps back for recording
// the call, per KiB of the text the event carries (the command, or a tool
// call's arguments), on a host that uploads nothing: redacting the event once
// (redactForRecord), marshalling and hashing its line and writing it. On the
// #4785 box with all 8 logical CPUs busy, after the watchdog has stopped the
// evaluation, that part of a 1 MiB call's tail measured 0.4-0.8 s; 1 ms per
// KiB holds it. Before #4785 the redaction alone took 6-11 ms per KiB there:
// each secret pattern walked the whole text, and the evaluation and the GC
// competed for the CPU.
const hookRecordReservePerKiB = time.Millisecond

// hookRecordReserveEnrolledPerKiB is the reserve on a host sendRemoteAudit
// uploads from (remoteAuditCredentials). Since #4781 the wire entry reuses the
// line's redaction, so the upload adds only its own marshal and the queue
// write: 0.05-0.22 s at 1 MiB on the box under load, about 0.2 ms per KiB
// over the local-only reserve. The enrolled 1 MiB call's whole tail measured
// 1.22-1.63 s against the 2.7 s margin and reserve hold. Before #4781 this
// reserve was 2.7 ms per KiB, sized for the second redaction (#4772 Opus pass
// 1); the smaller reserve is the window, at 1 MiB about 1.5 s, in which a
// call main would have decided by analysis on an enrolled host is decided by
// the fail-safe no longer.
const hookRecordReserveEnrolledPerKiB = 1200 * time.Microsecond

// hookBudgetFor is the budget for a call from harness h whose recorded text
// is size bytes, on a host that uploads its events (enrolled) or not: the
// harness's timeout less the margin and the record reserve, never below zero
// (the watchdog then answers at once, because recording the call alone would
// take the timeout), to the millisecond, and false when the harness has no
// known timeout.
func hookBudgetFor(h route.Harness, size int, enrolled bool) (budget, timeout time.Duration, ok bool) {
	switch {
	case hookBudgetOverride < 0:
		return 0, 0, false
	case hookBudgetOverride > 0:
		t := hookTimeouts[h].timeout
		return hookBudgetOverride, t, true
	}
	t, ok := hookTimeouts[h]
	if !ok {
		return 0, 0, false
	}
	reserve := hookRecordReservePerKiB
	if enrolled {
		reserve = hookRecordReserveEnrolledPerKiB
	}
	budget = t.timeout - hookBudgetMargin - time.Duration(size)*reserve/1024
	return max(budget, 0).Truncate(time.Millisecond), t.timeout, true
}

// Test seams. Only the internal/cli test binary sets them (pinTestHookBudget,
// called from TestMain, from environment variables only that binary reads),
// exactly as hostOS. The agentshield binary reads no environment variable for any of
// them: one that did would let an agent switch the budget off, or make every
// call decide AUDIT (TestHookBudgetSeams_ProductionBinaryIgnoresThem).
var (
	// hookBudgetOverride, when positive, is every harness's budget, those
	// with no known timeout included; when negative, no call is budgeted.
	hookBudgetOverride time.Duration
	// hookSlowPoints makes the hook sleep at a named point (hookSlowPoint):
	// "before-arm" (after the payload is parsed, before any handler arms the
	// budget), "load" (a shell lane, before it loads the config, #4805),
	// "evaluate" (each lane's evaluation step), "nested-posix"
	// (the PowerShell lane's POSIX reading of nested text and of the
	// native-command bridge), "before-redact" (an armed call's record,
	// before withholdIfTooSlow reads the clock, #4818), "before-record" (an
	// armed call's record, after its redaction and before markLate reads
	// the clock, #4785) and
	// "read-labels" (the watchdog's own read of the data labels, #4805, its
	// prefetch at half the budget included, #4814).
	hookSlowPoints map[string]time.Duration
	// hookLabelReadSeen is told each time the watchdog's own read of the
	// data labels starts, and by whom: "prefetch" or "watchdog"
	// (readDeclaredLabels, #4814), so a test can count the reads a call made.
	hookLabelReadSeen func(by string)
	// hookRaceGate holds each side's first claim until the other side has
	// reached its own, so the two contend for the claim at the same instant.
	hookRaceGate func(party string)
)

// hookSlowPoint sleeps for the duration the test binary set for point. A
// no-op in the agentshield binary, where hookSlowPoints is nil.
func hookSlowPoint(point string) {
	if d := hookSlowPoints[point]; d > 0 {
		time.Sleep(d)
	}
}

// budgetCall is what the watchdog needs to decide a call: everything the
// evaluation's own fail-safe reading of it would record, known before the
// evaluation starts.
type budgetCall struct {
	harness   route.Harness
	tool      string // the harness's tool or event name, for the note
	size      int    // bytes of the text the event records (hookBudgetFor)
	source    string // the shell source ("claude-code-hook", "cursor-hook", …)
	sessionID string

	// command is the text a shell-shaped event records. Set for a call one
	// of the shell lanes reads; empty for a tool call (toolCall).
	command string
	// emit writes the harness's verdict for a shell-shaped decision, the
	// function the evaluation calls with its own result. It exits 2 for a
	// BLOCK on the harnesses whose deny is an exit code.
	emit func(*policy.EvalResult)

	// toolCall is set for a call only MCP policy reads: its event is the
	// tool-call-shaped one auditMCPCall writes.
	toolCall     bool
	rawToolInput json.RawMessage

	// cwd is the evaluation directory and its notes, as the evaluation
	// computes them; called by the watchdog only.
	cwd func() (string, []logger.Note)
	// notes are the call's own notes known before evaluation (a routing gap).
	notes []logger.Note
}

// budgetOwner is who answers the call.
type budgetOwner int

const (
	budgetUnclaimed budgetOwner = iota
	budgetEvaluation
	budgetWatchdog
)

// hookBudget is one call's budget.
type hookBudget struct {
	call    budgetCall
	budget  time.Duration
	timeout time.Duration

	mu    sync.Mutex
	owner budgetOwner
	timer *time.Timer

	// answer writes the watchdog's reading and exits the process. A field
	// only so a unit test can count answers without exiting.
	answer func()
	// park holds an evaluation that lost the claim. A field for the same
	// reason; in the hook it never returns.
	park func()
	// evalGated is set once the evaluation has passed hookRaceGate; touched
	// by the evaluating goroutine only.
	evalGated bool
	// stop runs once the watchdog holds the claim, before it answers:
	// stopEvaluation in the hook. nil in a unit test that drives the claim
	// protocol in-process, where stopping this process's GC would outlive
	// the test.
	stop func()
	// labels is the data-label set the evaluation loaded (publishLabels),
	// for the watchdog's record (#4805); nil until the policy is complete.
	// Guarded by mu.
	labels *recordLabels
	// prefetched carries the watchdog's own read of the data labels when
	// prefetchLabels started it at half the budget (#4814); nil otherwise.
	// Guarded by mu.
	prefetched chan *recordLabels
}

// activeBudget is the budget of the call this process is answering, armed by
// a hook handler just before evaluation. nil everywhere else (every other
// command, and the tests that call evaluateCommand directly), where claiming
// is a no-op.
var activeBudget *hookBudget

// hookBudgetEnabled is set by hookCommand, the `agentshield hook` process's
// entry point, and nowhere else: a budget answers by exiting the process, so
// it is armed only in a process that exists to answer one call. A test that
// calls a handler in-process arms nothing.
var hookBudgetEnabled bool

// armHookBudget starts the budget for a call that is about to be evaluated.
// A harness with no known timeout is not armed. Arming twice keeps the first.
func armHookBudget(c budgetCall) {
	if !hookBudgetEnabled || activeBudget != nil {
		return
	}
	// Enrolled exactly when sendRemoteAudit will upload this call's event.
	budget, timeout, ok := hookBudgetFor(c.harness, c.size, remoteAuditCredentials() != nil)
	if !ok {
		return
	}
	b := &hookBudget{call: c, budget: budget, timeout: timeout, park: parkForever, stop: stopEvaluation}
	b.answer = b.answerFailSafe
	// The goroutine arming the budget is the one about to evaluate: the only
	// one abandon.Checkpoint may park once the watchdog answers.
	abandon.Bind()
	activeBudget = b
	b.mu.Lock()
	b.timer = time.AfterFunc(time.Until(hookProcessStart.Add(budget)), b.fire)
	b.mu.Unlock()
	// A tool call's record is never scrubbed with the data labels.
	if !c.toolCall {
		time.AfterFunc(time.Until(hookProcessStart.Add(budget/2)), b.prefetchLabels)
	}
}

// claimForEvaluation claims the call for the evaluation. Every write the
// hook makes for a call after arming goes through it first (the record step
// of each reading, failSafeDecision, and hookCommand's return). Once the
// evaluation holds the claim it answers alone: the timer is stopped and a
// watchdog that fires late finds the call taken. If the watchdog holds it,
// this never returns: the watchdog writes the call's one answer and exits
// the process. A nil budget (nothing armed) is a no-op.
func (b *hookBudget) claimForEvaluation() {
	if b == nil {
		return
	}
	if hookRaceGate != nil && !b.evalGated {
		b.evalGated = true
		hookRaceGate("evaluation")
	}
	b.mu.Lock()
	if b.owner == budgetUnclaimed {
		b.owner = budgetEvaluation
		if b.timer != nil {
			b.timer.Stop()
		}
	}
	owner := b.owner
	b.mu.Unlock()
	if owner == budgetWatchdog {
		b.park()
	}
}

// fire is the timer's callback: the budget ran out. It answers the call
// unless the evaluation claimed it first.
func (b *hookBudget) fire() {
	if hookRaceGate != nil {
		hookRaceGate("watchdog")
	}
	b.mu.Lock()
	if b.owner != budgetUnclaimed {
		b.mu.Unlock()
		return
	}
	b.owner = budgetWatchdog
	b.mu.Unlock()
	if b.stop != nil {
		b.stop()
	}
	b.answer()
}

// stopEvaluation is what the watchdog does the moment it holds the claim,
// before it answers (#4785). The evaluation it pre-empts is still running,
// and on a host whose CPUs are all busy the answer used to compete with it
// and with the garbage collector its allocations kept triggering: measured
// on a 4-core i7-4770 with all 8 logical CPUs busy, GC cycles ran at 9.1,
// 9.5, 10.0, 10.4 and 10.6 s, with stop-the-world pauses up to 65 ms, and a
// Codex call whose budget fired at 8.95 s answered at 10.1-10.7 s, after
// Codex's 10 s timeout.
//
//   - abandon.Stop parks the evaluating goroutine at its next checkpoint
//     (internal/abandon): the next rule, match form, analyzer or heuristic,
//     so its CPU and its allocations stop.
//   - The garbage collector is switched off, since the process exits once
//     the answer is written. SetGCPercent(-1) waits for a mark phase already
//     running to finish, so it runs on its own goroutine: the answer does
//     not wait for that cycle, and no cycle starts after it.
func stopEvaluation() {
	abandon.Stop()
	go debug.SetGCPercent(-1)
}

// parkForever holds the evaluating goroutine while the watchdog answers and
// exits the process. It sleeps rather than blocking on nothing, so the
// runtime's deadlock detector never mistakes it for a hang if the watchdog
// is itself waiting on I/O.
func parkForever() {
	for {
		time.Sleep(time.Hour)
	}
}

// budgetNote is the analysis_budget_exceeded note on the watchdog's event.
func (b *hookBudget) budgetNote() logger.Note {
	return logger.Note{
		Kind: analyzer.NoteAnalysisBudgetExceeded,
		Detail: fmt.Sprintf("budget=%s; harness=%s; harness_timeout=%s; tool=%s",
			b.budget, b.call.harness, b.timeout, b.call.tool),
	}
}

// hookAnswerExitGuard is how close to its harness's timeout the watchdog
// may start writing its record and still call the answer on time. Past it,
// the record says the answer may have reached the harness after the timeout
// (markLate). It holds the time from that point to the harness seeing the
// process exit: the local line, the SaaS queue entry and its uploader's
// start, the verdict, the exit and its teardown. On the #4785 box with all 8
// logical CPUs busy that measured 0.12-1.32 s. It stays under
// hookBudgetMargin, so an answer the budget timed normally starts its record
// before the guard and is not marked; one whose pre-record work ran slow is
// marked "possible" even when it then lands in time, which understates the
// receipt rather than overstating it.
const hookAnswerExitGuard = 1400 * time.Millisecond

// markLate marks the record of a call, the watchdog's answer (#4785) or the
// evaluation's own (#4818), when the answer may reach the harness after its
// hook timeout. at is the time since process start when the record is about
// to be written.
//
// Why a mark and not another order. The harness reads the verdict when the
// process exits (the exit code for Codex and Claude Code, stdout at EOF for
// Copilot), and the record has to be written before that exit, so a record
// always exists before the harness knows the answer. When the harness's
// timeout falls between the two, the harness runs the call and a BLOCK record
// claims an enforcement that did not happen: before #4785, every call the
// box's kill emulation stopped at 10 s or 30 s left exactly that record.
// Emitting the verdict before the record cannot help: the verdict is only
// delivered at the exit, after the record either way. So the record says when
// it was written: written within hookAnswerExitGuard of the timeout, its
// analysis_budget_exceeded note carries answered_after_harness_timeout=true
// and recorded_at, and the receipt no longer claims a BLOCK the harness may
// not have enforced. The decision, the verdict and the exit code are
// unchanged. A record written earlier is untouched.
//
// An evaluation's own record is checked too (#4818, Gary 2026-11-06). It
// claims the call before the budget fires, so it starts recording at least
// the margin and the record reserve before the timeout, but its redaction can
// outlast them: a large labelled command's union scrub, which
// withholdIfTooSlow skips when its estimate says so, and which the estimate
// can understate on text chosen against the redaction's prescans. A record
// that still ends up inside the guard gets its own late_answer note
// (analyzer.NoteLateAnswer), since its event has no analysis_budget_exceeded
// note to carry the mark: the decision is the evaluation's.
func (b *hookBudget) markLate(red logger.RedactedEvent, at time.Duration) logger.RedactedEvent {
	// A harness with no known timeout (timeout 0: only the test binary's
	// budget override arms one) has nothing to be late for.
	if b == nil || b.timeout <= 0 || at+hookAnswerExitGuard < b.timeout {
		return red
	}
	// "true" when the record starts at or past the timeout: the harness has
	// stopped waiting. "possible" inside the guard: the answer lands after
	// the timeout only when the rest of the write and the exit take longer
	// than what is left.
	late := "possible"
	if at >= b.timeout {
		late = "true"
	}
	notes := slices.Clone(red.Event().Notes)
	if !b.answeredByWatchdog() {
		notes = append(notes, logger.Note{
			Kind: analyzer.NoteLateAnswer,
			Detail: fmt.Sprintf("answered_after_harness_timeout=%s; recorded_at=%s; harness=%s; harness_timeout=%s; exit_guard=%s",
				late, at.Truncate(time.Millisecond), b.call.harness, b.timeout, hookAnswerExitGuard),
		})
		return red.WithNotes(notes)
	}
	for i, n := range notes {
		if n.Kind == analyzer.NoteAnalysisBudgetExceeded {
			notes[i].Detail = fmt.Sprintf("%s; answered_after_harness_timeout=%s; recorded_at=%s; exit_guard=%s",
				n.Detail, late, at.Truncate(time.Millisecond), hookAnswerExitGuard)
		}
	}
	return red.WithNotes(notes)
}

// uploadTimeout bounds the synchronous upload a record may still make before
// the verdict leaves the process: full, cut to the time left before the
// harness timeout, less hookAnswerExitGuard for the emit and the exit. That
// upload (AGENTSHIELD_AUDIT_UPLOAD=sync, or the fallback on an enrolled host
// whose audit queue cannot be written, #4782) runs after the record, so a
// full one could land the answer after the timeout. Then the harness runs
// the call while the receipt says BLOCK, and a record started before the
// guard carries no late mark (#4803's Codex pass: exit at 11.25 s on Codex's
// 10 s, with the server answering in 2.9 s). It applies to either claim's
// winner, since an evaluation that claims just inside the budget has the
// same tail. Gary, 2026-11-06: the BLOCK must land; on that degraded host
// the SaaS copy of the event may be cut short or lost, and the local line
// keeps it. Zero or less means skip the upload. A nil budget (any process
// but the hook, or a harness with no known timeout) keeps full.
func (b *hookBudget) uploadTimeout(full time.Duration) time.Duration {
	if b == nil {
		return full
	}
	if left := b.timeout - time.Since(hookProcessStart) - hookAnswerExitGuard; left < full {
		return left
	}
	return full
}

// answeredByWatchdog reports whether the watchdog holds the call's claim.
func (b *hookBudget) answeredByWatchdog() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.owner == budgetWatchdog
}

// redactForRecord is the one redaction of an event the hook is about to
// write (#4781): the audit.jsonl line (LogLinkedRedacted) and the SaaS
// queue's wire entry (sendRemoteAuditRedacted) are both built from what it
// returns. On an armed call it checks the clock twice: before the redaction,
// whether the evaluation's labelled record can be scrubbed in time
// (withholdIfTooSlow, #4818), and after it, the part of the record that grows
// with the command, whether the answer may be late (markLate), so what
// follows that check is the short part.
func redactForRecord(event *logger.AuditEvent) logger.RedactedEvent {
	if activeBudget == nil {
		return event.RedactOnce()
	}
	hookSlowPoint("before-redact")
	red := activeBudget.withholdIfTooSlow(event, time.Since(hookProcessStart)).RedactOnce()
	hookSlowPoint("before-record")
	return activeBudget.markLate(red, time.Since(hookProcessStart))
}

// budgetStage names the watchdog's failure at the fail-safe boundary.
const budgetStage = "analysis"

// publishLabels records the data-label set the evaluation loaded, so the
// watchdog's record of the call is scrubbed exactly as the evaluation's would
// have been (#4805). A nil budget (nothing armed) is a no-op.
func (b *hookBudget) publishLabels(l *recordLabels) {
	if b == nil {
		return
	}
	b.mu.Lock()
	b.labels = l
	b.mu.Unlock()
}

// budgetLabelReadLimit bounds how long the watchdog's answer waits on its
// own read of the data labels, which it needs only when the evaluation
// stopped before loading the policy (#4805). That read decodes the policy
// file and every shell pack whole, as the full load does: about 67 ms in a
// fresh process on an idle M-series Mac with the premium packs installed,
// about 130 ms with all its CPUs busy. Past the limit the record withholds
// the agent text instead: a late read must never make the BLOCK late. 100
// ms is a fifth of the half second the slow host's measured tail leaves
// inside hookBudgetMargin. The read is not started on the answer's tail: a
// shell call still without its labels at half the budget starts it then
// (prefetchLabels, #4814), so by the time the budget fires it has had half
// the budget to finish, and the limit bounds only what is left of it.
const budgetLabelReadLimit = 100 * time.Millisecond

// hookLabelReadLimit is the bound answerLabels applies: budgetLabelReadLimit,
// except in the internal/cli test binary, where a test that must see the
// watchdog's own read succeed raises it (pinTestHookBudget). The agentshield
// binary reads no environment variable for it.
var hookLabelReadLimit = budgetLabelReadLimit

// prefetchLabels runs at half the budget (#4814). An evaluation that has not
// published its labels by then is one whose policy load is slow, the only
// kind whose budget answer has to read them on its own, so it starts that
// read now instead of on the answer's tail, where a busy host ran it past
// budgetLabelReadLimit and the record withheld the command. It reads
// nothing once the evaluation has published its labels or claimed the call,
// or once the watchdog holds it (answerLabels then reads for itself).
// declaredLabels(nil) names the files config.Load would (PolicyLocation), so
// it reads what the answer's own read reads, without loading the config.
func (b *hookBudget) prefetchLabels() {
	b.mu.Lock()
	if b.labels != nil || b.owner != budgetUnclaimed {
		b.mu.Unlock()
		return
	}
	read := make(chan *recordLabels, 1)
	b.prefetched = read
	b.mu.Unlock()
	read <- readDeclaredLabels(nil, "prefetch")
}

// readDeclaredLabels is the watchdog's own read of the data labels, by the
// prefetch or by the answer itself.
func readDeclaredLabels(cfg *config.Config, by string) *recordLabels {
	if hookLabelReadSeen != nil {
		hookLabelReadSeen(by)
	}
	hookSlowPoint("read-labels")
	return declaredLabels(cfg)
}

// answerLabels is the data-label set of the watchdog's record: the
// evaluation's, when it published one, else the labels read on their own
// (the prefetch's read, or one started now) within budgetLabelReadLimit,
// else withheld.
func (b *hookBudget) answerLabels(cfg *config.Config) *recordLabels {
	b.mu.Lock()
	l, read := b.labels, b.prefetched
	b.mu.Unlock()
	if l != nil {
		return l
	}
	if read == nil {
		own := make(chan *recordLabels, 1)
		go func() { own <- readDeclaredLabels(cfg, "watchdog") }()
		read = own
	}
	limit := time.NewTimer(hookLabelReadLimit)
	defer limit.Stop()
	select {
	case l = <-read:
		return l
	case <-limit.C:
		return &recordLabels{withheld: fmt.Sprintf("data labels unread: the policy was not loaded when the budget answered, and reading its data_labels took longer than %s", hookLabelReadLimit)}
	}
}

// budgetScrubCostPerKiB is the time the budget's answer allows, per KiB of
// the command, for the one redaction of its record when the record is
// scrubbed of the data labels: the label spans and the secret spans masked
// together, then secret redaction once more (redact.RedactWithLabels, #4813;
// RedactOnce on the fail-safe event).
//
// Measured on an M-series Mac, per KiB of command, the worst of five kinds of
// text at 64 KiB to 1 MiB: prose, base64, dense label values, digit runs, and
// the analyzer corpus with a labelled secret every 40 commands, whose
// secret-shaped literals pass the redaction's prescans (the union's worst
// case). In brackets, main's scrub-then-redact on the same run (e210c480):
//
//	label set                         idle            8 CPU burners
//	none                              0.90 (0.90) ms  1.20 (1.09) ms
//	one regex (CUST-[0-9]{6})         2.52 (0.91) ms  3.19 (1.16) ms
//	eight (keywords, regexes, Luhn)   3.10 (1.29) ms  3.85 (2.31) ms   (1 MiB: 3.2 s, 3.9 s)
//	32 (eight plus 24 generated)      3.95 (1.94) ms  5.89 (2.39) ms
//	64 (eight plus 56 generated)      5.10 (2.88) ms  6.63 (3.75) ms
//
// 8 ms is about twice the busiest with up to eight labels. It still covers
// the busiest 64-label figure, by 1.2x rather than 2x: the cost grows with
// the number of labels, and how to bound that is not decided here (#4814
// follow-up 8). On the four kinds without secrets the union costs 1.0 to 1.5
// times main's. Text chosen against the prescans costs more than 8 ms: a
// label value then a fold-only rune (CUST-104233 then U+212A, repeated)
// turns off every case-insensitive prescan, and with one label measured 6.1
// to 6.9 ms idle and 8.3 to 9.2 ms under eight burners (#4813 Opus pass 1).
// The shortfall comes out of hookAnswerExitGuard: at the size this check
// withholds from when the budget fires (about 14 KiB), under 20 ms of its
// 1.4 s. On Windows (#4818, the #4785 box, end to end on Codex-shaped hook
// calls), the union added 0.1-1.1 s idle from 128 KiB to 1 MiB of that
// fold-rune text and 1.3-2.5 s at 256 KiB with all 8 logical CPUs busy,
// against main's order; the box ran this text faster than the M-series Mac
// (6.7-6.9 s against 12.0 s at 1 MiB idle), so 8 ms holds there too. A change
// that makes the scrub or the redaction slower raises this to its own
// measured cost.
const budgetScrubCostPerKiB = 8 * time.Millisecond

// scrubOrWithhold is the label set the budget's answer records with (Gary,
// 2026-11-06). Scrubbing a record grows with its command, and the budget's
// answer records after the budget has fired, in the margin and the record
// reserve, which were sized for redaction without a scrubber: at 1 MiB a
// labelled record took longer to scrub than that leaves, and the answer
// landed past the harness timeout, which then runs the call. So when the
// labels would scrub the record (l.scrub) and scrubbing size bytes, at
// budgetScrubCostPerKiB, would not finish before the harness timeout less
// hookAnswerExitGuard (elapsed is the time since process start), the agent
// text is withheld instead (agent_text_withheld, which costs the same at
// any size). The decision, rule, taxonomy, chain and identity are as
// before. A host with no labels, labels that are already withheld, and a
// command small enough to scrub in time are unchanged. An evaluation that
// claims the call makes the same check on its own record (withholdIfTooSlow,
// #4818).
func (b *hookBudget) scrubOrWithhold(l *recordLabels, size int, elapsed time.Duration) *recordLabels {
	if l == nil || l.scrub == nil {
		return l
	}
	if why, slow := b.scrubTooSlow(size, elapsed); slow {
		return &recordLabels{withheld: why}
	}
	return l
}

// scrubTooSlow reports whether scrubbing size bytes of agent text, at
// budgetScrubCostPerKiB, would not finish before the harness timeout less
// hookAnswerExitGuard, elapsed being the time since process start, and if
// so the agent_text_withheld detail that says so.
func (b *hookBudget) scrubTooSlow(size int, elapsed time.Duration) (string, bool) {
	if b.timeout <= 0 {
		return "", false // no known harness timeout: nothing to scrub in time for
	}
	need := time.Duration(size) * budgetScrubCostPerKiB / 1024
	left := b.timeout - elapsed - hookAnswerExitGuard
	if need <= left {
		return "", false
	}
	return fmt.Sprintf("agent text too large to scrub before the harness timeout: %d KiB would take about %s to scrub at %s per KiB, and %s was left before the %s exit guard",
		size>>10, need.Truncate(time.Millisecond), budgetScrubCostPerKiB, max(left, 0).Truncate(time.Millisecond), hookAnswerExitGuard), true
}

// withholdIfTooSlow is scrubOrWithhold for a record the evaluation writes
// (Gary, 2026-11-06, #4818). An evaluation that claims the call just inside
// the budget leaves its record the margin and the record reserve, which were
// sized for redaction without a scrubber, and the union redaction of a large
// labelled command takes longer than that: measured, a Codex call answered at
// 10.14-10.24 s on the #4785 box with every CPU busy (288 and 352 KiB) and at
// 11.96 s on an idle Mac (1 MiB), each a BLOCK for a call Codex had run. So an
// event that carries a scrubber, whose command would not scrub in the time
// left, is withheld instead: the command, args, MCP arguments and cwd. It
// keeps its own error and reasons (Withheld.KeepFailureText), which the
// scrubber still masks, since a rule's reason names arguments it matched and
// costs little. The decision, rules, taxonomy and chain are as before. A call
// the watchdog holds is left alone: its answer made this check already, with
// its own record shape. A nil budget, an event with no scrubber and a command
// small enough to scrub in time are unchanged.
func (b *hookBudget) withholdIfTooSlow(e *logger.AuditEvent, elapsed time.Duration) *logger.AuditEvent {
	if b == nil || !e.Scrubs() || b.answeredByWatchdog() {
		return e
	}
	why, slow := b.scrubTooSlow(len(e.Command), elapsed)
	if !slow {
		return e
	}
	w := e.WithAgentTextWithheld(logger.Withheld{Detail: why, KeepFailureText: true})
	return &w
}

// answerFailSafe is the watchdog's answer: the call's fail-safe reading,
// recorded and emitted as the evaluation would have recorded and emitted
// its own, then the process exits. It loads the config and opens the audit
// log itself; the evaluation's logger, if it opened one, has written nothing.
func (b *hookBudget) answerFailSafe() {
	c := b.call
	f := evalFailure{
		stage: budgetStage,
		err: fmt.Errorf("%s: no verdict within the hook's %s budget for %s, whose hook timeout is %s",
			analyzer.NoteAnalysisBudgetExceeded, b.budget, c.harness, b.timeout),
	}
	cfg, err := config.Load(policyPath, logPath, mode)
	if err == nil {
		f.cfg = cfg
	}

	cwd, cwdNotes := c.cwd()
	f.notes = append(append(append([]logger.Note(nil), cwdNotes...), c.notes...), b.budgetNote())

	if c.toolCall {
		failSafeToolCallReading(f, c.tool, c.rawToolInput, c.source, c.sessionID, cwd).answer()
		os.Exit(0)
	}

	// #4805: scrubbed with the evaluation's data labels, or withheld.
	f.labels = b.answerLabels(f.cfg)

	// The same writer an evaluation failure uses: the local line when a
	// logger opens (readShellShaped's "audit log init" failure writes none
	// either), and the SaaS queue.
	var auditLog *logger.AuditLogger
	if f.cfg != nil {
		if l, err := logger.New(f.cfg.LogPath); err == nil {
			auditLog, f.log = l, l
		}
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	// Gary, 2026-11-06: withheld instead of scrubbed when scrubbing would
	// land the answer past the harness timeout.
	f.labels = b.scrubOrWithhold(f.labels, len(c.command), time.Since(hookProcessStart))
	result, event, write := failSafeReading(f, c.command, cwd, c.source, c.sessionID)
	write(event)
	if auditLog != nil {
		_ = auditLog.Close()
	}
	c.emit(result)
	os.Exit(0)
}

// shellBudgetCall is the budgetCall of a command one shell handler
// evaluates and records shell-shaped (Cursor, Windsurf, Gemini CLI).
func shellBudgetCall(h route.Harness, tool, source, sessionID, cmdStr string, cwd func() (string, []logger.Note), emit func(*policy.EvalResult)) budgetCall {
	return budgetCall{harness: h, tool: tool, size: len(cmdStr), source: source, sessionID: sessionID, command: cmdStr, cwd: cwd, emit: emit}
}

// literalCwd is the evaluation directory of a handler that evaluates against
// the payload's cwd as given ("" for the process directory) with no notes.
func literalCwd(cwd string) func() (string, []logger.Note) {
	return func() (string, []logger.Note) { return cwd, nil }
}

// preToolUseBudgetCall is the budgetCall of a Claude-shaped PreToolUse call
// (Claude Code, Codex, both Copilot CLI dialects) about to be read by its
// row's lanes, and false when no lane will read anything.
//
// A call a shell lane reads (POSIX or PowerShell, alone or beside MCP policy)
// is recorded shell-shaped with the command text, as each shell lane records
// it, and gets the shell verdict; a call only MCP policy reads is recorded as
// its tool-call event and gets the MCP verdict. The note's tool says which
// tool a shell-shaped receipt came from, as lane_readings does.
func preToolUseBudgetCall(lanes []route.Lane, call route.ToolCall, input hookInput, rawToolInput json.RawMessage, source string) (budgetCall, bool) {
	c := budgetCall{
		harness:   call.Harness,
		tool:      call.Tool,
		source:    source,
		sessionID: sessionIDFor(input),
		cwd:       func() (string, []logger.Note) { return payloadEvalCwd(input.Cwd) },
	}
	shellLane := slices.Contains(lanes, route.POSIX) || slices.Contains(lanes, route.PowerShell)
	switch {
	case shellLane && !input.ToolInput.IsText && input.ToolInput.Command != "":
		cmdStr := input.ToolInput.Command
		c.command, c.size = cmdStr, len(cmdStr)
		c.emit = func(r *policy.EvalResult) { emitShellVerdict(source, cmdStr, r) }
	case slices.Contains(lanes, route.Structured):
		c.toolCall = true
		c.rawToolInput, c.size = rawToolInput, len(rawToolInput)
		if route.Gap(call) {
			c.notes = []logger.Note{routingGapNote(call)}
		}
	default:
		return budgetCall{}, false
	}
	return c, true
}
