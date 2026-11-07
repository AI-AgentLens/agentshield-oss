package cli

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/hookentry"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// The hook's decision budget (#4772). Every test below that runs the hook
// does so in a child process (runHookChild), because the watchdog answers
// by exiting the process: the exit code and stdout are the contract a
// harness sees.
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).

// Test seams for the decision budget. Only this test binary reads them
// (pinTestHookBudget, from TestMain), so they apply to it and to every child
// it re-execs. The agentshield binary has no such switches
// (TestHookBudgetSeams_ProductionBinaryIgnoresThem): one would let an agent
// turn the budget off, or make every call decide AUDIT.
const (
	// envTestHookBudget is every harness's budget (a Go duration), or "off"
	// to arm none.
	envTestHookBudget = "AGENTSHIELD_TEST_HOOK_BUDGET"
	// envTestHookSlow makes the evaluation sleep at named points:
	// "evaluate=10s" or "nested-posix=10s,evaluate=1s" (hookSlowPoint).
	envTestHookSlow = "AGENTSHIELD_TEST_HOOK_SLOW"
	// envTestHookRace, "1", holds each side's first claim until the other
	// side reaches its own, so both contend for the call at one instant.
	envTestHookRace = "AGENTSHIELD_TEST_HOOK_RACE"
	// envTestHookLabelLimit raises the watchdog's bound on its own read of
	// the data labels (a Go duration, hookLabelReadLimit), for a test that
	// must see that read succeed on a busy machine (#4805).
	envTestHookLabelLimit = "AGENTSHIELD_TEST_HOOK_LABEL_LIMIT"
	// envTestHookReadLog names a file each start of the watchdog's own read
	// of the data labels appends a line to: "prefetch" or "watchdog"
	// (hookLabelReadSeen, #4814).
	envTestHookReadLog = "AGENTSHIELD_TEST_HOOK_READ_LOG"
)

func pinTestHookBudget() {
	switch v := os.Getenv(envTestHookBudget); v {
	case "":
	case "off":
		hookBudgetOverride = -1
	default:
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			hookBudgetOverride = d
		}
	}
	if v := os.Getenv(envTestHookSlow); v != "" {
		hookSlowPoints = map[string]time.Duration{}
		for _, kv := range strings.Split(v, ",") {
			point, dur, _ := strings.Cut(kv, "=")
			if d, err := time.ParseDuration(dur); err == nil {
				hookSlowPoints[point] = d
			}
		}
	}
	if os.Getenv(envTestHookRace) == "1" {
		hookRaceGate = newHookRaceGate(10 * time.Second)
	}
	if d, err := time.ParseDuration(os.Getenv(envTestHookLabelLimit)); err == nil && d > 0 {
		hookLabelReadLimit = d
	}
	if path := os.Getenv(envTestHookReadLog); path != "" {
		hookLabelReadSeen = func(by string) {
			if f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				_, _ = f.WriteString(by + "\n")
				_ = f.Close()
			}
		}
	}
}

// newHookRaceGate is a two-party spin barrier: each caller spins until both
// have arrived (or timeout passes, so a test that never fires cannot hang),
// then spins a random few hundred nanoseconds more. Spinning rather than
// blocking keeps both goroutines running, so neither has to be woken by the
// other and the two reach the claim within a microsecond of each other; the
// random tail decides which is first. A blocking barrier let the side that
// released it win 80 of 80 runs, and a spin without the tail let the
// watchdog win about 95%.
func newHookRaceGate(timeout time.Duration) func(string) {
	var arrived atomic.Int32
	return func(string) {
		arrived.Add(1)
		deadline := time.Now().Add(timeout)
		for i := 0; arrived.Load() < 2; i++ {
			if i%4096 == 0 && time.Now().After(deadline) {
				return
			}
		}
		for i, n := 0, rand.IntN(2000); i < n; i++ {
			raceGateSink.Add(1)
		}
	}
}

// raceGateSink keeps the gate's random tail from being optimised away.
var raceGateSink atomic.Int64

// budgetEnv is a hook child's environment for a budget and slow points.
func budgetEnv(budget string, slow string) []string {
	env := []string{envTestHookBudget + "=" + budget}
	if slow != "" {
		env = append(env, envTestHookSlow+"="+slow)
	}
	return env
}

// budgetShellCase is one harness's shell call, with its verdict shapes.
type budgetShellCase struct {
	name    string
	harness route.Harness
	payload func(t *testing.T, cmd string) string
	env     []string
	source  string
	// exit code and stdout of an AUDIT and of a BLOCK, as the harness's own
	// handler writes them for an evaluated decision.
	auditExit, blockExit     int
	auditStdout, blockStdout verdictShape
}

func budgetShellCases() []budgetShellCase {
	claude := func(extra map[string]interface{}) func(t *testing.T, cmd string) string {
		return func(t *testing.T, cmd string) string {
			return claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), extra)
		}
	}
	return []budgetShellCase{
		{name: "claude-code", harness: route.ClaudeCode, payload: claude(nil), source: "claude-code-hook",
			auditExit: 0, blockExit: 2, auditStdout: verdictNone, blockStdout: verdictNone},
		{name: "codex", harness: route.Codex, payload: claude(map[string]interface{}{"turn_id": "turn-1"}), source: "codex-hook",
			auditExit: 0, blockExit: 2, auditStdout: verdictNone, blockStdout: verdictNone},
		{name: "copilot-cli compat", harness: route.CopilotCLI, payload: claude(nil), env: []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}, source: "copilot-cli-hook",
			auditExit: 0, blockExit: 2, auditStdout: verdictNone, blockStdout: verdictCopilotDeny},
		{name: "copilot-cli native", harness: route.CopilotCLINative, source: "copilot-cli-hook",
			payload: func(t *testing.T, cmd string) string {
				return copilotNativePayload(t, "budget", "bash", shellArgs(cmd))
			},
			auditExit: 0, blockExit: 2, auditStdout: verdictNone, blockStdout: verdictCopilotDeny},
		{name: "gemini-cli", harness: route.GeminiCLI, source: "gemini-cli-hook",
			payload: func(t *testing.T, cmd string) string {
				return routingJSON(t, map[string]interface{}{"hook_event_name": "BeforeTool", "session_id": "budget", "tool_name": "run_shell_command", "tool_input": routingCmd(cmd)})
			},
			auditExit: 0, blockExit: 0, auditStdout: verdictGeminiAllow, blockStdout: verdictGeminiDeny},
		{name: "cursor", harness: route.Cursor, source: "cursor-hook",
			payload: func(t *testing.T, cmd string) string {
				return routingJSON(t, map[string]interface{}{"hook_event_name": "beforeShellExecution", "conversation_id": "c1", "command": cmd})
			},
			auditExit: 0, blockExit: 0, auditStdout: verdictCursorAllow, blockStdout: verdictCursorDeny},
		{name: "windsurf", harness: route.Windsurf, source: "windsurf-hook",
			payload: func(t *testing.T, cmd string) string {
				return routingJSON(t, map[string]interface{}{"agent_action_name": "pre_run_command", "trajectory_id": "w1", "tool_info": map[string]interface{}{"command_line": cmd}})
			},
			auditExit: 0, blockExit: 2, auditStdout: verdictNone, blockStdout: verdictNone},
	}
}

// budgetNotes returns the analysis_budget_exceeded notes' details.
func budgetNotes(ns []logger.Note) []string {
	var out []string
	for _, n := range ns {
		if n.Kind == analyzer.NoteAnalysisBudgetExceeded {
			out = append(out, n.Detail)
		}
	}
	return out
}

// requireBudgetEvent checks the one event a budgeted call leaves: the
// fail-safe decision, its sentinel rule, flagged, the error, and one
// analysis_budget_exceeded note naming the budget, the harness and the tool.
func requireBudgetEvent(t *testing.T, e logger.AuditEvent, decision, rule, budget string, harness route.Harness, tool string) {
	t.Helper()
	if e.Decision != decision || len(e.TriggeredRules) != 1 || e.TriggeredRules[0] != rule || !e.Flagged {
		t.Errorf("event decision %s rules %v flagged %v; want %s [%s] flagged", e.Decision, e.TriggeredRules, e.Flagged, decision, rule)
	}
	if !strings.Contains(e.Error, analyzer.NoteAnalysisBudgetExceeded) {
		t.Errorf("event error %q; want the budget failure carried on the event", e.Error)
	}
	notes := budgetNotes(e.Notes)
	if len(notes) != 1 {
		t.Fatalf("notes %v; want exactly one %s note", noteKinds(e.Notes), analyzer.NoteAnalysisBudgetExceeded)
	}
	for _, want := range []string{"budget=" + budget, "harness=" + string(harness), "tool=" + tool} {
		if !strings.Contains(notes[0], want) {
			t.Errorf("note detail %q lacks %q", notes[0], want)
		}
	}
}

// TestHookBudget_PastTheBudgetDecidesAUDIT: on an unmanaged host, a call
// whose evaluation is still running when the budget runs out is decided AUDIT
// (agentshield-eval-error) with the note, and the harness gets exactly the
// AUDIT output its handler writes for an evaluated AUDIT. The command is one
// the analysis BLOCKs (TestHookBudget_FastPathUnchanged is the control), so
// the test also pins that past the budget the fail-safe's AUDIT is the
// decision, as Gary chose: those calls ran unevaluated before.
func TestHookBudget_PastTheBudgetDecidesAUDIT(t *testing.T) {
	destr := routingDestructive()
	for _, c := range budgetShellCases() {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			start := time.Now()
			code, stdout, stderr := runHookChild(t, home, c.payload(t, destr), append(c.env, budgetEnv("300ms", "evaluate=10s")...)...)
			if elapsed := time.Since(start); elapsed > 8*time.Second {
				t.Errorf("the call took %s: the budget did not answer before the evaluation finished", elapsed)
			}
			if code != c.auditExit {
				t.Errorf("exit %d, want %d (the harness's AUDIT). stderr:\n%s", code, c.auditExit, stderr)
			}
			checkVerdictShape(t, c.auditStdout, stdout)
			e := oneEvent(t, configDir)
			requireBudgetEvent(t, e, "AUDIT", evalErrorRuleID, "300ms", c.harness, toolOf(c))
			if e.Command != destr || e.Source != c.source {
				t.Errorf("event command %q source %q; want %q %q", e.Command, e.Source, destr, c.source)
			}
		})
	}
}

// toolOf is the tool or event name a shell case's note names.
func toolOf(c budgetShellCase) string {
	switch c.harness {
	case route.CopilotCLINative:
		return "bash"
	case route.GeminiCLI:
		return "run_shell_command"
	case route.Cursor:
		return cursorShellEvent
	case route.Windsurf:
		return "pre_run_command"
	}
	return "Bash"
}

// TestHookBudget_ManagedFailClosedBLOCKs: under managed fail_closed the same
// call is BLOCKed (enterprise-fail-closed), with the deny each harness's
// handler writes for an evaluated BLOCK: exit 2, Copilot's deny line, Cursor's
// and Gemini's deny JSON. Each deny carries the reason its harness reads: an
// exit 2 with no reason on stderr is a hook failure to Codex, after which the
// tool runs (codex-rs/hooks/src/events/pre_tool_use.rs), and Gemini shows the
// deny's reason.
func TestHookBudget_ManagedFailClosedBLOCKs(t *testing.T) {
	destr := routingDestructive()
	for _, c := range budgetShellCases() {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			code, stdout, stderr := runHookChild(t, home, c.payload(t, destr), append(c.env, budgetEnv("300ms", "evaluate=10s")...)...)
			if code != c.blockExit {
				t.Errorf("exit %d, want %d (the harness's deny). stderr:\n%s", code, c.blockExit, stderr)
			}
			checkVerdictShape(t, c.blockStdout, stdout)
			requireDenyReason(t, c, stdout, stderr)
			e := oneEvent(t, configDir)
			requireBudgetEvent(t, e, "BLOCK", failClosedRuleID, "300ms", c.harness, toolOf(c))
			if e.Mode != "managed" {
				t.Errorf("event mode %q, want managed", e.Mode)
			}
		})
	}
}

// requireDenyReason checks that a BLOCK's deny carries the fail-closed
// reason where its harness reads one: on stderr for the harnesses whose deny
// is exit 2 (Codex fails a reasonless exit 2 open), in the deny JSON for
// Gemini and Cursor.
func requireDenyReason(t *testing.T, c budgetShellCase, stdout, stderr string) {
	t.Helper()
	const reason = "blocking (fail_closed enabled)"
	switch c.harness {
	case route.GeminiCLI, route.Cursor:
		lines := jsonLines(stdout)
		if len(lines) != 1 {
			t.Fatalf("want one deny JSON on stdout, got %q", stdout)
		}
		var v map[string]interface{}
		_ = json.Unmarshal([]byte(lines[0]), &v)
		key := "reason"
		if c.harness == route.Cursor {
			key = "user_message"
		}
		if got, _ := v[key].(string); !strings.Contains(got, reason) {
			t.Errorf("deny JSON %s=%q lacks the reason %q", key, got, reason)
		}
	case route.Windsurf:
		if !strings.Contains(stderr, "BLOCKED by AgentShield") || !strings.Contains(stderr, reason) {
			t.Errorf("stderr lacks Windsurf's block message and reason:\n%s", stderr)
		}
	default: // Claude-shaped: Claude Code, Codex, both Copilot dialects
		if !strings.Contains(stderr, "AgentShield BLOCKED") || !strings.Contains(stderr, "Reason: AgentShield: "+budgetStage+" failed — "+reason) {
			t.Errorf("stderr lacks the block message and its Reason line:\n%s", stderr)
		}
	}
}

// budgetLaneCase is a call through a routing row that is not one shell lane.
type budgetLaneCase struct {
	name    string
	payload func(t *testing.T) string
	env     []string
	slow    string
	harness route.Harness
	tool    string
	// shell-shaped event (command set) or tool-call event (toolName set).
	command, toolName, source string
	// control: with the budget off, the slow point is reached and the call
	// takes at least this long.
	reached time.Duration
	// argKey/argValue: one argument a tool-call event must carry.
	argKey, argValue string
	// gap: the call is a routing gap (ADR-001 D5), whose routing_gap note the
	// budget's event must carry as the evaluation's would.
	gap bool
}

func budgetLaneCases() []budgetLaneCase {
	destr := routingDestructive()
	copilot := []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}
	readme := map[string]interface{}{"path": "/repo/README.md"}
	return []budgetLaneCase{
		// (claude-code, Monitor) → Structured, POSIX. The Structured lane
		// sleeps first; the record is shell-shaped, as the kept POSIX lane's.
		{name: "claude-code Monitor (structured+posix)", harness: route.ClaudeCode, tool: "Monitor", slow: "evaluate=10s",
			payload: func(t *testing.T) string { return claudeShaped(t, "PreToolUse", "Monitor", monitorInput(destr), nil) },
			command: destr, source: "claude-code-hook"},
		// (claude-code, PowerShell) → Structured, PowerShell. Only the
		// PowerShell lane's native-command bridge sleeps (nested-posix).
		{name: "claude-code PowerShell bridge (structured+powershell)", harness: route.ClaudeCode, tool: "PowerShell", slow: "nested-posix=10s",
			payload: func(t *testing.T) string {
				return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd("git status"), nil)
			},
			command: "git status", source: "claude-code-hook", reached: time.Second},
		// (copilot-cli, Bash, windows) → POSIX, PowerShell: the POSIX lane
		// reads first and fast; the PowerShell lane's bridge sleeps.
		{name: "copilot compat Bash on windows (posix+powershell)", harness: route.CopilotCLI, tool: "Bash", slow: "nested-posix=10s",
			env:     append(append([]string(nil), copilot...), onWindows...),
			payload: func(t *testing.T) string { return claudeShaped(t, "PreToolUse", "Bash", routingCmd("git status"), nil) },
			command: "git status", source: "copilot-cli-hook", reached: time.Second},
		// (copilot-cli-native, powershell) → POSIX, PowerShell.
		{name: "copilot native powershell (posix+powershell)", harness: route.CopilotCLINative, tool: "powershell", slow: "nested-posix=10s",
			payload: func(t *testing.T) string {
				return copilotNativePayload(t, "budget", "powershell", shellArgs("git status"))
			},
			command: "git status", source: "copilot-cli-hook", reached: time.Second},
		// An MCP tool call through the hook: Structured alone, a tool-call
		// event.
		{name: "claude-code MCP tool (structured)", harness: route.ClaudeCode, tool: "mcp__fs__read_file", slow: "evaluate=10s",
			payload:  func(t *testing.T) string { return claudeShaped(t, "PreToolUse", "mcp__fs__read_file", readme, nil) },
			toolName: "mcp__fs__read_file", source: "claude-code-mcp-hook", argKey: "path", argValue: "/repo/README.md"},
		{name: "codex MCP tool (structured)", harness: route.Codex, tool: "mcp__fs__read_file", slow: "evaluate=10s",
			payload: func(t *testing.T) string {
				return claudeShaped(t, "PreToolUse", "mcp__fs__read_file", readme, map[string]interface{}{"turn_id": "turn-1"})
			},
			toolName: "mcp__fs__read_file", source: "codex-mcp-hook", argKey: "path", argValue: "/repo/README.md"},
		{name: "copilot compat Read (structured)", harness: route.CopilotCLI, tool: "Read", slow: "evaluate=10s", env: copilot,
			payload:  func(t *testing.T) string { return claudeShaped(t, "PreToolUse", "Read", readme, nil) },
			toolName: "Read", source: "copilot-cli-mcp-hook", argKey: "path", argValue: "/repo/README.md"},
		// A routing gap: Codex's PowerShell carries command text no row
		// names, so MCP policy alone reads it and the event carries a
		// routing_gap note. The budget's event must keep it.
		{name: "codex PowerShell (routing gap, structured)", harness: route.Codex, tool: "PowerShell", slow: "evaluate=10s",
			payload: func(t *testing.T) string {
				return claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(psBenign), map[string]interface{}{"turn_id": "turn-1"})
			},
			toolName: "PowerShell", source: "codex-mcp-hook", argKey: "command", argValue: psBenign, gap: true},
	}
}

// TestHookBudget_EveryLaneReachesTheBudget: the budget covers the whole call
// on every row shape the hook reads: two lanes combined (Monitor), the
// PowerShell lane with its native-command bridge on each of its three rows,
// MCP tool calls, and a routing gap, whose note the budget's event keeps. On an unmanaged host each decides AUDIT with the note
// and exit 0; under managed fail_closed each BLOCKs with exit 2 (and
// Copilot's deny line). A shell lane's call is recorded shell-shaped, an MCP
// call as its tool-call event. For the bridge rows a control first shows the
// slow point is really inside that call's evaluation.
func TestHookBudget_EveryLaneReachesTheBudget(t *testing.T) {
	for _, c := range budgetLaneCases() {
		t.Run(c.name, func(t *testing.T) {
			if c.reached > 0 {
				home, _ := newFailSafeHome(t, false, failSafePolicyGood)
				slow := strings.Replace(c.slow, "10s", c.reached.String(), 1)
				start := time.Now()
				runHookChild(t, home, c.payload(t), append(c.env, budgetEnv("off", slow)...)...)
				if elapsed := time.Since(start); elapsed < c.reached {
					t.Fatalf("control: with the budget off the call took %s, less than its %s slow point: the row never reaches it", elapsed, c.reached)
				}
			}
			for _, managed := range []bool{false, true} {
				home, configDir := newFailSafeHome(t, managed, failSafePolicyGood)
				code, stdout, stderr := runHookChild(t, home, c.payload(t), append(c.env, budgetEnv("300ms", c.slow)...)...)
				decision, rule, exit := "AUDIT", evalErrorRuleID, 0
				if managed {
					decision, rule, exit = "BLOCK", failClosedRuleID, 2
				}
				if code != exit {
					t.Errorf("managed=%v: exit %d, want %d. stderr:\n%s", managed, code, exit, stderr)
				}
				switch {
				case managed && strings.HasPrefix(c.source, "copilot-cli"):
					checkVerdictShape(t, verdictCopilotDeny, stdout)
				default:
					checkVerdictShape(t, verdictNone, stdout)
				}
				e := oneEvent(t, configDir)
				requireBudgetEvent(t, e, decision, rule, "300ms", c.harness, c.tool)
				if e.Command != c.command || e.ToolName != c.toolName || e.Source != c.source {
					t.Errorf("managed=%v: event command %q tool %q source %q; want %q %q %q", managed, e.Command, e.ToolName, e.Source, c.command, c.toolName, c.source)
				}
				if c.argKey != "" && e.MCPArguments[c.argKey] != c.argValue {
					t.Errorf("managed=%v: tool-call event arguments %v; want the call's own (%s=%q)", managed, e.MCPArguments, c.argKey, c.argValue)
				}
				wantGap := 0
				if c.gap {
					wantGap = 1
				}
				if n := countKind(e.Notes, analyzer.NoteRoutingGap); n != wantGap {
					t.Errorf("managed=%v: %d %s notes on the budget's event (kinds %v), want %d", managed, n, analyzer.NoteRoutingGap, noteKinds(e.Notes), wantGap)
				}
			}
		})
	}
}

// TestHookBudget_EveryWriterClaimsFirst: each of the hook's write paths
// claims the call as its first statement, and hookCommand claims on return.
// The race test kills a missing claim on the two record paths every armed
// call goes through today; the other two (failSafeDecision, hookCommand's
// return) are reached after arming on no current path, so no behavioural
// test can tell them from their absence. They guard the next path that arms
// and then answers some other way; this keeps them from being dropped.
func TestHookBudget_EveryWriterClaimsFirst(t *testing.T) {
	isClaim := func(n ast.Node) bool {
		es, ok := n.(*ast.ExprStmt)
		if !ok {
			return false
		}
		call, ok := es.X.(*ast.CallExpr)
		if !ok {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "claimForEvaluation" {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "activeBudget"
	}
	receiver := func(fd *ast.FuncDecl) string {
		if fd.Recv == nil || len(fd.Recv.List) == 0 {
			return ""
		}
		if st, ok := fd.Recv.List[0].Type.(*ast.StarExpr); ok {
			if id, ok := st.X.(*ast.Ident); ok {
				return id.Name
			}
		}
		return ""
	}
	firstStatementClaims := map[string]bool{
		"commandReading.record":  false,
		"toolCallReading.record": false,
		"failSafeDecision":       false,
	}
	deferredClaim := false
	for _, file := range []string{"hook.go", "fail_safe.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			name := fd.Name.Name
			if r := receiver(fd); r != "" {
				name = r + "." + name
			}
			if _, want := firstStatementClaims[name]; want {
				firstStatementClaims[name] = len(fd.Body.List) > 0 && isClaim(fd.Body.List[0])
			}
			if name == "hookCommand" {
				for _, st := range fd.Body.List {
					ds, ok := st.(*ast.DeferStmt)
					if !ok {
						continue
					}
					if lit, ok := ds.Call.Fun.(*ast.FuncLit); ok && len(lit.Body.List) == 1 && isClaim(lit.Body.List[0]) {
						deferredClaim = true
					}
				}
			}
		}
	}
	for name, ok := range firstStatementClaims {
		if !ok {
			t.Errorf("%s does not claim the call as its first statement", name)
		}
	}
	if !deferredClaim {
		t.Error("hookCommand does not claim the call on return (defer activeBudget.claimForEvaluation)")
	}
}

// normalizedAuditLine is the audit line with the fields that differ between
// two runs of the same call (time and the hash chain) removed.
func normalizedAuditLine(t *testing.T, configDir string) map[string]interface{} {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(readFailSafeAuditLog(t, configDir)), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one audit line, got %d", len(lines))
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if k == "timestamp" || strings.Contains(k, "hash") {
			delete(m, k)
		}
	}
	return m
}

// TestHookBudget_FastPathUnchanged: a call decided within its budget is
// byte-for-byte the call main answers: the same exit code, stdout, stderr
// and audit line (time and chain aside), with no note, whether the budget
// is armed for an hour, armed at the production table's value, or not armed
// at all. The rows cover every handler and row shape, BLOCK and not.
func TestHookBudget_FastPathUnchanged(t *testing.T) {
	destr := routingDestructive()
	payloads := []struct {
		name    string
		payload string
		env     []string
	}{
		{"claude-code Bash destructive", claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), nil), nil},
		{"claude-code Bash benign", claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingBenign), nil), nil},
		{"codex Bash destructive", claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), map[string]interface{}{"turn_id": "t"}), nil},
		{"copilot compat Bash destructive", claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), nil), []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}},
		{"copilot native bash destructive", copilotNativePayload(t, "s", "bash", shellArgs(destr)), nil},
		{"gemini destructive", routingJSON(t, map[string]interface{}{"hook_event_name": "BeforeTool", "tool_name": "run_shell_command", "tool_input": routingCmd(destr)}), nil},
		{"cursor destructive", routingJSON(t, map[string]interface{}{"hook_event_name": "beforeShellExecution", "command": destr}), nil},
		{"windsurf destructive", routingJSON(t, map[string]interface{}{"agent_action_name": "pre_run_command", "tool_info": map[string]interface{}{"command_line": destr}}), nil},
		{"claude-code Monitor destructive", claudeShaped(t, "PreToolUse", "Monitor", monitorInput(destr), nil), nil},
		{"claude-code PowerShell key read", claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(psKeyRead()), nil), nil},
		{"claude-code MCP credential read", claudeShaped(t, "PreToolUse", "mcp__fs__read_file", map[string]interface{}{"path": catchAllCredentialPath()}, nil), nil},
	}
	type run struct {
		code           int
		stdout, stderr string
		line           map[string]interface{}
	}
	for _, p := range payloads {
		t.Run(p.name, func(t *testing.T) {
			var runs []run
			for _, budget := range []string{"off", "1h", ""} {
				home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				env := append([]string(nil), p.env...)
				if budget != "" {
					env = append(env, envTestHookBudget+"="+budget)
				}
				code, stdout, stderr := runHookChild(t, home, p.payload, env...)
				r := run{code, stdout, stderr, normalizedAuditLine(t, configDir)}
				if raw := readFailSafeAuditLog(t, configDir); strings.Contains(raw, analyzer.NoteAnalysisBudgetExceeded) {
					t.Fatalf("budget %q: a call decided in time carries the budget note:\n%s", budget, raw)
				}
				runs = append(runs, r)
			}
			off := runs[0]
			for i, label := range []string{"armed for 1h", "armed at the table's budget"} {
				r := runs[i+1]
				if r.code != off.code || r.stdout != off.stdout || r.stderr != off.stderr {
					t.Errorf("%s: exit/stdout/stderr = %d %q %q; not armed: %d %q %q", label, r.code, r.stdout, r.stderr, off.code, off.stdout, off.stderr)
				}
				a, _ := json.Marshal(r.line)
				b, _ := json.Marshal(off.line)
				if string(a) != string(b) {
					t.Errorf("%s: audit line differs\n armed:     %s\n not armed: %s", label, a, b)
				}
			}
		})
	}
}

// TestHookBudget_ClaimRaceLeavesOneAnswer forces the race: the budget fires
// at once and waits at a barrier until the evaluation reaches its claim, so
// both claim at one instant. Whichever wins, the call leaves exactly one
// audit line and one verdict, and they agree: the evaluation's decision with
// its own verdict (Cursor's deny JSON; Copilot's deny line and exit 2; an MCP
// AUDIT), or the budget's AUDIT with the allow. Both outcomes must be seen,
// or the barrier did not make the two contend. The shell and tool-call rows
// each kill the mutant that drops their record's claim (a call that exits 2
// cannot: the process ends before the watchdog writes).
func TestHookBudget_ClaimRaceLeavesOneAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the hook dozens of times")
	}
	destr := routingDestructive()
	cases := []struct {
		name    string
		payload string
		env     []string
		// the evaluation's decision and verdict, and the budget's AUDIT verdict
		evalDecision            string
		evalExit, auditExit     int
		evalStdout, auditStdout verdictShape
	}{
		// A shell BLOCK that returns (Cursor answers on stdout, exit 0).
		{"cursor shell BLOCK", routingJSON(t, map[string]interface{}{"hook_event_name": "beforeShellExecution", "command": destr}), nil,
			"BLOCK", 0, 0, verdictCursorDeny, verdictCursorAllow},
		// A shell BLOCK that exits 2.
		{"copilot compat shell BLOCK", claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), nil), []string{"AGENTSHIELD_AGENT_ID=copilot-cli"},
			"BLOCK", 2, 0, verdictCopilotDeny, verdictNone},
		// A tool call MCP policy decides AUDIT: the tool-call record's claim.
		{"claude-code MCP AUDIT", claudeShaped(t, "PreToolUse", "mcp__fs__read_file", map[string]interface{}{"path": "/repo/README.md"}, nil), nil,
			"AUDIT", 0, 0, verdictNone, verdictNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			won := map[string]int{}
			for i := 0; i < 80 && (i < 16 || len(won) < 2); i++ {
				home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
				code, stdout, stderr := runHookChild(t, home, c.payload, append(c.env, envTestHookBudget+"=1ns", envTestHookRace+"=1")...)
				events := loggedEvents(t, configDir)
				if len(events) != 1 {
					t.Fatalf("run %d: %d audit lines, want exactly one. stderr:\n%s", i, len(events), stderr)
				}
				if n := len(jsonLines(stdout)); n > 1 {
					t.Fatalf("run %d: %d verdicts on stdout, want at most one:\n%s", i, n, stdout)
				}
				e := events[0]
				if len(budgetNotes(e.Notes)) == 1 {
					won["budget"]++
					if e.Decision != "AUDIT" || code != c.auditExit {
						t.Fatalf("run %d: the budget's event %s with exit %d; want AUDIT, exit %d", i, e.Decision, code, c.auditExit)
					}
					checkVerdictShape(t, c.auditStdout, stdout)
				} else {
					won["evaluation"]++
					if e.Decision != c.evalDecision || code != c.evalExit {
						t.Fatalf("run %d: the evaluation's event %s with exit %d; want %s, exit %d", i, e.Decision, code, c.evalDecision, c.evalExit)
					}
					checkVerdictShape(t, c.evalStdout, stdout)
				}
			}
			t.Logf("winners: %v", won)
			if len(won) < 2 {
				t.Errorf("only one side ever won (%v): the barrier did not make the claims contend", won)
			}
		})
	}
}

// TestHookBudget_ClaimIsExclusive drives the claim protocol in-process,
// under -race in CI's race job: a watchdog firing and an evaluation claiming
// at the same instant, thousands of times. Exactly one side answers each
// time: the watchdog answers and the evaluation parks, or the evaluation
// proceeds and the watchdog writes nothing.
func TestHookBudget_ClaimIsExclusive(t *testing.T) {
	var watchdogWon, evaluationWon int
	for i := 0; i < 5000; i++ {
		var answered, parked atomic.Int32
		b := &hookBudget{
			answer: func() { answered.Add(1) },
			park:   func() { parked.Add(1) },
			timer:  time.NewTimer(time.Hour),
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); <-start; b.fire() }()
		go func() { defer wg.Done(); <-start; b.claimForEvaluation(); b.claimForEvaluation() }()
		close(start)
		wg.Wait()
		switch {
		case answered.Load() == 1 && parked.Load() == 2:
			watchdogWon++
		case answered.Load() == 0 && parked.Load() == 0:
			evaluationWon++
		default:
			t.Fatalf("iteration %d: watchdog answered %d times, evaluation parked %d times; want exactly one side answering", i, answered.Load(), parked.Load())
		}
	}
	t.Logf("watchdog won %d, evaluation won %d", watchdogWon, evaluationWon)
	// A nil budget (nothing armed) never parks.
	var none *hookBudget
	none.claimForEvaluation()
}

// TestHookBudget_GenuinelySlowCommandDecidesWithinBudget is the end-to-end
// test: the hook entry point in its own process, a throwaway HOME, no
// artificial delay, and a command that is genuinely slow to analyse (four
// brace groups, so every regex rescans each expanded whole-command form). A
// control first shows the analysis takes more than twice the budget; with the
// budget armed the call is answered at the budget, AUDIT with the note.
func TestHookBudget_GenuinelySlowCommandDecidesWithinBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("analyses a slow command")
	}
	cmd := slowBraceCommand(16 << 10)
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), nil)
	const budget = 500 * time.Millisecond

	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	start := time.Now()
	runHookChild(t, home, payload, envTestHookBudget+"=off")
	if took := time.Since(start); took < 2*budget {
		t.Fatalf("control: the analysis took %s, not more than twice the %s budget; the command is not slow enough to test with", took, budget)
	}

	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	start = time.Now()
	code, stdout, stderr := runHookChild(t, home, payload, envTestHookBudget+"="+budget.String())
	took := time.Since(start)
	if code != 0 || strings.TrimSpace(stdout) != "" {
		t.Errorf("exit %d stdout %q; want Claude Code's AUDIT (exit 0, nothing on stdout). stderr:\n%s", code, stdout, stderr)
	}
	requireBudgetEvent(t, oneEvent(t, configDir), "AUDIT", evalErrorRuleID, budget.String(), route.ClaudeCode, "Bash")
	if took > budget+3*time.Second {
		t.Errorf("the call took %s; the budget is %s", took, budget)
	}
}

// slowBraceCommand is a benign command of about n bytes with four brace
// groups: ExpandBraces makes up to 64 full-length forms of it (#4772).
func slowBraceCommand(n int) string {
	head := "echo x{a,b,c,d} y{a,b,c,d} z{a,b,c,d} w{a,b,c,d} "
	var b strings.Builder
	b.WriteString(head)
	for b.Len() < n {
		b.WriteString("word ")
	}
	return b.String()
}

// buildAgentshield builds the real agentshield binary into a temp dir.
func buildAgentshield(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "agentshield")
	build := exec.Command("go", "build", "-o", bin, "github.com/AI-AgentLens/agentshield/cmd/agentshield")
	build.Env = withoutEnv(os.Environ(), "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// runAgentshield runs the real binary's hook with a throwaway HOME, no
// AGENTSHIELD_* variables but env, and the payload on stdin.
func runAgentshield(t *testing.T, bin, home, payload string, env ...string) (int, string, string, time.Duration) {
	t.Helper()
	cmd := exec.Command(bin, "hook")
	cmd.Env = append(withoutEnv(os.Environ(), "AGENTSHIELD_", "HOME="), append(env, "HOME="+home)...)
	cmd.Stdin = strings.NewReader(payload)
	var out, errb strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	err := cmd.Run()
	took := time.Since(start)
	if err == nil {
		return 0, out.String(), errb.String(), took
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), out.String(), errb.String(), took
	}
	t.Fatalf("running agentshield: %v", err)
	return -1, "", "", 0
}

// TestHookBudgetSeams_ProductionBinaryIgnoresThem builds the real binary and
// gives it every seam: a 1 ns budget, a 3 s sleep in the evaluation, and the
// race barrier. The binary must ignore all three, deciding by analysis (the
// BLOCK, exit 2, no note) and quickly, while this test binary, which honours
// them, decides AUDIT with the note: the positive control that shows the
// variables would change the answer if read.
func TestHookBudgetSeams_ProductionBinaryIgnoresThem(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agentshield binary")
	}
	bin := buildAgentshield(t)
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingDestructive()), nil)
	seams := []string{envTestHookBudget + "=1ns", envTestHookSlow + "=evaluate=3s", envTestHookRace + "=1", envTestHookLabelLimit + "=1h"}

	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	if code, _, stderr := runHookChild(t, home, payload, seams[:2]...); code != 0 {
		t.Fatalf("control: the test binary with the seams exits %d, want 0 (the budget's AUDIT). stderr:\n%s", code, stderr)
	}
	if n := budgetNotes(oneEvent(t, configDir).Notes); len(n) != 1 {
		t.Fatalf("control: the test binary's event carries no budget note")
	}

	home, configDir = newFailSafeHome(t, false, failSafePolicyGood)
	code, _, stderr, took := runAgentshield(t, bin, home, payload, seams...)
	if code != 2 {
		t.Errorf("the agentshield binary with the seams exits %d, want 2 (the analysis's BLOCK). stderr:\n%s", code, stderr)
	}
	e := oneEvent(t, configDir)
	if e.Decision != "BLOCK" || len(budgetNotes(e.Notes)) != 0 {
		t.Errorf("the agentshield binary decided %s with notes %v; want the analysis's BLOCK and no budget note", e.Decision, noteKinds(e.Notes))
	}
	if took >= 3*time.Second {
		t.Errorf("the agentshield binary took %s: it slept at the test-only slow point", took)
	}
}

// TestHookBudgetSeams_OnlyTestsSetThem: no file of the agentshield build
// names a seam variable or assigns a seam, and only TestMain's helper sets
// them in tests. The binary test above proves the behaviour for this build;
// this keeps a later edit from adding a reader on another path.
func TestHookBudgetSeams_OnlyTestsSetThem(t *testing.T) {
	seamVars := map[string]bool{"hookBudgetOverride": true, "hookSlowPoints": true, "hookRaceGate": true, "activeBudget": true, "hookLabelReadLimit": true, "hookLabelReadSeen": true}
	envNames := []string{envTestHookBudget, envTestHookSlow, envTestHookRace, "AGENTSHIELD_TEST_HOOK"}
	root := filepath.Join("..", "..")
	assigns := map[string]int{}
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
		for _, name := range envNames {
			if strings.Contains(string(src), name) {
				t.Errorf("%s names %s: only the internal/cli test binary may read it", path, name)
			}
		}
		if filepath.Base(filepath.Dir(path)) != "cli" {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && seamVars[id.Name] {
						assigns[filepath.Base(path)+":"+id.Name]++
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The one production assignment: armHookBudget sets activeBudget.
	if len(assigns) != 1 || assigns["hook_budget.go:activeBudget"] != 1 {
		t.Errorf("assignments to the budget's seams outside tests: %v; want only armHookBudget's activeBudget", assigns)
	}
	// Control: the scan sees the declarations' file.
	if src, err := os.ReadFile("hook_budget.go"); err != nil || !strings.Contains(string(src), "hookBudgetOverride time.Duration") {
		t.Fatalf("control: hook_budget.go does not declare the seams where this test expects (%v)", err)
	}
}

// TestHookBudget_CountsFromProcessStart: the budget is measured from the
// hook process's start, not from the moment a handler arms it, so time spent
// before arming (reading and parsing the payload, here a 1 s sleep at the
// before-arm point) counts against it. With a 1.5 s budget the call is
// answered at about 1.5 s; timed from arming it would be about 2.5 s.
func TestHookBudget_CountsFromProcessStart(t *testing.T) {
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingDestructive()), nil)
	start := time.Now()
	code, _, stderr := runHookChild(t, home, payload, budgetEnv("1500ms", "before-arm=1s,evaluate=10s")...)
	took := time.Since(start)
	if code != 0 {
		t.Fatalf("exit %d, want 0 (the budget's AUDIT). stderr:\n%s", code, stderr)
	}
	requireBudgetEvent(t, oneEvent(t, configDir), "AUDIT", evalErrorRuleID, "1.5s", route.ClaudeCode, "Bash")
	if took < time.Second {
		t.Fatalf("answered after %s, before the 1 s pre-arm sleep ended: the before-arm point was not reached", took)
	}
	if took > 2100*time.Millisecond {
		t.Errorf("answered after %s: the 1.5 s budget was timed from arming (≈2.5 s), not from process start", took)
	}
}

// writeFakeCredentials writes credentials.json into home's config directory
// naming a server nothing listens on, so nothing can leave this host.
func writeFakeCredentials(t *testing.T, configDir, token string) {
	t.Helper()
	creds := fmt.Sprintf(`{"server": "http://127.0.0.1:9", "token": %q, "user": {"id": 1, "email": "x@example.invalid"}}`, token)
	if err := os.WriteFile(filepath.Join(configDir, "credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHookBudget_EnrolledHostReservesItsUploadTail: armHookBudget takes the
// enrolled reserve exactly when sendRemoteAudit would upload the call's
// event (remoteAuditCredentials: credentials with a token), so the reserve
// and the tail it holds cannot disagree (#4772 Opus pass 1). Arms in-process
// and stops the timer at once; the harness's budget (Claude Code, ~10 min)
// is far beyond the test anyway.
func TestHookBudget_EnrolledHostReservesItsUploadTail(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	const size = 1 << 20
	arm := func() time.Duration {
		t.Helper()
		if activeBudget != nil {
			t.Fatal("a budget is already armed in this test process")
		}
		hookBudgetEnabled = true
		defer func() { hookBudgetEnabled = false }()
		armHookBudget(budgetCall{harness: route.ClaudeCode, tool: "Bash", size: size, command: "x",
			cwd: literalCwd(""), emit: func(*policy.EvalResult) {}})
		b := activeBudget
		activeBudget = nil
		if b == nil {
			t.Fatal("nothing armed")
		}
		b.claimForEvaluation() // stops the timer; this test answers nothing
		return b.budget
	}
	want := func(enrolled bool) time.Duration {
		b, _, _ := hookBudgetFor(route.ClaudeCode, size, enrolled)
		return b
	}

	if got := arm(); got != want(false) {
		t.Errorf("no credentials: armed %s, want the local-only budget %s", got, want(false))
	}
	writeFakeCredentials(t, configDir, "")
	if remoteAuditCredentials() != nil {
		t.Fatal("control: credentials with no token count as enrolled; sendRemoteAudit uploads nothing for them")
	}
	if got := arm(); got != want(false) {
		t.Errorf("credentials without a token: armed %s, want the local-only budget %s (no upload follows)", got, want(false))
	}
	writeFakeCredentials(t, configDir, "fake-token")
	if remoteAuditCredentials() == nil {
		t.Fatal("control: credentials with a token do not count as enrolled")
	}
	if got := arm(); got != want(true) {
		t.Errorf("credentials with a token: armed %s, want the enrolled budget %s", got, want(true))
	}
	if want(true) >= want(false) {
		t.Errorf("enrolled budget %s is not below the local-only %s", want(true), want(false))
	}
}

// TestHookTimeouts_MatchWhatSetupWrites ties the budget table to the hook
// entries `agentshield setup` writes, so a timeout changed in setup fails
// here instead of leaving a budget past the harness's timeout. Claude Code's
// entry carries no timeout (Claude Code's default applies), and the two
// harnesses with no known timeout have no budget.
func TestHookTimeouts_MatchWhatSetupWrites(t *testing.T) {
	entryTimeout := func(m map[string]interface{}, key string) float64 {
		t.Helper()
		b, _ := json.Marshal(m)
		var v struct {
			Hooks []map[string]interface{} `json:"hooks"`
		}
		_ = json.Unmarshal(b, &v)
		if len(v.Hooks) != 1 {
			t.Fatalf("entry %s: want one hook object", b)
		}
		f, ok := v.Hooks[0][key].(float64)
		if !ok {
			t.Fatalf("entry %s has no numeric %q", b, key)
		}
		return f
	}
	codex := entryTimeout(agentshieldCodexHookGroup("^Bash$", "AgentShield"), "timeout")
	if got := hookTimeouts[route.Codex].timeout; got != time.Duration(codex)*time.Second {
		t.Errorf("Codex: table %s, setup writes %v s", got, codex)
	}
	gemini := entryTimeout(agentshieldGeminiHookEntry(), "timeout")
	if got := hookTimeouts[route.GeminiCLI].timeout; got != time.Duration(gemini)*time.Millisecond {
		t.Errorf("Gemini CLI: table %s, setup writes %v ms", got, gemini)
	}
	b, _ := json.Marshal(copilotHookFile("/bin/agentshield"))
	var cf struct {
		Hooks map[string][]map[string]interface{} `json:"hooks"`
	}
	_ = json.Unmarshal(b, &cf)
	copilot, _ := cf.Hooks["PreToolUse"][0]["timeoutSec"].(float64)
	for _, h := range []route.Harness{route.CopilotCLI, route.CopilotCLINative} {
		if got := hookTimeouts[h].timeout; got != time.Duration(copilot)*time.Second {
			t.Errorf("%s: table %s, setup writes %v s", h, got, copilot)
		}
	}
	for _, exec := range []bool{false, true} {
		h, form := claudeCodeHook("/opt/homebrew/bin/agentshield", exec)
		if _, ok := h["timeout"]; ok {
			t.Errorf("Claude Code %v entry writes a timeout %v: the table assumes Claude Code's default", form, h["timeout"])
		}
		if form != hookentry.Exec && form != hookentry.Shell {
			t.Errorf("unexpected form %v", form)
		}
	}
	if got := hookTimeouts[route.ClaudeCode].timeout; got != claudeCodeHookTimeout {
		t.Errorf("Claude Code: table %s, want claudeCodeHookTimeout %s", got, claudeCodeHookTimeout)
	}

	for _, h := range []route.Harness{route.ClaudeCode, route.Codex, route.CopilotCLI, route.CopilotCLINative, route.GeminiCLI} {
		for _, enrolled := range []bool{false, true} {
			budget, timeout, ok := hookBudgetFor(h, 0, enrolled)
			if !ok || budget != timeout-hookBudgetMargin || budget <= 0 {
				t.Errorf("%s enrolled=%v: budget %s of timeout %s (ok=%v); want the timeout less %s", h, enrolled, budget, timeout, ok, hookBudgetMargin)
			}
			// The record reserve: a MiB of text keeps back 1024 reserves,
			// the enrolled host's own when it uploads.
			reserve := hookRecordReservePerKiB
			if enrolled {
				reserve = hookRecordReserveEnrolledPerKiB
			}
			if big, _, _ := hookBudgetFor(h, 1<<20, enrolled); big != max(budget-1024*reserve, 0).Truncate(time.Millisecond) {
				t.Errorf("%s enrolled=%v: budget for 1 MiB %s; want %s less 1024 x %s", h, enrolled, big, budget, reserve)
			}
			// Text whose record alone outlasts the timeout is answered at once.
			if huge, _, ok := hookBudgetFor(h, 1<<30, enrolled); huge != 0 || !ok {
				t.Errorf("%s enrolled=%v: budget for 1 GiB %s (ok=%v); want 0", h, enrolled, huge, ok)
			}
		}
	}
	// The enrolled reserve holds the upload's tail on top of the local one.
	if hookRecordReserveEnrolledPerKiB <= hookRecordReservePerKiB {
		t.Errorf("enrolled reserve %s is not above the local-only %s", hookRecordReserveEnrolledPerKiB, hookRecordReservePerKiB)
	}
	for _, h := range []route.Harness{route.Cursor, route.Windsurf} {
		if _, _, ok := hookBudgetFor(h, 0, false); ok {
			t.Errorf("%s has a budget; its hook timeout is not known", h)
		}
	}
}

// hookPerfBudgetEnv is the nightly perf workflow's switch (make test-perf),
// the same one TestPipelinePerfBudget reads: wall-clock bounds that measure
// the runner as much as the code run only there, on a quiet machine (#3505).
const hookPerfBudgetEnv = "SHIELD_PERF_BUDGET"

// hookCITailTolerance is how long after its budget the production binary may
// answer on CI before the test calls it a failure. The watchdog's tail on
// this test's 160 KiB command measured 0.15 s idle and 0.27 s with 8 cores
// busy on an M-series Mac, and about 1 s inside a test binary during the
// Opus pass on #4772; Shield's CI is one shared 4-core runner (#3505). Four
// seconds is four times the worst of those, and the analysis takes about 30 s,
// so an answer inside it can only be the budget's.
const hookCITailTolerance = 4 * time.Second

// TestHookBudget_ProductionBinaryAtCodexTimeout runs the real binary as
// Codex runs it, with no seam at all, on a command whose analysis takes about
// 30 s, three times Codex's 10 s hook timeout. Always: the budget answers,
// AUDIT with the note naming the table's budget, no earlier than that budget
// and within hookCITailTolerance of it. With SHIELD_PERF_BUDGET (the nightly
// perf workflow, make test-perf): strictly before the 10 s timeout, the
// guarantee itself, which on a saturated shared runner measures the runner.
// On main this call outlasts the harness and runs unevaluated and unrecorded.
func TestHookBudget_ProductionBinaryAtCodexTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the agentshield binary and waits out a real budget")
	}
	cmd := slowBraceCommand(160 << 10)
	// The throwaway HOME has no credentials: the not-enrolled reserve.
	budget, timeout, ok := hookBudgetFor(route.Codex, len(cmd), false)
	if !ok {
		t.Fatal("Codex has no budget")
	}
	bin := buildAgentshield(t)
	payload := claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), map[string]interface{}{"turn_id": "turn-1"})
	home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	code, stdout, stderr, took := runAgentshield(t, bin, home, payload)
	if code != 0 || strings.TrimSpace(stdout) != "" {
		t.Errorf("exit %d stdout %q; want Codex's AUDIT (exit 0, nothing on stdout). stderr:\n%s", code, stdout, stderr)
	}
	requireBudgetEvent(t, oneEvent(t, configDir), "AUDIT", evalErrorRuleID, budget.String(), route.Codex, "Bash")
	t.Logf("answered after %s (budget %s, timeout %s)", took, budget, timeout)
	if took < budget {
		t.Errorf("answered after %s, before its %s budget: the watchdog did not wait for the budget", took, budget)
	}
	if took > budget+hookCITailTolerance {
		t.Errorf("answered after %s, more than %s past its %s budget", took, hookCITailTolerance, budget)
	}
	if os.Getenv(hookPerfBudgetEnv) != "" && took >= timeout {
		t.Errorf("answered after %s, at or past Codex's %s hook timeout", took, timeout)
	}
}
