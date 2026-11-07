package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/enterprise"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/policy/remediation"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// Lane combining in the hook (ADR-001 D4, D9; #4753).
//
// A routing row that names more than one lane is read by every lane, in row
// order. Each reading is evaluated WITHOUT being recorded (readCommand,
// readToolCall): building one writes no audit line and queues nothing for the
// SaaS. route.Combine then picks the reading whose record is the call's
// receipt, and only that one is finished: its event is written exactly as
// that lane writes it on a single-lane row (same source, the same command or
// tool_name shape, the same rules and taxonomy), plus the other readings'
// uncertainty notes (and, where the AUDIT tie rule moved the record to a
// reading that names a rule, the rule-less pick's notes, #4779) and one
// lane_readings note naming what every lane decided, and its verdict is the
// one the harness sees (exit code, stderr, Copilot's deny line). Every other
// reading is released unwritten. So a call leaves one receipt and one
// upload, whichever lane decided it.

// laneReading is one lane's evaluation of a call, held until the combiner
// has picked.
type laneReading interface {
	// Verdict is the reading in the combiner's shape (assembly's adapters).
	Verdict() route.Verdict
	// finish records the reading with the combined decision (the reading's
	// own, unless the AUDIT floor raised it) and extra notes, then writes its
	// verdict; it exits 2 on a BLOCK. It records before it writes the
	// verdict, because a BLOCK verdict exits.
	finish(c route.Combined, extra []logger.Note)
	// release drops the reading without recording it.
	release()
}

// shellLaneReading is the POSIX lane's reading of a Claude-shaped call.
type shellLaneReading struct {
	*commandReading
	lane   route.Lane
	source string
	cmdStr string
}

func (r *shellLaneReading) Verdict() route.Verdict {
	return shellVerdict(r.lane, r.result, r.event.Notes)
}

func (r *shellLaneReading) finish(c route.Combined, extra []logger.Note) {
	if string(r.result.Decision) != c.Decision || string(r.result.OriginalDecision) != c.OriginalDecision {
		r.result.Decision, r.result.OriginalDecision = policy.Decision(c.Decision), policy.Decision(c.OriginalDecision)
		r.event.Decision, r.event.OriginalDecision = c.Decision, c.OriginalDecision
	}
	r.record(extra)
	emitShellVerdict(r.source, r.cmdStr, r.result)
}

// psLaneReading is the PowerShell lane's reading of a Claude-shaped call. It
// is recorded exactly as a shell reading is (shell-shaped, the harness's
// shell source); only its verdict differs, because its uncertainty notes put
// the AUDIT floor under the call (ADR-001 D4).
type psLaneReading struct {
	shellLaneReading
}

func (r *psLaneReading) Verdict() route.Verdict {
	return factsLaneVerdict(r.lane, r.result, r.event.Notes)
}

func (r *toolCallReading) Verdict() route.Verdict {
	return toolCallVerdict(r.result, r.notes)
}

func (r *toolCallReading) finish(c route.Combined, extra []logger.Note) {
	r.result.Decision, r.result.OriginalDecision = policy.Decision(c.Decision), policy.Decision(c.OriginalDecision)
	r.record(extra)
	r.emit()
}

// release: an MCP reading holds nothing open; its logger is opened by record.
func (r *toolCallReading) release() {}

// shellVerdict adapts the POSIX lane's result with the notes its event
// carries (assembly.ShellVerdict). None is marked uncertain (D4).
func shellVerdict(lane route.Lane, r *policy.EvalResult, notes []logger.Note) route.Verdict {
	return assembly.ShellVerdict(lane, r, routeNotes(notes))
}

// toolCallVerdict adapts the Structured lane's result with the hook's notes
// on the call (assembly.ToolCallVerdict).
func toolCallVerdict(r mcp.MCPEvalResult, notes []logger.Note) route.Verdict {
	return assembly.ToolCallVerdict(r, routeNotes(notes))
}

func routeNotes(ns []logger.Note) []route.Note {
	if len(ns) == 0 {
		return nil
	}
	out := make([]route.Note, 0, len(ns))
	for _, n := range ns {
		out = append(out, route.Note{Kind: n.Kind, Rule: n.Rule, Detail: n.Detail})
	}
	return out
}

// combineLanes runs every lane of a multi-lane row on a Claude-shaped call
// and finishes the reading route.Combine keeps.
func combineLanes(lanes []route.Lane, call route.ToolCall, input hookInput, rawToolInput json.RawMessage, source string) error {
	sessionID := sessionIDFor(input)
	row, ok := assembly.ReadRow(call.Tool, lanes, func(l route.Lane) (laneReading, bool) {
		switch l {
		case route.Structured:
			var notes []logger.Note
			if route.Gap(call) {
				notes = append(notes, routingGapNote(call))
			}
			return readToolCall(input.ToolName, rawToolInput, source, sessionID, input.Cwd, notes), true
		case route.POSIX:
			// Nothing for a shell to read: no command, or a tool_input that
			// is a string. A shell-only row refuses a string input or passes
			// an empty command (handlePreToolUse); here another lane reads
			// and records the call, so the shell lane just has no verdict.
			if input.ToolInput.IsText || input.ToolInput.Command == "" {
				return nil, false
			}
			cmdStr := input.ToolInput.Command
			cwd, cwdNotes := payloadEvalCwd(input.Cwd)
			return &shellLaneReading{
				commandReading: readCommand(cmdStr, cwd, source, sessionID, cwdNotes),
				lane:           l, source: source, cmdStr: cmdStr,
			}, true
		case route.PowerShell:
			// Nothing to read, as for the POSIX lane. A row that holds only
			// shell lanes never gets here with a string tool_input
			// (handlePreToolUse refuses it).
			if input.ToolInput.IsText || input.ToolInput.Command == "" {
				return nil, false
			}
			cmdStr := input.ToolInput.Command
			cwd, cwdNotes := payloadEvalCwd(input.Cwd)
			return &psLaneReading{shellLaneReading{
				commandReading: readPowerShell(cmdStr, cwd, source, sessionID, cwdNotes),
				lane:           l, source: source, cmdStr: cmdStr,
			}}, true
		default:
			// A lane the hook cannot run is a lane failure (ADR-001 D9):
			// BLOCK under managed fail_closed, AUDIT otherwise. No row names
			// one (internal/route's table tests); this keeps a future row
			// from being silently ignored.
			cwd, cwdNotes := payloadEvalCwd(input.Cwd)
			result, event, write := failSafeReading(evalFailure{
				stage: "lane " + string(l),
				err:   fmt.Errorf("the hook has no implementation of the %s lane", l),
				notes: cwdNotes,
			}, input.ToolInput.Command, cwd, source, sessionID)
			return &shellLaneReading{
				commandReading: &commandReading{result: result, event: event, write: write},
				lane:           l, source: source, cmdStr: input.ToolInput.Command,
			}, true
		}
	})
	if !ok {
		return nil
	}
	for i, r := range row.Readings {
		if i != row.Combined.Winner {
			r.release()
		}
	}
	// The kept record carries the other readings' uncertainty notes (and,
	// after the AUDIT tie rule, the pick's notes), then lane_readings
	// (assembly.Row.Extra, #4779).
	row.Kept().finish(row.Combined, auditNotes(row.Extra()))
	return nil
}

// emitShellVerdict writes a Claude-shaped harness's verdict for a shell
// command: on a BLOCK, the rules, reasons and remediation on stderr,
// Copilot's deny line, and exit 2. ALLOW and AUDIT write nothing.
func emitShellVerdict(source, cmdStr string, evalResult *policy.EvalResult) {
	if evalResult.Decision != policy.DecisionBlock {
		return
	}
	fmt.Fprintf(os.Stderr, "🛡️ AgentShield BLOCKED this command\n")
	if len(evalResult.TriggeredRules) > 0 {
		fmt.Fprintf(os.Stderr, "   Rule: %s\n", strings.Join(evalResult.TriggeredRules, ", "))
	}
	for _, reason := range evalResult.Reasons {
		fmt.Fprintf(os.Stderr, "   Reason: %s\n", reason)
	}
	fmt.Fprint(os.Stderr, remediation.SuggestForShell(evalResult.TriggeredRules, cmdStr, enterprise.ManagedHost()))
	emitCopilotDeny(source, "this command", evalResult.TriggeredRules, evalResult.Reasons)
	os.Exit(2)
}
