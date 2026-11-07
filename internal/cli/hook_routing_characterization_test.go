package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// Routing characterization (ADR-001 step 0, #4245). These tests pin which
// evaluator every hook payload reaches TODAY, so that moving the routing
// decision out of hookCommand/handlePreToolUse into one table (step 1) fails
// loudly if any call changes path. They assert only what a harness or an
// auditor can observe: the exit code, the verdict JSON on stdout, and the
// audit event (its source, whether it records a command or a tool name, its
// decision and a rule id).
//
// Each row's input is chosen so that its decision DIFFERS by path. Measured on
// main (40a7ad71) with the embedded packs:
//
//   - shell pipeline: `rm -rf /` BLOCKs (ts-block-rm-root); `ls -la` ALLOWs
//     (ts-allow-readonly).
//   - MCP policy, {"command": …}: tools named PowerShell, Powershell, Read,
//     Edit, mcp__srv__tool … decide AUDIT; tools whose name reads as code
//     execution (bash, Shell, run_shell_command) BLOCK on the tool name
//     alone (mcp-sem-block-code-execute), whatever the command.
//   - passthrough: no audit event at all.
//
// So a shell row uses `ls -la` when its tool name would BLOCK under MCP
// policy and `rm -rf /` when it would AUDIT there, and each MCP row uses the
// input the shell pipeline would decide differently. The mutation evidence is
// in the PR that added this file.
//
// A row that starts failing after a PACK change (not a routing change) needs a
// new discriminating input, not a new expectation: the path is the contract.
//
// Claude Code's Monitor rows (#4753) are the first multi-lane row: Structured
// (MCP policy, which alone read them on main, AUDIT on every input here) then
// POSIX. Each one pins which lane's record the call keeps. The destructive
// row is the raise (main: AUDIT; now the shell pipeline's BLOCK and a
// shell-shaped event); the read-only row is where a swap to POSIX would have
// lowered the decision (ts-allow-readonly ALLOWs it); the poll-loop row is a
// tie, where the decisions agree and the RECORD is what differs by lane: the
// earlier lane, MCP policy, keeps it. The lane_readings note on each is pinned
// by TestLaneCombining_* (hook_lanes_test.go).
//
// Attack strings are assembled at runtime: the hook reads test sources as
// commands (dogfooding).

// raisedRows are the rows whose decision differs from main's because a row
// gained a lane (ADR-001 D4), with main's decision. Every other row decides
// as main did. A raised row must rank above main's decision: adding a lane
// may only raise (TestHookRoutingCharacterization checks it).
var raisedRows = map[string]string{
	"claude-code Monitor destructive": "AUDIT", // #4753: MCP policy alone read it on main
	// ADR-001 step 4: MCP policy alone read Claude Code's PowerShell tool on
	// main. The PowerShell lane joins it.
	"claude-code PowerShell key read": "AUDIT",
	// Copilot on Windows, and its native powershell tool: POSIX alone on
	// main, where bash reads `type` as its builtin and ts-allow-readonly
	// ALLOWs a key read. The PowerShell lane reads it as Get-Content.
	"copilot compat Bash on windows key read": "ALLOW",
	"copilot native powershell key read":      "ALLOW",
	// The cost side of the same rows: the PowerShell lane has no ALLOW rule,
	// so its default (AUDIT) outranks the bash pipeline's ALLOW on every
	// benign call those rows read.
	"copilot compat Bash on windows benign": "ALLOW",
}

// routePath is the evaluator a payload reached.
type routePath string

const (
	pathShell routePath = "shell pipeline" // event.command set, source "<agent>-hook"
	pathMCP   routePath = "MCP policy"     // event.tool_name set, source "<agent>-mcp-hook"
	pathPass  routePath = "passthrough"    // no evaluation, no event
)

// psKeyRead is a PowerShell read of an SSH private key, spelled as Windows
// agents write it. bash reads `type` as its builtin and the rest as text.
func psKeyRead() string { return "type $env:USERPROFILE" + `\.ssh\id_` + "rsa" }

// psBenign is a real Claude Code PowerShell call (#4245's Windows capture).
const psBenign = "Get-ChildItem -Name"

// sshKeyReadNode is the taxonomy node a bash read of an SSH private key gets
// from the protected-path check.
const sshKeyReadNode = "credential-exposure/private-key-access/ssh-private-key-read"

// verdictShape is the JSON a dialect writes to stdout, if any.
type verdictShape string

const (
	verdictNone        verdictShape = "none"
	verdictCopilotDeny verdictShape = "copilot deny"
	verdictCursorAllow verdictShape = "cursor allow"
	verdictCursorDeny  verdictShape = "cursor deny"
	verdictGeminiAllow verdictShape = "gemini allow"
	verdictGeminiDeny  verdictShape = "gemini deny"
)

type routingCase struct {
	name    string
	payload string
	env     []string

	path     routePath
	source   string // audit source (shell and MCP rows)
	command  string // shell rows: the event's command
	tool     string // MCP rows: the event's tool_name
	decision string // the event's decision
	rule     string // a rule id the event must carry; "" asserts none in particular
	taxonomy string // a taxonomy node the event must carry; "" asserts none in particular
	argKey   string // MCP rows: an argument key the event must carry
	exit     int
	stdout   verdictShape
	// readings is the lane_readings note's detail on a multi-lane row's
	// event; "" asserts the event carries no such note.
	readings string
}

type routingEvent struct {
	Command        string                 `json:"command"`
	ToolName       string                 `json:"tool_name"`
	Source         string                 `json:"source"`
	Decision       string                 `json:"decision"`
	TriggeredRules []string               `json:"triggered_rules"`
	Taxonomy       []string               `json:"taxonomy"`
	Arguments      map[string]interface{} `json:"arguments"`
	Notes          []struct {
		Kind   string `json:"kind"`
		Detail string `json:"detail"`
	} `json:"notes"`
}

func routingDestructive() string { return "rm -rf " + "/" }

const routingBenign = "ls -la"

func routingJSON(t *testing.T, m map[string]interface{}) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// claudeShaped is a PreToolUse payload as Claude Code sends it; extra keys
// (turn_id for Codex) are merged in.
func claudeShaped(t *testing.T, event, tool string, input interface{}, extra map[string]interface{}) string {
	m := map[string]interface{}{
		"hook_event_name": event,
		"session_id":      "route-char",
		"tool_name":       tool,
		"tool_input":      input,
	}
	for k, v := range extra {
		m[k] = v
	}
	return routingJSON(t, m)
}

func routingCmd(c string) map[string]interface{} { return map[string]interface{}{"command": c} }

// monitorInput is Claude Code's Monitor tool_input, as the audit log records
// it on every Monitor call (#4753).
func monitorInput(c string) map[string]interface{} {
	return map[string]interface{}{"command": c, "description": "wait for the build", "timeout_ms": 600000}
}

// routingPollLoop is the shape real Monitor commands take: the shell pipeline
// and MCP policy both decide AUDIT on it.
const routingPollLoop = "until test -f build/done; do sleep 5; done"

func routingCases(t *testing.T) []routingCase {
	destr := routingDestructive()
	codex := map[string]interface{}{"turn_id": "turn-1"}
	copilotEnv := []string{"AGENTSHIELD_AGENT_ID=copilot-cli"}
	copilotOnWindows := append(slices.Clone(copilotEnv), onWindows...)
	copilotOnDarwin := append(slices.Clone(copilotEnv), envTestHostOS+"=darwin")
	keyRead := psKeyRead()
	readme := map[string]interface{}{"file_path": "/repo/README.md"}
	gemini := func(tool string, input interface{}) string {
		return routingJSON(t, map[string]interface{}{"hook_event_name": "BeforeTool", "session_id": "route-char", "tool_name": tool, "tool_input": input})
	}
	cursorEvent := func(cmd string) string {
		return routingJSON(t, map[string]interface{}{"hook_event_name": "beforeShellExecution", "conversation_id": "c1", "command": cmd, "cwd": "/repo"})
	}
	cursorLegacy := func(cmd string) string {
		return routingJSON(t, map[string]interface{}{"command": cmd, "cwd": "/repo"})
	}
	windsurf := func(action, cmd string) string {
		return routingJSON(t, map[string]interface{}{"agent_action_name": action, "trajectory_id": "w1", "tool_info": map[string]interface{}{"command_line": cmd, "cwd": "/repo"}})
	}

	return []routingCase{
		// ---- Claude Code: PreToolUse --------------------------------------
		{name: "claude-code Bash benign", payload: claudeShaped(t, "PreToolUse", "Bash", routingCmd(routingBenign), nil),
			path: pathShell, source: "claude-code-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictNone},
		{name: "claude-code Bash destructive", payload: claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), nil),
			path: pathShell, source: "claude-code-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone},
		// Claude Code's Windows shell tool (ADR-001 step 4): Structured, then
		// the PowerShell lane. On main MCP policy alone read it and decided
		// AUDIT on every input here. The key read is the PowerShell lane's
		// raise (with the node the bash spelling gets); the destructive row
		// stays main's AUDIT (no POSIX lane here, Kai 2026-11-03: it added 5
		// false BLOCKs in 471 benign inputs), and the benign row is a tie,
		// where MCP policy keeps main's record.
		{name: "claude-code PowerShell destructive", payload: claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(destr), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "PowerShell", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone,
			readings: "tool=PowerShell; structured=AUDIT; powershell=AUDIT; kept=structured"},
		{name: "claude-code PowerShell key read", payload: claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(keyRead), nil),
			path: pathShell, source: "claude-code-hook", command: keyRead, decision: "BLOCK", rule: "protected-path", taxonomy: sshKeyReadNode, exit: 2, stdout: verdictNone,
			readings: "tool=PowerShell; structured=AUDIT; powershell=BLOCK(protected-path); kept=powershell"},
		{name: "claude-code PowerShell benign", payload: claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(psBenign), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "PowerShell", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone,
			readings: "tool=PowerShell; structured=AUDIT; powershell=AUDIT; kept=structured"},
		{name: "claude-code PowerShell string tool_input", payload: claudeShaped(t, "PreToolUse", "PowerShell", keyRead, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "PowerShell", decision: "AUDIT", argKey: "input", exit: 0, stdout: verdictNone,
			readings: "tool=PowerShell; structured=AUDIT; powershell=none; kept=structured"},
		// The row is Claude Code's: Codex's PowerShell is still MCP policy
		// alone, a routing gap.
		{name: "codex PowerShell key read", payload: claudeShaped(t, "PreToolUse", "PowerShell", routingCmd(keyRead), codex),
			path: pathMCP, source: "codex-mcp-hook", tool: "PowerShell", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone},
		// The shell match is exact: a lower-case "bash" is a tool call.
		// Claude Code's Monitor tool: Structured then POSIX (#4753).
		{name: "claude-code Monitor destructive", payload: claudeShaped(t, "PreToolUse", "Monitor", monitorInput(destr), nil),
			path: pathShell, source: "claude-code-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone,
			readings: "tool=Monitor; structured=AUDIT; posix=BLOCK(block-rm-root); kept=posix"},
		{name: "claude-code Monitor benign read-only", payload: claudeShaped(t, "PreToolUse", "Monitor", monitorInput(routingBenign), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Monitor", decision: "AUDIT", argKey: "timeout_ms", exit: 0, stdout: verdictNone,
			readings: "tool=Monitor; structured=AUDIT; posix=ALLOW(allow-safe-readonly); kept=structured"},
		{name: "claude-code Monitor poll loop (tie)", payload: claudeShaped(t, "PreToolUse", "Monitor", monitorInput(routingPollLoop), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Monitor", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone,
			readings: "tool=Monitor; structured=AUDIT; posix=AUDIT; kept=structured"},
		// Nothing for the shell lane to read: MCP policy reads and records
		// the call alone, as on main.
		{name: "claude-code Monitor empty command", payload: claudeShaped(t, "PreToolUse", "Monitor", monitorInput(""), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Monitor", decision: "AUDIT", argKey: "description", exit: 0, stdout: verdictNone,
			readings: "tool=Monitor; structured=AUDIT; posix=none; kept=structured"},
		{name: "claude-code Monitor string tool_input", payload: claudeShaped(t, "PreToolUse", "Monitor", routingDestructive(), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Monitor", decision: "AUDIT", argKey: "input", exit: 0, stdout: verdictNone,
			readings: "tool=Monitor; structured=AUDIT; posix=none; kept=structured"},
		// The row is Claude Code's: Codex's Monitor is still MCP policy alone.
		{name: "codex Monitor destructive", payload: claudeShaped(t, "PreToolUse", "Monitor", monitorInput(destr), codex),
			path: pathMCP, source: "codex-mcp-hook", tool: "Monitor", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone},
		{name: "claude-code bash (lower case) benign", payload: claudeShaped(t, "PreToolUse", "bash", routingCmd(routingBenign), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "bash", decision: "BLOCK", rule: "mcp-sem-block-code-execute", argKey: "command", exit: 2, stdout: verdictNone},
		// A string tool_input on a tool no row sends to the shell reaches MCP
		// policy as a patch, and the name alone BLOCKs. hookCommand's refusal
		// of a string shell input must route with the Claude-shaped harness:
		// routed as Copilot's native format, lower-case bash is a shell tool,
		// and the call would take the fail-safe AUDIT instead (#4754 review,
		// mutant H2).
		{name: "claude-code bash (lower case) string tool_input", payload: claudeShaped(t, "PreToolUse", "bash", capturedPatch, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "bash", decision: "BLOCK", rule: "mcp-sem-block-code-execute", argKey: "patch", exit: 2, stdout: verdictNone},
		// Gemini's shell tool name is a shell only in Gemini's own dialect.
		{name: "claude-code run_shell_command benign", payload: claudeShaped(t, "PreToolUse", "run_shell_command", routingCmd(routingBenign), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "run_shell_command", decision: "BLOCK", rule: "mcp-sem-block-code-execute", argKey: "command", exit: 2, stdout: verdictNone},
		{name: "claude-code Read", payload: claudeShaped(t, "PreToolUse", "Read", readme, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Read", decision: "AUDIT", argKey: "file_path", exit: 0, stdout: verdictNone},
		{name: "claude-code Write", payload: claudeShaped(t, "PreToolUse", "Write", map[string]interface{}{"file_path": "/repo/notes.txt", "content": "hello"}, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Write", decision: "AUDIT", argKey: "content", exit: 0, stdout: verdictNone},
		{name: "claude-code Edit", payload: claudeShaped(t, "PreToolUse", "Edit", map[string]interface{}{"file_path": "/repo/notes.txt", "old_string": "a", "new_string": "b"}, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Edit", decision: "AUDIT", argKey: "new_string", exit: 0, stdout: verdictNone},
		// An MCP server's tool whose argument happens to be named command.
		{name: "claude-code mcp__srv__tool with a command argument", payload: claudeShaped(t, "PreToolUse", "mcp__srv__tool", routingCmd(destr), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "mcp__srv__tool", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone},
		// A string tool_input (apply_patch) reaches MCP policy under "patch";
		// the shell path would refuse a string input.
		{name: "claude-code apply_patch string tool_input", payload: claudeShaped(t, "PreToolUse", "apply_patch", capturedPatch, nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "apply_patch", decision: "AUDIT", argKey: "patch", exit: 0, stdout: verdictNone},
		// A tool with no special meaning whose input carries a command: MCP
		// policy, on the tool name (ADR-001 D5 adds a routing_gap note here).
		{name: "claude-code unknown tool carrying a command", payload: claudeShaped(t, "PreToolUse", "Shell", routingCmd(routingBenign), nil),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "Shell", decision: "BLOCK", rule: "mcp-sem-block-code-execute", argKey: "command", exit: 2, stdout: verdictNone},
		{name: "claude-code Bash empty command", payload: claudeShaped(t, "PreToolUse", "Bash", routingCmd(""), nil),
			path: pathPass, exit: 0, stdout: verdictNone},
		// Any event name other than BeforeTool and Cursor's shell event takes
		// the Claude-shaped path; the event name itself is not checked.
		{name: "claude-shaped PostToolUse Bash destructive", payload: claudeShaped(t, "PostToolUse", "Bash", routingCmd(destr), nil),
			path: pathShell, source: "claude-code-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone},
		{name: "claude-shaped event with no tool name", payload: routingJSON(t, map[string]interface{}{"hook_event_name": "beforeReadFile", "file_path": "/repo/README.md"}),
			path: pathMCP, source: "claude-code-mcp-hook", tool: "", decision: "AUDIT", exit: 0, stdout: verdictNone},
		// Cursor's shell event name with a tool_name is Claude-shaped.
		{name: "beforeShellExecution with a tool_name", payload: claudeShaped(t, "beforeShellExecution", "Bash", routingCmd(destr), nil),
			path: pathShell, source: "claude-code-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone},

		// ---- Codex CLI: the Claude shape plus turn_id ----------------------
		{name: "codex Bash destructive", payload: claudeShaped(t, "PreToolUse", "Bash", routingCmd(destr), codex),
			path: pathShell, source: "codex-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone},
		{name: "codex apply_patch string tool_input", payload: claudeShaped(t, "PreToolUse", "apply_patch", capturedPatch, codex),
			path: pathMCP, source: "codex-mcp-hook", tool: "apply_patch", decision: "AUDIT", argKey: "patch", exit: 0, stdout: verdictNone},

		// ---- Copilot CLI, Claude-compatible format (setup's default) -------
		{name: "copilot compat Bash destructive", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(destr)), env: copilotEnv,
			path: pathShell, source: "copilot-cli-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictCopilotDeny},
		{name: "copilot compat Bash benign", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(routingBenign)), env: copilotEnv,
			path: pathShell, source: "copilot-cli-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictNone},
		// On Windows Copilot sends its powershell tool as Bash too, so the
		// row reads POSIX then PowerShell (ADR-001 D1). Elsewhere it is POSIX
		// alone, as on main: the host OS is pinned both ways.
		{name: "copilot compat Bash on windows key read", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(keyRead)), env: copilotOnWindows,
			path: pathShell, source: "copilot-cli-hook", command: keyRead, decision: "BLOCK", rule: "protected-path", taxonomy: sshKeyReadNode, exit: 2, stdout: verdictCopilotDeny,
			readings: "tool=Bash; posix=ALLOW(ts-allow-readonly); powershell=BLOCK(protected-path); kept=powershell"},
		{name: "copilot compat Bash on darwin key read", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(keyRead)), env: copilotOnDarwin,
			path: pathShell, source: "copilot-cli-hook", command: keyRead, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictNone},
		{name: "copilot compat Bash on windows destructive", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(destr)), env: copilotOnWindows,
			path: pathShell, source: "copilot-cli-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictCopilotDeny,
			readings: "tool=Bash; posix=BLOCK(block-rm-root); powershell=AUDIT; kept=posix"},
		{name: "copilot compat Bash on windows benign", payload: copilotCompatPayload(t, "route-char", "Bash", shellArgs(routingBenign)), env: copilotOnWindows,
			path: pathShell, source: "copilot-cli-hook", command: routingBenign, decision: "AUDIT", exit: 0, stdout: verdictNone,
			readings: "tool=Bash; posix=ALLOW(allow-safe-readonly); powershell=AUDIT; kept=powershell"},
		// The native rename does not apply to the compatible format.
		{name: "copilot compat bash (lower case) benign", payload: copilotCompatPayload(t, "route-char", "bash", shellArgs(routingBenign)), env: copilotEnv,
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "bash", decision: "BLOCK", rule: "mcp-sem-block-code-execute", argKey: "command", exit: 2, stdout: verdictCopilotDeny},
		{name: "copilot compat Read", payload: copilotCompatPayload(t, "route-char", "Read", map[string]interface{}{"path": "/repo/README.md"}), env: copilotEnv,
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "Read", decision: "AUDIT", argKey: "path", exit: 0, stdout: verdictNone},
		{name: "copilot compat Edit with patch text", payload: copilotCompatPayload(t, "route-char", "Edit", capturedPatch), env: copilotEnv,
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "Edit", decision: "AUDIT", argKey: "patch", exit: 0, stdout: verdictNone},

		// ---- Copilot CLI, native format: bash and powershell become Bash ----
		{name: "copilot native bash benign", payload: copilotNativePayload(t, "route-char", "bash", shellArgs(routingBenign)),
			path: pathShell, source: "copilot-cli-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictNone},
		{name: "copilot native powershell destructive", payload: copilotNativePayload(t, "route-char", "powershell", shellArgs(destr)),
			path: pathShell, source: "copilot-cli-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictCopilotDeny,
			readings: "tool=powershell; posix=BLOCK(block-rm-root); powershell=AUDIT; kept=posix"},
		{name: "copilot native powershell key read", payload: copilotNativePayload(t, "route-char", "powershell", shellArgs(keyRead)),
			path: pathShell, source: "copilot-cli-hook", command: keyRead, decision: "BLOCK", rule: "protected-path", taxonomy: sshKeyReadNode, exit: 2, stdout: verdictCopilotDeny,
			readings: "tool=powershell; posix=ALLOW(ts-allow-readonly); powershell=BLOCK(protected-path); kept=powershell"},
		// The rename is exact: any other spelling stays a tool call.
		{name: "copilot native Powershell (not a runtime name) destructive", payload: copilotNativePayload(t, "route-char", "Powershell", shellArgs(destr)),
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "Powershell", decision: "AUDIT", argKey: "command", exit: 0, stdout: verdictNone},
		// The rename targets "Bash", so a native call already named Bash is a
		// shell call too.
		{name: "copilot native Bash benign", payload: copilotNativePayload(t, "route-char", "Bash", shellArgs(routingBenign)),
			path: pathShell, source: "copilot-cli-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictNone},
		{name: "copilot native view", payload: copilotNativePayload(t, "route-char", "view", map[string]interface{}{"path": "/repo/README.md"}),
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "view", decision: "AUDIT", argKey: "path", exit: 0, stdout: verdictNone},
		{name: "copilot native apply_patch string toolArgs", payload: copilotNativePayload(t, "route-char", "apply_patch", capturedPatch),
			path: pathMCP, source: "copilot-cli-mcp-hook", tool: "apply_patch", decision: "AUDIT", argKey: "patch", exit: 0, stdout: verdictNone},
		{name: "copilot native bash empty command", payload: copilotNativePayload(t, "route-char", "bash", shellArgs("")),
			path: pathPass, exit: 0, stdout: verdictNone},

		// ---- Gemini CLI: BeforeTool, only run_shell_command is evaluated ---
		{name: "gemini run_shell_command destructive", payload: gemini("run_shell_command", routingCmd(destr)),
			path: pathShell, source: "gemini-cli-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 0, stdout: verdictGeminiDeny},
		{name: "gemini run_shell_command benign", payload: gemini("run_shell_command", routingCmd(routingBenign)),
			path: pathShell, source: "gemini-cli-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictGeminiAllow},
		{name: "gemini run_shell_command empty command", payload: gemini("run_shell_command", routingCmd("")),
			path: pathPass, exit: 0, stdout: verdictGeminiAllow},
		{name: "gemini non-shell tool", payload: gemini("read_file", map[string]interface{}{"absolute_path": "/repo/README.md"}),
			path: pathPass, exit: 0, stdout: verdictGeminiAllow},
		// Claude's shell tool name means nothing in Gemini's dialect.
		{name: "gemini Bash destructive", payload: gemini("Bash", routingCmd(destr)),
			path: pathPass, exit: 0, stdout: verdictGeminiAllow},

		// ---- Cursor: beforeShellExecution, documented and legacy shapes ----
		{name: "cursor beforeShellExecution destructive", payload: cursorEvent(destr),
			path: pathShell, source: "cursor-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 0, stdout: verdictCursorDeny},
		{name: "cursor beforeShellExecution empty command", payload: cursorEvent(""),
			path: pathPass, exit: 0, stdout: verdictCursorAllow},
		{name: "cursor legacy destructive", payload: cursorLegacy(destr),
			path: pathShell, source: "cursor-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 0, stdout: verdictCursorDeny},
		{name: "cursor legacy benign", payload: cursorLegacy(routingBenign),
			path: pathShell, source: "cursor-hook", command: routingBenign, decision: "ALLOW", rule: "ts-allow-readonly", exit: 0, stdout: verdictCursorAllow},
		// An empty legacy command matches no dialect at all: no verdict.
		{name: "cursor legacy empty command", payload: cursorLegacy(""),
			path: pathPass, exit: 0, stdout: verdictNone},

		// ---- Windsurf: pre_run_command -------------------------------------
		{name: "windsurf pre_run_command destructive", payload: windsurf("pre_run_command", destr),
			path: pathShell, source: "windsurf-hook", command: destr, decision: "BLOCK", rule: "ts-block-rm-root", exit: 2, stdout: verdictNone},
		{name: "windsurf pre_run_command empty command", payload: windsurf("pre_run_command", ""),
			path: pathPass, exit: 0, stdout: verdictNone},
		{name: "windsurf other action", payload: windsurf("post_run_command", destr),
			path: pathPass, exit: 0, stdout: verdictNone},

		// ---- Unsupported payloads pass through -----------------------------
		{name: "empty object", payload: "{}", path: pathPass, exit: 0, stdout: verdictNone},
		{name: "unrelated object", payload: `{"something":"else"}`, path: pathPass, exit: 0, stdout: verdictNone},
	}
}

// TestHookRoutingCharacterization runs every row through the real hook entry
// point in a child process, each in its own HOME so "no event" is meaningful.
func TestHookRoutingCharacterization(t *testing.T) {
	cases := routingCases(t)
	names := map[string]routingCase{}
	for _, c := range cases {
		names[c.name] = c
	}
	for name, mainDecision := range raisedRows {
		c, ok := names[name]
		if !ok {
			t.Fatalf("raisedRows names %q, which is not a characterization row", name)
		}
		if route.Rank(route.Verdict{Decision: c.decision}) <= route.Rank(route.Verdict{Decision: mainDecision}) {
			t.Errorf("row %q decides %s, not above main's %s: a lane added to a row may only raise", name, c.decision, mainDecision)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, stdout, stderr := runHookChild(t, home, c.payload, c.env...)

			if code != c.exit {
				t.Errorf("exit %d, want %d (path %s). stderr:\n%s", code, c.exit, c.path, stderr)
			}
			checkVerdictShape(t, c.stdout, stdout)

			events := routingEvents(t, configDir)
			if c.path == pathPass {
				if len(events) != 0 {
					t.Fatalf("want passthrough (no evaluation, no event), got %d event(s): %+v", len(events), events)
				}
				return
			}
			if len(events) != 1 {
				t.Fatalf("want exactly one audit event from the %s, got %d: %+v", c.path, len(events), events)
			}
			e := events[0]
			switch c.path {
			case pathShell:
				if e.Command != c.command || e.ToolName != "" {
					t.Errorf("event command=%q tool_name=%q; want the %s to record command %q and no tool name", e.Command, e.ToolName, c.path, c.command)
				}
			case pathMCP:
				if e.Command != "" || e.ToolName != c.tool {
					t.Errorf("event command=%q tool_name=%q; want the %s to record tool %q and no command", e.Command, e.ToolName, c.path, c.tool)
				}
				if c.argKey != "" {
					if _, ok := e.Arguments[c.argKey]; !ok {
						t.Errorf("event arguments %v lack %q", e.Arguments, c.argKey)
					}
				}
			}
			if e.Source != c.source {
				t.Errorf("event source %q, want %q", e.Source, c.source)
			}
			if e.Decision != c.decision {
				t.Errorf("event decision %q, want %q (rules %v) — the %s decides %s on this input",
					e.Decision, c.decision, e.TriggeredRules, c.path, c.decision)
			}
			if c.rule != "" && !containsStr(e.TriggeredRules, c.rule) {
				t.Errorf("event rules %v lack %q", e.TriggeredRules, c.rule)
			}
			if c.taxonomy != "" && !containsStr(e.Taxonomy, c.taxonomy) {
				t.Errorf("event taxonomy %v lacks %q", e.Taxonomy, c.taxonomy)
			}
			var readings []string
			for _, n := range e.Notes {
				if n.Kind == analyzer.NoteLaneReadings {
					readings = append(readings, n.Detail)
				}
			}
			switch {
			case c.readings == "" && len(readings) != 0:
				t.Errorf("a single-lane row's event carries %s notes %q", analyzer.NoteLaneReadings, readings)
			case c.readings != "" && (len(readings) != 1 || readings[0] != c.readings):
				t.Errorf("%s notes %q, want exactly one: %q", analyzer.NoteLaneReadings, readings, c.readings)
			}
		})
	}
}

func routingEvents(t *testing.T, configDir string) []routingEvent {
	t.Helper()
	var out []routingEvent
	for _, l := range strings.Split(readFailSafeAuditLog(t, configDir), "\n") {
		if strings.TrimSpace(l) == "" {
			continue
		}
		var e routingEvent
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("audit line is not JSON: %v (%s)", err, l)
		}
		out = append(out, e)
	}
	return out
}

func checkVerdictShape(t *testing.T, want verdictShape, stdout string) {
	t.Helper()
	lines := jsonLines(stdout)
	if want == verdictNone {
		if strings.TrimSpace(stdout) != "" {
			t.Errorf("stdout %q, want nothing", stdout)
		}
		return
	}
	if len(lines) != 1 {
		t.Fatalf("want one %s verdict on stdout, got %q", want, stdout)
	}
	var v map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &v); err != nil {
		t.Fatalf("stdout verdict is not JSON: %v (%s)", err, lines[0])
	}
	var key, value string
	switch want {
	case verdictCopilotDeny:
		key, value = "permissionDecision", "deny"
	case verdictCursorAllow:
		key, value = "permission", "allow"
	case verdictCursorDeny:
		key, value = "permission", "deny"
	case verdictGeminiAllow:
		key, value = "decision", "allow"
	case verdictGeminiDeny:
		key, value = "decision", "deny"
	}
	if got, _ := v[key].(string); got != value {
		t.Errorf("stdout verdict %s, want %s (%s=%q)", lines[0], want, key, value)
	}
}
