// Package route decides which evaluation lanes a tool call reaches (ADR-001,
// docs/architecture/adr-001-tool-routing-dialect-lanes.md, #4245).
//
// A call is routed on what the harness tells us: the harness (its payload
// dialect), the tool or event it names, and the host OS. Never on the text:
// the attacker writes the text, and rm, ls and cat are valid in more than one
// shell dialect.
//
// Step 1 of the ADR moved today's routing here unchanged. Before it, the
// decision lived in three inline branches of internal/cli/hook.go: tool_name
// == "Bash" in handlePreToolUse, Gemini's run_shell_command check, and the
// Copilot native adapter renaming bash and powershell to Bash. Every row below
// reproduces one of them, except the rows that add a lane (see table). One row
// names an OS: Copilot's compatible format on Windows, where the harness does
// not name the dialect (D1). internal/cli's TestHookRoutingCharacterization
// pins the result at the hook entry point.
//
// A row with more than one lane runs every lane and keeps the stricter
// verdict, the earlier lane winning ties, except that a rule-less AUDIT gives
// its record to a tied AUDIT that names a rule (Combine, verdict.go).
//
// The package imports only the standard library (internal/archtest).
package route

import (
	"slices"
	"strings"
)

// Harness is the harness a call came from, as far as its payload and the hook
// configuration prove it. Codex and Copilot CLI's Claude-compatible format
// speak Claude Code's PreToolUse dialect, so they are told apart by turn_id and
// by AGENTSHIELD_AGENT_ID, as the audit source is.
type Harness string

const (
	// ClaudeCode is a PreToolUse payload that names no other harness. That
	// includes a harness whose AGENTSHIELD_AGENT_ID is a label this package
	// does not know: its tools are routed as Claude Code's are.
	ClaudeCode Harness = "claude-code"
	// Codex is a PreToolUse payload carrying turn_id.
	Codex Harness = "codex"
	// CopilotCLI is Copilot CLI's Claude-compatible format, the one `agentshield
	// setup copilot-cli` installs: a PreToolUse payload from a hook configured
	// with AGENTSHIELD_AGENT_ID=copilot-cli. Copilot maps its tools to Claude
	// names here, and sends both its bash and powershell tools as Bash.
	CopilotCLI Harness = "copilot-cli"
	// CopilotCLINative is Copilot CLI's native format (toolName, toolArgs),
	// which keeps the runtime tool names: bash, powershell, view, apply_patch.
	CopilotCLINative Harness = "copilot-cli-native"
	// GeminiCLI is a BeforeTool payload.
	GeminiCLI Harness = "gemini-cli"
	// Cursor sends a shell event and no tool (beforeShellExecution, or its
	// legacy payload with a top-level command, which is the same event).
	Cursor Harness = "cursor"
	// Windsurf sends a shell event and no tool (pre_run_command).
	Windsurf Harness = "windsurf"
)

// harnesses lists every harness the hook can name.
var harnesses = []Harness{ClaudeCode, Codex, CopilotCLI, CopilotCLINative, GeminiCLI, Cursor, Windsurf}

// Lane is one way of reading a call.
type Lane string

const (
	// POSIX is the shell pipeline: the command is parsed as bash and run
	// through the staged analyzers (policy.Engine).
	POSIX Lane = "posix"
	// Structured is MCP policy: the tool name and its JSON arguments
	// (mcp.PolicyEvaluator). Nothing parses the arguments as a shell.
	Structured Lane = "structured"
	// PowerShell is the PowerShell lane (ADR-001 step 4): the text is read by
	// internal/psreader and decided by policy.Engine.EvaluateFacts (protected
	// paths and managed-host self-protection; PowerShell pack rules are step
	// 5). It runs only beside a lane its row already had.
	PowerShell Lane = "powershell"
)

// AnyOS in a row matches every host OS.
const AnyOS = ""

// ToolCall is what routing may look at. It never holds the command text.
type ToolCall struct {
	Harness Harness
	// Tool is the tool name the payload carries, or for a harness that sends
	// a shell event and no tool (Cursor, Windsurf), the event name. Matched
	// exactly, case included, as the hook always has.
	Tool string
	// OS is the host OS, as runtime.GOOS spells it.
	OS string
	// HasCommand reports whether the input carries a non-empty string
	// "command" field. It never selects a row; it only marks a gap (see Gap).
	HasCommand bool
}

// row maps (harness, tool, OS) to lanes. A row whose tool is "" is the
// harness's default: it routes every tool no other row of that harness names.
type row struct {
	harness Harness
	tool    string
	os      string
	lanes   []Lane
}

// table is the routing. A tool row beats the default row, and an OS row beats
// an AnyOS row. A row with no lanes means the call is not evaluated.
//
// A row with more than one lane is read by each lane in order, and the
// verdicts are combined (Combine): the stricter wins, and on a tie the
// earlier lane's record is kept, unless it is a plain AUDIT naming no rule
// and a tied AUDIT names one (Gary, 2026-11-05; evidence only). A row moves by ADDING a lane after the one
// it had, never by swapping it (ADR-001 TL;DR 3), so a call never decides
// below main. Only the Claude-shaped handler combines lanes; the Gemini,
// Cursor and Windsurf handlers read one (TestTable_MultiLaneRowsOnlyWhereTheHookCombines).
var table = []row{
	// Claude Code, Codex, Copilot's Claude-compatible format: "Bash" is a
	// shell call. Every tool no row names is a tool call for MCP policy.
	{ClaudeCode, "Bash", AnyOS, []Lane{POSIX}},
	// Claude Code's Windows shell tool (ADR-001 step 4). The local hook sent
	// it to MCP policy (the default row); the PowerShell lane is added after
	// it, so a tie keeps MCP policy's record, as on main, except where MCP
	// policy's AUDIT names no rule and the lane's names one (Combine's AUDIT
	// tie rule, #4779): then the receipt is the lane's. The hook never read
	// it with POSIX, so the row has no POSIX lane. shield-server reads a keyed
	// request with its client's old lane first (step 2), so the PowerShell
	// client's POSIX reading of this tool stays there: PowerShell runs
	// cross-platform CLIs verbatim, and only the POSIX pipeline has their
	// rules (#4766). Dropping it is a step 6 question.
	{ClaudeCode, "PowerShell", AnyOS, []Lane{Structured, PowerShell}},
	// Claude Code's Monitor tool runs the shell script in its command field
	// (#4753). MCP policy read it alone before; the shell pipeline is added
	// after it, not swapped in, because a swap lowered 1 of 37 real Monitor
	// calls from AUDIT to ALLOW (ts-allow-readonly).
	{ClaudeCode, "Monitor", AnyOS, []Lane{Structured, POSIX}},
	{ClaudeCode, "", AnyOS, []Lane{Structured}},
	{Codex, "Bash", AnyOS, []Lane{POSIX}},
	{Codex, "", AnyOS, []Lane{Structured}},
	{CopilotCLI, "Bash", AnyOS, []Lane{POSIX}},
	// Copilot's compatible format sends both its bash and its powershell tool
	// as Bash, so on Windows, where the powershell tool exists, the dialect
	// is unknown and both lanes read the call (D1, Gary's decision 4). On
	// macOS and Linux Copilot has no powershell tool: POSIX alone.
	{CopilotCLI, "Bash", "windows", []Lane{POSIX, PowerShell}},
	{CopilotCLI, "", AnyOS, []Lane{Structured}},

	// Copilot's native format names its two shell tools; the adapter used to
	// rename both to Bash, so a call already named Bash is a shell call too.
	{CopilotCLINative, "bash", AnyOS, []Lane{POSIX}},
	// The powershell tool keeps the bash pipeline it had and gains the
	// PowerShell lane after it.
	{CopilotCLINative, "powershell", AnyOS, []Lane{POSIX, PowerShell}},
	{CopilotCLINative, "Bash", AnyOS, []Lane{POSIX}},
	{CopilotCLINative, "", AnyOS, []Lane{Structured}},

	// Gemini CLI's hook is registered for run_shell_command only. Any other
	// tool passes through unevaluated, as it always has.
	{GeminiCLI, "run_shell_command", AnyOS, []Lane{POSIX}},
	{GeminiCLI, "", AnyOS, nil},

	// Cursor and Windsurf send one shell event each.
	{Cursor, "beforeShellExecution", AnyOS, []Lane{POSIX}},
	{Cursor, "", AnyOS, nil},
	{Windsurf, "pre_run_command", AnyOS, []Lane{POSIX}},
	{Windsurf, "", AnyOS, nil},
}

// Route returns the lanes c runs on. An empty result means the call is not
// evaluated (passthrough).
func Route(c ToolCall) []Lane {
	lanes, _ := lookup(table, c)
	return slices.Clone(lanes)
}

// Gap reports a call no tool row names that carries command text and that its
// harness's default sends to the Structured lane only. Such a call is
// evaluated by MCP policy as a tool call, as before ADR-001, and no shell lane
// reads its text: Claude Code's PowerShell tool was the case that went
// unnoticed (it has a row now). The hook records it as a routing_gap note. A gap never changes
// the lanes, so it never changes a decision.
//
// A Gemini, Cursor or Windsurf call with no row is not evaluated at all, so
// there is no event to carry a note; Gap is false for it.
func Gap(c ToolCall) bool {
	lanes, named := lookup(table, c)
	return !named && c.HasCommand && slices.Equal(lanes, []Lane{Structured})
}

// lookup returns the lanes of the most specific row matching c, and whether
// that row names c's tool (rather than being the harness's default).
func lookup(t []row, c ToolCall) (lanes []Lane, named bool) {
	best := -1
	bestRank := -1
	for i, r := range t {
		if r.harness != c.Harness || (r.tool != "" && r.tool != c.Tool) || (r.os != AnyOS && r.os != c.OS) {
			continue
		}
		rank := 0
		if r.tool != "" {
			rank += 2
		}
		if r.os != AnyOS {
			rank++
		}
		if rank > bestRank {
			best, bestRank = i, rank
		}
	}
	if best < 0 {
		return nil, false
	}
	return t[best].lanes, t[best].tool != ""
}

// NestedLane routes text a lane found an interpreter started with (ADR-001
// D6): `powershell -EncodedCommand …` or `bash -c …` inside PowerShell text.
// It is keyed on the interpreter's program name, in any letter case, with or
// without a directory or `.exe`, never on the text. powershell and pwsh go to
// the PowerShell lane, bash and sh to the POSIX lane. Any other interpreter
// (cmd, wsl) has no lane: ok is false, and the caller records the unread text.
func NestedLane(exe string) (lane Lane, ok bool) {
	if i := strings.LastIndexAny(exe, `/\`); i >= 0 {
		exe = exe[i+1:]
	}
	exe = asciiLower(exe)
	exe = strings.TrimSuffix(exe, ".exe")
	switch exe {
	case "powershell", "pwsh":
		return PowerShell, true
	case "bash", "sh":
		return POSIX, true
	}
	return "", false
}

// asciiLower folds ASCII letters only, as Windows resolves a program name:
// a non-ASCII letter that lower-cases to an ASCII one (U+212A KELVIN SIGN)
// names a different file.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
