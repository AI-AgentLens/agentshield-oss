package route

import (
	"slices"
	"testing"
)

// hostOSes are the OSes the hook ships on.
var hostOSes = []string{"darwin", "linux", "windows"}

// TestRoute_TodaysRouting is the table, written out call by call: it is what
// internal/cli/hook.go decided inline before ADR-001 step 1, on every OS, plus
// the lanes rows have gained since (each one after the lanes it had).
// The hook-level pins are internal/cli's TestHookRoutingCharacterization.
func TestRoute_TodaysRouting(t *testing.T) {
	posix := []Lane{POSIX}
	structured := []Lane{Structured}
	structuredThenPOSIX := []Lane{Structured, POSIX}           // #4753
	structuredThenPowerShell := []Lane{Structured, PowerShell} // ADR-001 step 4
	posixThenPowerShell := []Lane{POSIX, PowerShell}           // ADR-001 step 4
	cases := []struct {
		h    Harness
		tool string
		want []Lane
		// windows, when set, is the row on a Windows host; want is every
		// other OS's.
		windows []Lane
	}{
		{ClaudeCode, "Bash", posix, nil},
		{ClaudeCode, "bash", structured, nil}, // exact match, case included
		{ClaudeCode, "PowerShell", structuredThenPowerShell, nil},
		{ClaudeCode, "powershell", structured, nil}, // exact match, case included
		{ClaudeCode, "Powershell", structured, nil},
		{ClaudeCode, "Monitor", structuredThenPOSIX, nil},
		{ClaudeCode, "monitor", structured, nil}, // exact match, case included
		{ClaudeCode, "run_shell_command", structured, nil},
		{ClaudeCode, "Read", structured, nil},
		{ClaudeCode, "mcp__srv__tool", structured, nil},
		{ClaudeCode, "apply_patch", structured, nil},
		{ClaudeCode, "", structured, nil}, // a Claude-shaped event with no tool name
		{Codex, "Bash", posix, nil},       // Codex on Windows: not a row of step 4
		{Codex, "PowerShell", structured, nil},
		{Codex, "apply_patch", structured, nil},
		{Codex, "Monitor", structured, nil}, // the Monitor row is Claude Code's only
		{CopilotCLI, "Bash", posix, posixThenPowerShell},
		{CopilotCLI, "PowerShell", structured, nil}, // the compatible format never sends it
		{CopilotCLI, "Monitor", structured, nil},
		{CopilotCLINative, "Monitor", structured, nil},
		{CopilotCLI, "bash", structured, nil}, // the native rename never applied here
		{CopilotCLI, "Read", structured, nil},
		{CopilotCLINative, "bash", posix, nil},
		{CopilotCLINative, "powershell", posixThenPowerShell, nil},
		{CopilotCLINative, "Bash", posix, nil},
		{CopilotCLINative, "Powershell", structured, nil},
		{CopilotCLINative, "view", structured, nil},
		{CopilotCLINative, "apply_patch", structured, nil},
		{GeminiCLI, "run_shell_command", posix, nil},
		{GeminiCLI, "read_file", nil, nil},
		{GeminiCLI, "Bash", nil, nil},
		{Cursor, "beforeShellExecution", posix, nil}, // Cursor on Windows: out of step 4's scope
		{Cursor, "beforeReadFile", nil, nil},         // the hook's dispatch never sends this here; the default must still be nothing
		{Windsurf, "pre_run_command", posix, nil},    // Windsurf on Windows: likewise
		{Windsurf, "post_run_command", nil, nil},     // likewise
		{Harness("unknown"), "Bash", nil, nil},
	}
	for _, c := range cases {
		for _, goos := range hostOSes {
			want := c.want
			if goos == "windows" && c.windows != nil {
				want = c.windows
			}
			for _, hasCmd := range []bool{false, true} {
				got := Route(ToolCall{Harness: c.h, Tool: c.tool, OS: goos, HasCommand: hasCmd})
				if !slices.Equal(got, want) {
					t.Errorf("Route(%s, %q, %s, command=%v) = %v, want %v", c.h, c.tool, goos, hasCmd, got, want)
				}
			}
		}
	}
}

func TestGap(t *testing.T) {
	cases := []struct {
		h      Harness
		tool   string
		hasCmd bool
		want   bool
	}{
		{ClaudeCode, "Shell", true, true},
		{ClaudeCode, "Powershell", true, true}, // not the PowerShell row: exact match
		{ClaudeCode, "mcp__srv__tool", true, true},
		{Codex, "Shell", true, true},
		{CopilotCLI, "bash", true, true},
		{CopilotCLINative, "Powershell", true, true},
		{ClaudeCode, "PowerShell", true, false},  // named (ADR-001 step 4): the PowerShell lane reads it
		{ClaudeCode, "PowerShell", false, false}, // no command text, nothing unread
		{Codex, "PowerShell", true, true},        // the row is Claude Code's only
		{ClaudeCode, "Read", false, false},
		{ClaudeCode, "Bash", true, false},       // named: the shell lane reads it
		{ClaudeCode, "Monitor", true, false},    // named (#4753): the shell lane reads it too
		{ClaudeCode, "monitor", true, true},     // not that row
		{Codex, "Monitor", true, true},          // the row is Claude Code's only
		{CopilotCLINative, "bash", true, false}, // named
		{CopilotCLINative, "powershell", true, false},
		{CopilotCLI, "Bash", true, false},
		{GeminiCLI, "Bash", true, false}, // not evaluated at all: no event to note
		{Cursor, "beforeShellExecution", true, false},
		{Harness("unknown"), "Shell", true, false},
	}
	for _, c := range cases {
		for _, goos := range hostOSes {
			if got := Gap(ToolCall{Harness: c.h, Tool: c.tool, OS: goos, HasCommand: c.hasCmd}); got != c.want {
				t.Errorf("Gap(%s, %q, %s, command=%v) = %v, want %v", c.h, c.tool, goos, c.hasCmd, got, c.want)
			}
		}
	}
}

// TestGap_NeverChangesTheLanes: a gap is a record, so a call routes the same
// with or without command text.
func TestGap_NeverChangesTheLanes(t *testing.T) {
	for _, h := range harnesses {
		for _, tool := range []string{"Bash", "bash", "PowerShell", "Shell", "run_shell_command", "Read", ""} {
			for _, goos := range hostOSes {
				without := Route(ToolCall{Harness: h, Tool: tool, OS: goos})
				with := Route(ToolCall{Harness: h, Tool: tool, OS: goos, HasCommand: true})
				if !slices.Equal(without, with) {
					t.Errorf("(%s, %q, %s): lanes %v without a command, %v with one", h, tool, goos, without, with)
				}
			}
		}
	}
}

// combiningHarnesses are the harnesses whose hook handler runs every lane of
// a row and combines their verdicts: internal/cli's handlePreToolUse, which
// Claude Code, Codex and both Copilot CLI dialects reach. The Gemini, Cursor
// and Windsurf handlers read one lane, so a second lane on one of their rows
// would be silently ignored.
var combiningHarnesses = []Harness{ClaudeCode, Codex, CopilotCLI, CopilotCLINative}

// implementedLanes are the lanes the hook can run (internal/cli
// combineLanes); a lane outside it takes the fail-safe reading.
var implementedLanes = []Lane{POSIX, Structured, PowerShell}

// TestTable_MultiLaneRowsOnlyWhereTheHookCombines: a row may hold more than
// one lane only for a harness whose handler combines lanes, each lane at most
// once, and only lanes the hook implements.
func TestTable_MultiLaneRowsOnlyWhereTheHookCombines(t *testing.T) {
	multi := 0
	for _, r := range table {
		for _, l := range r.lanes {
			if !slices.Contains(implementedLanes, l) {
				t.Errorf("row (%s, %q, %q) routes to lane %s, which the hook does not implement", r.harness, r.tool, r.os, l)
			}
		}
		if len(r.lanes) <= 1 {
			continue
		}
		multi++
		if !slices.Contains(combiningHarnesses, r.harness) {
			t.Errorf("row (%s, %q, %q) has lanes %v, but the %s handler reads one lane: implement combining there first", r.harness, r.tool, r.os, r.lanes, r.harness)
		}
		seen := map[Lane]bool{}
		for _, l := range r.lanes {
			if seen[l] {
				t.Errorf("row (%s, %q, %q) names lane %s twice", r.harness, r.tool, r.os, l)
			}
			seen[l] = true
		}
	}
	if multi == 0 {
		t.Fatal("no multi-lane row: this check is vacuous (the Monitor row, #4753, should be one)")
	}
}

type rowKey struct {
	harness  Harness
	tool, os string
}

// mainLanes are the lanes the local hook on main gave each multi-lane row's
// call before the row gained a lane: the record a tie must keep. Every
// multi-lane row is listed, so a new one has to state what it replaced.
var mainLanes = map[rowKey][]Lane{
	{ClaudeCode, "Monitor", AnyOS}: {Structured}, // #4753
	// ADR-001 step 4: the PowerShell lane is new.
	{ClaudeCode, "PowerShell", AnyOS}:       {Structured},
	{CopilotCLI, "Bash", "windows"}:         {POSIX}, // the AnyOS Bash row
	{CopilotCLINative, "powershell", AnyOS}: {POSIX}, // the adapter's rename to Bash
}

// TestTable_AddedLanesComeAfterTheOldOnes: a row that combines lanes keeps
// the lanes main gave the call FIRST, so they win ties and keep main's record
// (ADR-001 D4), and the PowerShell lane, the newest, comes last. A row that
// put a new lane first would rewrite every tied receipt.
func TestTable_AddedLanesComeAfterTheOldOnes(t *testing.T) {
	multi := map[rowKey]bool{}
	for _, r := range table {
		if len(r.lanes) <= 1 {
			continue
		}
		k := rowKey{r.harness, r.tool, r.os}
		multi[k] = true
		old, ok := mainLanes[k]
		if !ok {
			t.Errorf("multi-lane row (%s, %q, %q) is not in mainLanes: say which lanes main gave the call", r.harness, r.tool, r.os)
			continue
		}
		if len(old) >= len(r.lanes) || !slices.Equal(r.lanes[:len(old)], old) {
			t.Errorf("row (%s, %q, %q) has lanes %v; main's %v must come first, and something must be added", r.harness, r.tool, r.os, r.lanes, old)
		}
		if i := slices.Index(r.lanes, PowerShell); i >= 0 && i != len(r.lanes)-1 {
			t.Errorf("row (%s, %q, %q) has lanes %v; the PowerShell lane is the newest and must come last", r.harness, r.tool, r.os, r.lanes)
		}
	}
	for k := range mainLanes {
		if !multi[k] {
			t.Errorf("mainLanes names (%s, %q, %q), which is not a multi-lane row", k.harness, k.tool, k.os)
		}
	}
}

// TestTable_PowerShellLaneNeverAlone: the PowerShell lane is added beside a
// lane its row already had (ADR-001 migration step 4), so no row reads a call
// with the new reader alone.
func TestTable_PowerShellLaneNeverAlone(t *testing.T) {
	rows := 0
	for _, r := range table {
		if !slices.Contains(r.lanes, PowerShell) {
			continue
		}
		rows++
		if len(r.lanes) < 2 {
			t.Errorf("row (%s, %q, %q) reads the call with the PowerShell lane alone", r.harness, r.tool, r.os)
		}
	}
	if rows != 3 {
		t.Errorf("%d rows hold the PowerShell lane, want 3 (Claude Code PowerShell, Copilot compat Bash on Windows, Copilot native powershell)", rows)
	}
}

// TestNestedLane: a nested interpreter is routed on its program name
// (ADR-001 D6), any ASCII case, with or without a directory or .exe.
func TestNestedLane(t *testing.T) {
	cases := []struct {
		exe  string
		want Lane
		ok   bool
	}{
		{"powershell", PowerShell, true},
		{"pwsh", PowerShell, true},
		{"PowerShell.EXE", PowerShell, true},
		{"PWSH.exe", PowerShell, true},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, PowerShell, true},
		{"/usr/local/bin/pwsh", PowerShell, true},
		{"bash", POSIX, true},
		{"sh", POSIX, true},
		{"BASH.exe", POSIX, true},
		{`C:\Program Files\Git\bin\bash.exe`, POSIX, true},
		{"cmd", "", false},
		{"wsl", "", false},
		{"zsh", "", false},
		{"", "", false},
		{"powershell.exe.exe", "", false},
		{"bash5", "", false},
		{"pwsh\u212a", "", false},
		{"\u212ash", "", false}, // KELVIN SIGN folds to k, not s: no lane
	}
	for _, c := range cases {
		got, ok := NestedLane(c.exe)
		if got != c.want || ok != c.ok {
			t.Errorf("NestedLane(%q) = %q, %v; want %q, %v", c.exe, got, ok, c.want, c.ok)
		}
	}
}

// TestTable_ShellOnlyHarnesses: the Gemini, Cursor and Windsurf handlers in
// internal/cli implement only the POSIX lane (their dialects have no
// tool-call path), so a row sending one of their calls anywhere else would
// be silently dropped. Adding one means adding that path to the handler first.
func TestTable_ShellOnlyHarnesses(t *testing.T) {
	for _, r := range table {
		switch r.harness {
		case GeminiCLI, Cursor, Windsurf:
			if len(r.lanes) > 0 && !slices.Equal(r.lanes, []Lane{POSIX}) {
				t.Errorf("row (%s, %q, %q) has lanes %v; the %s handler implements only %s", r.harness, r.tool, r.os, r.lanes, r.harness, POSIX)
			}
		}
	}
}

// TestTable_ToolCallHarnessesNeverRouteToNothing: Claude Code, Codex and both
// Copilot formats send every tool call through the hook, and the hook has
// always evaluated each one, on the shell pipeline or MCP policy. A row of
// theirs with no lanes would pass a call through unevaluated, and nothing
// else would notice (#4754 review, H9).
func TestTable_ToolCallHarnessesNeverRouteToNothing(t *testing.T) {
	checked := 0
	for _, r := range table {
		switch r.harness {
		case ClaudeCode, Codex, CopilotCLI, CopilotCLINative:
			checked++
			if len(r.lanes) == 0 {
				t.Errorf("row (%s, %q, %q) routes to no lane: a %s tool call would pass through unevaluated", r.harness, r.tool, r.os, r.harness)
			}
		}
	}
	if checked < 4 {
		t.Fatalf("only %d rows checked: the table is not being read", checked)
	}
}

// TestTable_KeysAreUnique: two rows with one key would make the first one
// win silently.
func TestTable_KeysAreUnique(t *testing.T) {
	type key struct {
		harness  Harness
		tool, os string
	}
	seen := map[key]bool{}
	for _, r := range table {
		k := key{r.harness, r.tool, r.os}
		if seen[k] {
			t.Errorf("duplicate row key (%s, %q, %q)", r.harness, r.tool, r.os)
		}
		seen[k] = true
	}
}

// TestTable_EveryHarnessHasADefault: a harness with no default row would
// route every unnamed tool to no lane at all, which is a passthrough nobody
// chose. Each default is written out, even an empty one.
func TestTable_EveryHarnessHasADefault(t *testing.T) {
	for _, h := range harnesses {
		found := false
		for _, r := range table {
			if r.harness == h && r.tool == "" && r.os == AnyOS {
				found = true
			}
		}
		if !found {
			t.Errorf("harness %s has no default row", h)
		}
	}
	for _, r := range table {
		if !slices.Contains(harnesses, r.harness) {
			t.Errorf("row (%s, %q) names a harness missing from harnesses", r.harness, r.tool)
		}
	}
}

// TestLookup_Precedence runs the lookup over a table with OS rows of every
// kind (the real table has one): a tool row beats a default, and an OS row
// beats an AnyOS row of the same kind.
func TestLookup_Precedence(t *testing.T) {
	synthetic := []row{
		{ClaudeCode, "", AnyOS, []Lane{Structured}},
		{ClaudeCode, "", "windows", []Lane{PowerShell}},
		{ClaudeCode, "Bash", AnyOS, []Lane{POSIX}},
		{ClaudeCode, "Bash", "windows", []Lane{POSIX, PowerShell}},
	}
	cases := []struct {
		tool, os  string
		want      []Lane
		wantNamed bool
	}{
		{"Bash", "darwin", []Lane{POSIX}, true},
		{"Bash", "windows", []Lane{POSIX, PowerShell}, true},
		{"Read", "darwin", []Lane{Structured}, false},
		{"Read", "windows", []Lane{PowerShell}, false},
	}
	for _, c := range cases {
		got, named := lookup(synthetic, ToolCall{Harness: ClaudeCode, Tool: c.tool, OS: c.os})
		if !slices.Equal(got, c.want) || named != c.wantNamed {
			t.Errorf("lookup(%q, %s) = %v named=%v, want %v named=%v", c.tool, c.os, got, named, c.want, c.wantNamed)
		}
	}
	// Row order must not matter.
	reversed := slices.Clone(synthetic)
	slices.Reverse(reversed)
	for _, c := range cases {
		if got, _ := lookup(reversed, ToolCall{Harness: ClaudeCode, Tool: c.tool, OS: c.os}); !slices.Equal(got, c.want) {
			t.Errorf("reversed table: lookup(%q, %s) = %v, want %v", c.tool, c.os, got, c.want)
		}
	}
}

// TestRoute_ReturnsACopy: a caller that appends to the result must not edit
// the table.
func TestRoute_ReturnsACopy(t *testing.T) {
	c := ToolCall{Harness: ClaudeCode, Tool: "Bash", OS: "linux"}
	got := Route(c)
	got[0] = Structured
	if again := Route(c); !slices.Equal(again, []Lane{POSIX}) {
		t.Fatalf("Route result aliases the table: %v after the caller edited its copy", again)
	}
}
