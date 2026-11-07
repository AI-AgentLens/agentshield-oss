package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// The routing_gap note (ADR-001 D5, #4245). A tool call that carries command
// text, from a harness and tool no routing row names, still goes to MCP policy
// as it did before ADR-001; its audit event now says so. A note never changes
// a decision.

// routingGapRows are the TestHookRoutingCharacterization rows whose call
// carries a command and reaches MCP policy through a harness's default row,
// keyed by row name, with the tool the note must name.
var routingGapRows = map[string]string{
	"codex PowerShell key read":                                  "PowerShell", // the PowerShell row is Claude Code's
	"claude-code bash (lower case) benign":                       "bash",
	"claude-code run_shell_command benign":                       "run_shell_command",
	"claude-code mcp__srv__tool with a command argument":         "mcp__srv__tool",
	"claude-code unknown tool carrying a command":                "Shell",
	"copilot compat bash (lower case) benign":                    "bash",
	"copilot native Powershell (not a runtime name) destructive": "Powershell",
	"codex Monitor destructive":                                  "Monitor", // the Monitor row is Claude Code's (#4753)
}

func routingGapNotes(ns []logger.Note) []logger.Note {
	var out []logger.Note
	for _, n := range ns {
		if n.Kind == analyzer.NoteRoutingGap {
			out = append(out, n)
		}
	}
	return out
}

// TestRoutingGapNote_NeverChangesADecision replays every characterization row
// whose call is evaluated. The rows' exit codes and decisions were measured on
// main before the note existed (except the rows in raisedRows, which the lane
// combiner raised later), so each row asserts, on one run, that the decision
// is still the row's and that the note is present exactly on the gap rows: on
// an AUDIT (Codex's PowerShell, mcp__srv__tool) and on a BLOCK (Shell) alike.
func TestRoutingGapNote_NeverChangesADecision(t *testing.T) {
	cases := routingCases(t)
	names := map[string]bool{}
	for _, c := range cases {
		names[c.name] = true
	}
	for name := range routingGapRows {
		if !names[name] {
			t.Fatalf("routingGapRows names %q, which is not a characterization row: the gap check would skip it", name)
		}
	}

	evaluated := 0
	for _, c := range cases {
		if c.path == pathPass {
			continue
		}
		evaluated++
		t.Run(c.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
			code, _, stderr := runHookChild(t, home, c.payload, c.env...)
			if code != c.exit {
				t.Errorf("exit %d, want the row's %d. stderr:\n%s", code, c.exit, stderr)
			}
			e := lastLoggedEvent(t, configDir)
			if e.Decision != c.decision {
				t.Errorf("decision %q, want the row's %q (rules %v, notes %+v)", e.Decision, c.decision, e.TriggeredRules, e.Notes)
			}
			gaps := routingGapNotes(e.Notes)
			tool, isGap := routingGapRows[c.name]
			switch {
			case isGap && len(gaps) != 1:
				t.Errorf("want one %s note, got %+v", analyzer.NoteRoutingGap, e.Notes)
			case isGap && !strings.Contains(gaps[0].Detail, `"`+tool+`"`):
				t.Errorf("note detail %q does not name the tool %q", gaps[0].Detail, tool)
			case !isGap && len(gaps) != 0:
				t.Errorf("want no %s note on a %s row, got %+v", analyzer.NoteRoutingGap, c.path, gaps)
			}
		})
	}
	if evaluated < 30 {
		t.Fatalf("only %d evaluated rows: the characterization table is not being read", evaluated)
	}
}

// TestRoutingGapNote_OnTheWire: the note travels in the /api/audit body, not
// only on the local line.
func TestRoutingGapNote_OnTheWire(t *testing.T) {
	_, configDir := newFailSafeHome(t, false, failSafePolicyGood)
	posted := captureAuditPOSTs(t)

	payload := claudeShaped(t, "PreToolUse", "mcp__srv__tool", routingCmd(routingDestructive()), nil)
	var input hookInput
	var raw rawHookInput
	if err := json.Unmarshal([]byte(payload), &input); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(payload), &raw)
	if err := handleClaudeCodeHook(input, raw.ToolInput); err != nil {
		t.Fatalf("handleClaudeCodeHook: %v", err)
	}

	if e := lastLoggedEvent(t, configDir); e.Decision != "AUDIT" || len(routingGapNotes(e.Notes)) != 1 {
		t.Fatalf("local event decision %q notes %+v, want AUDIT with one %s note", e.Decision, e.Notes, analyzer.NoteRoutingGap)
	}
	sent := posted()
	if len(sent) != 1 || len(routingGapNotes(sent[0])) != 1 {
		t.Errorf("POSTed notes %+v, want one %s note on the wire", sent, analyzer.NoteRoutingGap)
	}
}

// TestRoutingGapNote_OnTheManagedWriteBlock: the managed-host tool-write BLOCK
// (#4260) is recorded before MCP policy loads; a gap call there carries the
// note too, and the BLOCK is unchanged.
func TestRoutingGapNote_OnTheManagedWriteBlock(t *testing.T) {
	home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
	target := filepath.Join(home, ".agentshield", "policy.yaml")
	payload := claudeShaped(t, "PreToolUse", "Write", map[string]interface{}{
		"file_path": target, "content": "rules: []\n", "command": "ls",
	}, nil)
	code, _, stderr := runHookChild(t, home, payload)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (managed tool-write block). stderr:\n%s", code, stderr)
	}
	e := lastLoggedEvent(t, configDir)
	if !containsStr(e.TriggeredRules, "enterprise-self-protect") {
		t.Errorf("rules %v, want enterprise-self-protect", e.TriggeredRules)
	}
	if len(routingGapNotes(e.Notes)) != 1 {
		t.Errorf("notes %+v, want one %s note", e.Notes, analyzer.NoteRoutingGap)
	}
}

// TestRoutingGapNote_OnTheFailClosedBlock: on a managed fail_closed host whose
// MCP ruleset failed to load, a gap call is blocked before any rule runs
// (enterprise-fail-closed). Its event carries the note too, and the BLOCK is
// unchanged (#4754 review, mutant H10).
func TestRoutingGapNote_OnTheFailClosedBlock(t *testing.T) {
	for _, fx := range unreadablePacksFixtures {
		t.Run(fx.name, func(t *testing.T) {
			home, configDir := newFailSafeHome(t, true, failSafePolicyGood)
			fx.make(t, configDir)
			payload := claudeShaped(t, "PreToolUse", "mcp__srv__tool", routingCmd(routingBenign), nil)
			code, _, stderr := runHookChild(t, home, payload)
			if code != 2 {
				t.Fatalf("exit %d, want 2 (fail_closed on a degraded MCP ruleset). stderr:\n%s", code, stderr)
			}
			e := lastLoggedEvent(t, configDir)
			if e.Decision != "BLOCK" || !containsStr(e.TriggeredRules, failClosedRuleID) {
				t.Errorf("decision %q rules %v, want BLOCK by %s", e.Decision, e.TriggeredRules, failClosedRuleID)
			}
			if len(routingGapNotes(e.Notes)) != 1 {
				t.Errorf("notes %+v, want one %s note", e.Notes, analyzer.NoteRoutingGap)
			}
		})
	}
}
