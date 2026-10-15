package cli

import (
	"strings"
	"testing"
)

// TestCursorDocumentedPayloadIsEvaluated (#4261): Cursor's documented hook
// payload carries hook_event_name on every event. The dispatcher sent any
// payload with an event name to the Claude handler, where tool_name is empty,
// so a Cursor shell command was never evaluated. The legacy shape is the
// control: it proves the command is one this policy denies.
func TestCursorDocumentedPayloadIsEvaluated(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	common := `"conversation_id":"c1","generation_id":"g1","model":"m","cursor_version":"1.0","workspace_roots":["/repo"],"user_email":"a@b.c","transcript_path":null`
	legacy := `{"command":"` + destructiveShell() + `","cwd":"/repo"}`
	documented := `{"hook_event_name":"beforeShellExecution",` + common + `,"command":"` + destructiveShell() + `","cwd":"/repo","sandbox":false}`
	benign := `{"hook_event_name":"beforeShellExecution",` + common + `,"command":"ls -la","cwd":"/repo","sandbox":false}`

	if _, stdout, stderr := runHookChild(t, home, legacy); !strings.Contains(stdout, `"permission":"deny"`) {
		t.Fatalf("control (legacy shape): stdout %q stderr %q, want deny", stdout, stderr)
	}
	if _, stdout, stderr := runHookChild(t, home, documented); !strings.Contains(stdout, `"permission":"deny"`) {
		t.Errorf("documented shape: stdout %q stderr %q, want Cursor deny verdict", stdout, stderr)
	}
	if _, stdout, stderr := runHookChild(t, home, benign); !strings.Contains(stdout, `"permission":"allow"`) {
		t.Errorf("documented shape, benign: stdout %q stderr %q, want Cursor allow verdict", stdout, stderr)
	}
}

// A Claude-shaped payload must keep its own handler: the routing keys on the
// Cursor event name AND an empty tool_name.
func TestCursorEventRoutingLeavesClaudeAlone(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	p := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"` + destructiveShell() + `"}}`
	if code, _, stderr := runHookChild(t, home, p); code != 2 {
		t.Errorf("Claude Bash payload: exit %d stderr %q, want 2", code, stderr)
	}
}
