package cli

import (
	"strings"
	"testing"
)

// The last silent allow after #3622 (adversarial review, 2026-09-02): a hook
// invoked with stdin that is not the JSON a harness sends returned nil before
// evaluateCommand ever ran, so a managed fail_closed host allowed whatever the
// harness was about to execute, with no audit event. These re-exec the real
// entry point and assert the exit code, the only contract a harness sees.

func TestHook_MalformedStdin_ExitsTwoUnderManagedFailClosed(t *testing.T) {
	home, _ := newFailSafeHome(t, true, failSafePolicyGood)
	for _, payload := range []string{`{not json`, ``, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /"`} {
		code, stderr := runHookInChildProcess(t, home, payload)
		if code != 2 {
			t.Errorf("payload %q: exit %d; want 2 under managed fail_closed. stderr:\n%s", payload, code, stderr)
			continue
		}
		if !strings.Contains(stderr, "hook input parse") {
			t.Errorf("payload %q: stderr does not name the stage:\n%s", payload, stderr)
		}
	}
}

func TestHook_MalformedStdin_AllowsWithWarningWhenNotManaged(t *testing.T) {
	home, _ := newFailSafeHome(t, false, failSafePolicyGood)
	code, stderr := runHookInChildProcess(t, home, `{not json`)
	if code != 0 {
		t.Fatalf("exit %d; want 0 outside managed mode. stderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "hook input parse") || !strings.Contains(stderr, "evaluated as AUDIT") {
		t.Errorf("the failure must be spelled out, not swallowed:\n%s", stderr)
	}
}
