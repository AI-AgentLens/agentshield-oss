package cli

import (
	"fmt"
	"strings"
	"testing"
)

// #4448: a data-label BLOCK used to keep the matched value in the audit event,
// which is the local audit.jsonl line and the /api/audit body. These drive the
// real hook entry point in a child process and read the line it wrote.

const dataLabelPolicy4448 = `version: "0.1"
defaults:
  decision: "AUDIT"
rules: []
data_labels:
  - id: "customer-records"
    name: "Customer records"
    decision: "BLOCK"
    confidence: 0.9
    reason: "customer id in agent action"
    patterns:
      - regex: 'CUST-[0-9]{6}'
`

func dataLabelPayload4448(cmd string) string {
	return fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"dl-4448","tool_input":{"command":%q}}`, cmd)
}

func TestHook_DataLabelBlock_AuditRecordCarriesNoMatchedValue_4448(t *testing.T) {
	const idA, idB = "CUST-104233", "CUST-104234"
	cmd := "echo " + idA + " " + idB + " > notes.txt"

	t.Run("control: without the label the value is in the record", func(t *testing.T) {
		home, configDir := newFailSafeHome(t, false, failSafePolicyGood)
		runHookInChildProcess(t, home, dataLabelPayload4448(cmd))
		if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, idA) {
			t.Fatalf("control is vacuous: the unlabelled run did not record the command:\n%s", log)
		}
	})

	t.Run("label BLOCK decides BLOCK and the record has the id, not the values", func(t *testing.T) {
		home, configDir := newFailSafeHome(t, false, dataLabelPolicy4448)
		code, stderr := runHookInChildProcess(t, home, dataLabelPayload4448(cmd))
		if code != 2 {
			t.Fatalf("exit %d, want 2 (BLOCK); stderr:\n%s", code, stderr)
		}
		log := readFailSafeAuditLog(t, configDir)
		for _, leak := range []string{idA, idB} {
			if strings.Contains(log, leak) {
				t.Fatalf("%s survived in the audit line:\n%s", leak, log)
			}
		}
		if got := strings.Count(log, "[LABEL:customer-records]"); got < 2 {
			t.Fatalf("want a placeholder per match, got %d:\n%s", got, log)
		}
		if !strings.Contains(log, `"dl-customer-records"`) {
			t.Fatalf("the rule id must stay in the record:\n%s", log)
		}
	})

	t.Run("a command that matches no label is recorded unchanged", func(t *testing.T) {
		home, configDir := newFailSafeHome(t, false, dataLabelPolicy4448)
		runHookInChildProcess(t, home, dataLabelPayload4448("echo hello CUST-12"))
		if log := readFailSafeAuditLog(t, configDir); !strings.Contains(log, "echo hello CUST-12") {
			t.Fatalf("non-matching command was altered:\n%s", log)
		}
	})
}
