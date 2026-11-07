package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// #4813, end to end: a data-label value inside a secret's value left the
// rest of the secret in the record, because Redacted() scrubbed the label
// before it redacted the secret. Each row runs the real hook entry point as
// Codex runs it, in a child process with the production detached uploader
// (envAuditDetachedSpawn), on a home whose policy declares the
// customer-records label, enrolled with fake credentials at a local capture
// server. The command carries the issue's shape. Both copies of the record,
// the audit.jsonl line and the uploaded wire entry, must be free of the
// secret's tail, its head and the label value, and agree with each other.
// The decision, exit code and stdout are main's.
//
// The file uses no symbol #4813 added, so it runs on main too: there every
// row's leak checks fail and its decision, exit-code and stdout checks pass.

const tail4813 = "zz9yy8xx7ww6vv5u"

// shape4813 is the issue's command, assembled at runtime.
func shape4813() string { return "export TO" + "KEN=abcdefghijklmn" + labelValue4805() + tail4813 }

func TestHookRecord_LabelInsideSecret_4813(t *testing.T) {
	rows := []struct {
		name     string
		managed  bool
		policy   string
		decision string // main's
		exit     int    // main's
		stdout   string // main's
	}{
		{name: "normal path", policy: labelledPolicy4805, decision: "BLOCK", exit: 2},
		{name: "fail-safe: policy load fails, managed fail_closed", managed: true, policy: brokenElsewhere4805, decision: "BLOCK", exit: 2},
		{name: "fail-safe: engine init fails on a rule", policy: failSafePolicyBadLabel + labelBlock4805, decision: "AUDIT", exit: 0},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, c.managed, c.policy)
			wire.enroll(t)
			code, stdout, stderr := runHookChild(t, home, codexPayload4805(t, shape4813()), envAuditDetachedSpawn+"=1")
			// A failure explains itself: one unexplained failure in 23 runs
			// (2026-11-06) printed nothing this test now logs.
			t.Cleanup(func() {
				if t.Failed() {
					t.Logf("child exit %d stdout %q stderr:\n%s\nline:\n%.2000s\nwire: %.2000v", code, stdout, stderr, readFailSafeAuditLog(t, configDir), wire.all())
				}
			})
			// The uploader is a detached process: wait for its POST.
			deadline := time.Now().Add(30 * time.Second)
			for len(wire.all()) == 0 && time.Now().Before(deadline) {
				time.Sleep(50 * time.Millisecond)
			}
			// It goes on writing the queue after the POST, so wait for it to
			// exit before the temp HOME is removed (Opus pass 1: 3 of 240
			// runs under load failed that removal, the record correct).
			waitIdle(t, filepath.Join(configDir, auditQueueDirName))
			entries := wire.all()
			line := readFailSafeAuditLog(t, configDir)
			if code != c.exit || stdout != c.stdout {
				t.Errorf("exit %d stdout %q, want exit %d stdout %q (main's)", code, stdout, c.exit, c.stdout)
			}
			if len(entries) != 1 {
				t.Fatalf("%d wire entries, want 1; stderr:\n%s", len(entries), stderr)
			}
			w := entries[0]
			if d := fmt.Sprint(w["decision"]); d != c.decision {
				t.Errorf("wire decision %s, want %s (main's)", d, c.decision)
			}
			var e logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &e); err != nil {
				t.Fatalf("audit.jsonl: %v\n%s", err, line)
			}
			if e.Decision != c.decision {
				t.Errorf("line decision %s, want %s (main's)", e.Decision, c.decision)
			}
			wireText, _ := json.Marshal(entries)
			t.Logf("exit=%d decision=%s line command=%q wire command=%q", code, e.Decision, e.Command, w["command"])
			for _, leak := range []string{tail4813, labelValue4805(), "abcdefghijklmn"} {
				if strings.Contains(line, leak) {
					t.Errorf("LEAK: the audit.jsonl line carries %q:\n%s", leak, line)
				}
				if strings.Contains(string(wireText), leak) {
					t.Errorf("LEAK: the wire entry carries %q:\n%s", leak, wireText)
				}
			}
			if e.Command != w["command"] {
				t.Errorf("line and wire disagree: %q vs %q", e.Command, w["command"])
			}
		})
	}
}

// TestHookRecord_LabelInsideSecret_BudgetAnswer_4813 is the budget's answer
// on a managed fail_closed host with data labels, as
// TestFailSafeRecord_TooLargeToScrub_AnsweredOnTime runs it (Codex, budget
// 8 s, the policy load held past it), with the issue's shape in the command.
// At 1 MiB the union redaction cannot finish in the time left at
// budgetScrubCostPerKiB, so the record withholds the agent text: the BLOCK
// lands before Codex's 10 s timeout, and neither copy carries the label
// value or any part of the secret. At its own size the same command is
// scrubbed on the budget's path too, with the union: both copies read
// "export [REDACTED]".
func TestHookRecord_LabelInsideSecret_BudgetAnswer_4813(t *testing.T) {
	if testing.Short() {
		t.Skip("waits out an 8 s budget per row")
	}
	big := strings.Repeat(shape4813()+" ; ", (1<<20)/(len(shape4813())+3))
	for _, c := range []struct {
		name, cmd string
		withheld  bool
	}{
		{"1 MiB, withheld", big, true},
		{"the issue's command, scrubbed with the union", shape4813(), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, true, labelledPolicy4805)
			wire.enroll(t)
			start := time.Now()
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, c.cmd), budgetEnv("8s", "load=30s")...)
			took := time.Since(start)
			t.Logf("%d KiB command answered after %s (Codex timeout 10s)", len(c.cmd)>>10, took)
			checkBudgetAnswerTime(t, took, 8*time.Second, 10*time.Second)
			if r.exit != 2 || r.decision != "BLOCK" {
				t.Fatalf("exit %d decision %s, want the managed fail_closed BLOCK (exit 2)", r.exit, r.decision)
			}
			for _, leak := range []string{tail4813, labelValue4805(), "abcdefghijklmn"} {
				if strings.Contains(r.line, leak) || strings.Contains(r.wireText(), leak) {
					t.Errorf("LEAK: %q in the line or the wire", leak)
				}
			}
			if c.withheld {
				checkRecord4805(t, r, "BLOCK", "withheld", true)
				if !strings.Contains(r.line, "too large to scrub before the harness timeout") || !strings.Contains(r.wireText(), "too large to scrub before the harness timeout") {
					t.Errorf("the %s note does not say the text was too large to scrub:\n%.2000s", withheldKind, r.line)
				}
				return
			}
			var e logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
				t.Fatalf("line: %v", err)
			}
			if e.Command != "export [REDACTED]" || fmt.Sprint(r.wire[0]["command"]) != "export [REDACTED]" {
				t.Errorf("line command %q, wire command %q, want both %q", e.Command, r.wire[0]["command"], "export [REDACTED]")
			}
			if strings.Contains(r.line+r.wireText(), withheldKind) {
				t.Errorf("a command small enough to scrub was withheld")
			}
		})
	}
}
