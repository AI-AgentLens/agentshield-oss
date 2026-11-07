package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/facts"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/AI-AgentLens/agentshield/internal/psreader"
)

// #4805: the record never carries the value it stopped (#4448), on the
// fail-safe path too. failSafeReading built its event with no scrubber, so a
// customer data-label value in the command reached audit.jsonl and the SaaS
// payload on every fail-safe answer: the decision budget's, a config, log,
// policy or pack failure, engine init, a lane's panic.
//
// Each row drives one fail-safe path with a labelled value in the command and
// reads both copies of the record: the audit.jsonl line and the wire entry
// (the /api/audit body the hook uploads, captured by a local server with fake
// credentials, or buildAuditPayload where the path has no credentials to
// upload with). It asserts the decision, exit code and stdout main gives, and
// that neither copy carries the value: the line and the wire carry the
// [LABEL:<id>] placeholder, or, when the labels cannot be read, the withheld
// command and the agent_text_withheld note.
//
// The file uses no symbol #4805 added (the placeholder and note kind are
// spelled out), so the same file runs on main: there every row's leak and
// placeholder checks fail and its decision, exit-code and stdout checks pass.

const (
	labelID4805     = "customer-records"
	labelHolder4805 = "[LABEL:" + labelID4805 + "]"
	withheld4805    = "[WITHHELD]"
	withheldKind    = "agent_text_withheld"
)

// labelValue4805 is the value the label stops, assembled so this source is
// not itself a match.
func labelValue4805() string { return "CUST-" + "104" + "233" }

func labelCmd4805() string { return "echo " + labelValue4805() + " > notes.txt" }

const labelBlock4805 = `data_labels:
  - id: "customer-records"
    name: "Customer records"
    decision: "BLOCK"
    reason: "customer id in agent action"
    patterns:
      - regex: 'CUST-[0-9]{6}'
`

const (
	// labelledPolicy4805 loads cleanly and declares the label.
	labelledPolicy4805 = "version: \"0.1\"\ndefaults:\n  decision: \"AUDIT\"\nrules: []\n" + labelBlock4805
	// brokenElsewhere4805 fails the policy load (an unclosed flow list
	// after the block) with a data_labels block that reads on its own.
	brokenElsewhere4805 = "version: \"0.1\"\n" + labelBlock4805 + "rules: [\n"
	// brokenBlock4805 fails the load inside its data_labels block.
	brokenBlock4805 = "version: \"0.1\"\ndata_labels:\n  - id: \"customer-records\"\n    patterns: [\n"
	// uncompilable4805 loads, and its labels do not compile: engine init
	// fails on the second label's regex, and nothing can scrub the first.
	uncompilable4805 = labelledPolicy4805 + "  - id: \"broken-regex\"\n    decision: \"AUDIT\"\n    patterns:\n      - regex: '(unclosed'\n"
)

// wireCapture is a fake SaaS: it keeps every event POSTed to /api/audit.
type wireCapture struct {
	srv    *httptest.Server
	mu     sync.Mutex
	events []map[string]any
}

func newWireCapture(t *testing.T) *wireCapture {
	t.Helper()
	c := &wireCapture{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/audit" {
			body, _ := io.ReadAll(r.Body)
			var b struct {
				Events []map[string]any `json:"events"`
			}
			if json.Unmarshal(body, &b) == nil {
				c.mu.Lock()
				c.events = append(c.events, b.Events...)
				c.mu.Unlock()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

// enroll writes fake credentials for the capture server into HOME.
func (c *wireCapture) enroll(t *testing.T) {
	t.Helper()
	if err := auth.Save(&auth.Credentials{Server: c.srv.URL, Token: "test-agent-token"}); err != nil {
		t.Fatal(err)
	}
}

func (c *wireCapture) all() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.events...)
}

// record4805 is one row's outcome: the decision, the two copies, and the
// harness-facing answer when the row ran the hook in a child.
type record4805 struct {
	decision string
	line     string           // the raw audit.jsonl text; "" when no line was written
	wire     []map[string]any // the uploaded entries
	exit     int
	stdout   string
}

func (r record4805) wireText() string {
	b, _ := json.Marshal(r.wire)
	return string(b)
}

// checkRecord4805 asserts what every row asserts. want is "scrubbed" or
// "withheld"; wantLine says whether the path writes a local line at all.
func checkRecord4805(t *testing.T, r record4805, wantDecision, want string, wantLine bool) {
	t.Helper()
	value := labelValue4805()
	t.Logf("decision=%s exit=%d stdout=%q line_written=%v wire_entries=%d line_has_value=%v wire_has_value=%v",
		r.decision, r.exit, strings.TrimSpace(r.stdout), r.line != "", len(r.wire),
		strings.Contains(r.line, value), strings.Contains(r.wireText(), value))
	if r.decision != wantDecision {
		t.Errorf("decision %s, want %s (main's)", r.decision, wantDecision)
	}
	if (r.line != "") != wantLine {
		t.Errorf("local line written = %v, want %v (main's)", r.line != "", wantLine)
	}
	if len(r.wire) != 1 {
		t.Fatalf("%d wire entries, want 1", len(r.wire))
	}
	if strings.Contains(r.line, value) {
		t.Errorf("LEAK: the audit.jsonl line carries the label value:\n%s", r.line)
	}
	if strings.Contains(r.wireText(), value) {
		t.Errorf("LEAK: the wire entry carries the label value:\n%s", r.wireText())
	}
	w := r.wire[0]
	switch want {
	case "scrubbed":
		if !strings.Contains(fmt.Sprint(w["command"]), labelHolder4805) {
			t.Errorf("wire command %q, want the %s placeholder", w["command"], labelHolder4805)
		}
		if wantLine && !strings.Contains(r.line, labelHolder4805) {
			t.Errorf("line carries no %s placeholder:\n%s", labelHolder4805, r.line)
		}
		if strings.Contains(r.line+r.wireText(), withheldKind) {
			t.Errorf("a scrubbed record carries the %s note", withheldKind)
		}
	case "withheld":
		if w["command"] != withheld4805 || !strings.Contains(r.wireText(), withheldKind) {
			t.Errorf("wire entry %s, want command %s and a %s note", r.wireText(), withheld4805, withheldKind)
		}
		if wantLine {
			var e logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
				t.Fatalf("line: %v", err)
			}
			if e.Command != withheld4805 || len(e.Args) != 0 || countKind(e.Notes, withheldKind) != 1 {
				t.Errorf("line command %q args %q notes %v, want the withheld command, no args and one %s note", e.Command, e.Args, noteKinds(e.Notes), withheldKind)
			}
		}
	}
	// The rule id stays: the record still says why the call was decided.
	if rule := fmt.Sprint(w["rule_id"]); rule != failClosedRuleID && rule != evalErrorRuleID {
		t.Errorf("wire rule_id %q, want a fail-safe sentinel", rule)
	}
	if wantLine {
		// The line and the wire are one redaction (#4781): same command,
		// first reason and notes.
		var e logger.AuditEvent
		if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
			t.Fatalf("line: %v", err)
		}
		lineNotes, _ := json.Marshal(e.Notes)
		var notes []logger.Note
		raw, _ := json.Marshal(w["notes"])
		_ = json.Unmarshal(raw, &notes)
		wireNotes, _ := json.Marshal(notes)
		if e.Command != w["command"] || firstReason(e.Reasons) != w["reason"] || string(lineNotes) != string(wireNotes) {
			t.Errorf("line and wire disagree:\n line %q %q %s\n wire %q %q %s", e.Command, firstReason(e.Reasons), lineNotes, w["command"], w["reason"], wireNotes)
		}
	}
}

// runChild4805 runs the real hook entry point as Codex runs it, on a home
// prepared by the caller, and reads both copies of what it recorded.
func runChild4805(t *testing.T, home, configDir string, wire *wireCapture, payload string, env ...string) record4805 {
	t.Helper()
	code, stdout, stderr := runHookChild(t, home, payload, env...)
	r := record4805{exit: code, stdout: stdout, line: readFailSafeAuditLog(t, configDir), wire: wire.all()}
	if len(r.wire) > 0 {
		r.decision = fmt.Sprint(r.wire[0]["decision"])
	}
	if t.Failed() || r.decision == "" {
		t.Logf("child stderr:\n%s", stderr)
	}
	return r
}

func codexPayload4805(t *testing.T, cmd string) string {
	return claudeShaped(t, "PreToolUse", "Bash", routingCmd(cmd), map[string]interface{}{"turn_id": "turn-4805"})
}

// TestFailSafeRecord_DataLabelScrubbed_4805 is the per-path gate, through the
// hook as a harness runs it.
func TestFailSafeRecord_DataLabelScrubbed_4805(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the audit-log row needs file permission bits")
	}
	writePack := func(t *testing.T, configDir, name, body string) {
		t.Helper()
		p := filepath.Join(configDir, "packs", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct {
		name     string
		managed  bool
		policy   string
		setup    func(t *testing.T, configDir string)
		env      []string
		decision string // main's
		exit     int    // main's
		want     string // "scrubbed" or "withheld"
		line     bool   // main writes a local line
		detail   string // withheld: what the note must name
		reason   string // withheld: what the reason must also name
	}{
		// The load slow point holds the evaluation before it reads the
		// config, so the watchdog reads the labels itself.
		// The watchdog's own read decodes every pack whole (about 60 ms), so
		// these rows raise its bound: what they test is that the read
		// scrubs, not how fast this machine is. The bound itself is the
		// "too slow" row's and TestFailSafeRecord_BudgetLabelReadIsBounded_4805's.
		{name: "budget answer before the policy loaded, unmanaged", policy: labelledPolicy4805,
			env:      []string{envTestHookBudget + "=1ns", envTestHookSlow + "=load=8s", "AGENTSHIELD_TEST_HOOK_LABEL_LIMIT=30s"},
			decision: "AUDIT", exit: 0, want: "scrubbed", line: true},
		{name: "budget answer before the policy loaded, managed fail_closed", managed: true, policy: labelledPolicy4805,
			env:      []string{envTestHookBudget + "=1ns", envTestHookSlow + "=load=8s", "AGENTSHIELD_TEST_HOOK_LABEL_LIMIT=30s"},
			decision: "BLOCK", exit: 2, want: "scrubbed", line: true},
		// The evaluation loads the policy, publishes its labels, then sleeps
		// in its evaluate step; the watchdog answers with those labels. Its
		// own read would take past the limit (read-labels), so a scrubbed
		// record here can only come from the published set.
		{name: "budget answer after the policy loaded, managed fail_closed", managed: true, policy: labelledPolicy4805,
			env:      []string{envTestHookBudget + "=3s", envTestHookSlow + "=evaluate=8s,read-labels=5s"},
			decision: "BLOCK", exit: 2, want: "scrubbed", line: true},
		{name: "budget answer whose own label read is too slow", managed: true, policy: labelledPolicy4805,
			env: []string{envTestHookBudget + "=1ns", envTestHookSlow + "=load=8s,read-labels=5s"}, decision: "BLOCK", exit: 2, want: "withheld", line: true,
			detail: "took longer than 100ms"},
		{name: "policy load fails, data_labels block readable", managed: true, policy: brokenElsewhere4805,
			decision: "BLOCK", exit: 2, want: "scrubbed", line: true},
		{name: "policy load fails inside data_labels", policy: brokenBlock4805,
			decision: "AUDIT", exit: 0, want: "withheld", line: true, detail: "policy.yaml: data_labels does not parse"},
		{name: "audit log unwritable", managed: true, policy: labelledPolicy4805,
			setup: func(t *testing.T, configDir string) {
				p := filepath.Join(configDir, "audit.jsonl")
				if err := os.WriteFile(p, nil, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			}, decision: "BLOCK", exit: 2, want: "scrubbed", line: false},
		{name: "engine init fails on a rule", policy: failSafePolicyBadLabel + labelBlock4805,
			decision: "AUDIT", exit: 0, want: "scrubbed", line: true},
		// The packs directory is unreadable on an unmanaged host, so the
		// evaluation goes on without the disk packs (#4077) and records with
		// the labels that loaded, as the normal path does; engine init then
		// fails, and its record uses that same set.
		{name: "engine init fails after the packs fallback, unmanaged", policy: failSafePolicyBadLabel + labelBlock4805,
			setup: makePacksPathAFile, decision: "AUDIT", exit: 0, want: "scrubbed", line: true},
		{name: "engine init fails on the labels themselves", policy: uncompilable4805,
			decision: "AUDIT", exit: 0, want: "withheld", line: true, detail: "do not compile"},
		{name: "packs directory unreadable, managed fail_closed", managed: true, policy: labelledPolicy4805,
			setup: makePacksPathAFile, decision: "BLOCK", exit: 2, want: "withheld", line: true, detail: "packs: not a directory"},
		// Two reads failed: the audit log (the stage) and the packs directory
		// (the labels). The reason names both, in the file system's words.
		{name: "audit log unwritable and packs directory unreadable, managed fail_closed", managed: true, policy: labelledPolicy4805,
			setup: func(t *testing.T, configDir string) {
				makePacksPathAFile(t, configDir)
				p := filepath.Join(configDir, "audit.jsonl")
				if err := os.WriteFile(p, nil, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
			}, decision: "BLOCK", exit: 2, want: "withheld", line: false,
			detail: "packs: not a directory", reason: "audit.jsonl: permission denied"},
		// The pack's rules do not parse, so the full load drops it and its
		// label with it; its data_labels block still reads.
		{name: "a pack fails to parse, managed fail_closed, label in that pack", managed: true, policy: failSafePolicyGood,
			setup: func(t *testing.T, configDir string) {
				writePack(t, configDir, "team.yaml", "name: team\n"+labelBlock4805+"rules: [\n")
			}, decision: "BLOCK", exit: 2, want: "scrubbed", line: true},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, c.managed, c.policy)
			wire.enroll(t)
			if c.setup != nil {
				c.setup(t, configDir)
			}
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, labelCmd4805()), c.env...)
			if r.exit != c.exit || (c.exit == 0 && strings.TrimSpace(r.stdout) != "") {
				t.Errorf("exit %d stdout %q, want exit %d and no stdout (main's)", r.exit, r.stdout, c.exit)
			}
			checkRecord4805(t, r, c.decision, c.want, c.line)
			if c.want == "withheld" && (c.detail == "" || !strings.Contains(r.wireText(), c.detail)) {
				t.Errorf("the %s note does not name %q:\n%s", withheldKind, c.detail, r.wireText())
			}
			if c.reason != "" && (len(r.wire) != 1 || !strings.Contains(fmt.Sprint(r.wire[0]["reason"]), c.reason) ||
				strings.Contains(fmt.Sprint(r.wire[0]["reason"]), "data labels")) {
				t.Errorf("the reason does not name %q, or names the labels' own failure as the stage's (#4814 item 2):\n%s", c.reason, r.wireText())
			}
		})
	}
}

// TestFailSafeRecord_LanePanic_4805: a panic in the PowerShell lane is a
// fail-safe reading taken after the policy loaded, so it is scrubbed with the
// evaluation's labels. Driven in-process, because only this test binary can
// make the reader panic.
func TestFailSafeRecord_LanePanic_4805(t *testing.T) {
	prev := psRead
	psRead = func(string, psreader.Env) facts.Facts { panic("reader exploded") }
	t.Cleanup(func() { psRead = prev })
	for _, c := range []struct {
		managed, packsFallback bool
	}{{false, false}, {true, false}, {false, true}} {
		managed := c.managed
		t.Run(fmt.Sprintf("managed=%v packs fallback=%v", c.managed, c.packsFallback), func(t *testing.T) {
			wire := newWireCapture(t)
			_, configDir := newFailSafeHome(t, managed, labelledPolicy4805)
			wire.enroll(t)
			if c.packsFallback {
				// Unmanaged with an unreadable packs directory: evaluation
				// goes on without the disk packs, and the panic's record
				// uses the labels that loaded, as the normal path would.
				makePacksPathAFile(t, configDir)
			}
			reading := readPowerShell("Write-Output "+labelValue4805(), t.TempDir(), "claude-code-hook", "s", nil)
			reading.record(nil)
			want := "AUDIT"
			if managed {
				want = "BLOCK"
			}
			r := record4805{decision: string(reading.result.Decision), line: readFailSafeAuditLog(t, configDir), wire: wire.all()}
			if !strings.Contains(reading.event.Error, "panicked") {
				t.Fatalf("control: event error %q; the lane did not panic", reading.event.Error)
			}
			checkRecord4805(t, r, want, "scrubbed", true)
		})
	}
}

// TestFailSafeRecord_ConfigLoad_4805: config.Load fails before it reads
// anything. That record has no local line (no log path) and no credentials
// to upload with on a real host, so its wire entry is read with
// buildAuditPayload, from the event the hook returns.
func TestFailSafeRecord_ConfigLoad_4805(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("needs a directory the user cannot write")
	}
	payload := func(t *testing.T, ev *logger.AuditEvent) record4805 {
		t.Helper()
		body, err := buildAuditPayload(ev, "")
		if err != nil {
			t.Fatal(err)
		}
		var b struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal(body, &b); err != nil {
			t.Fatal(err)
		}
		return record4805{decision: ev.Decision, wire: b.Events}
	}

	// The config directory cannot be created; --policy names a labelled
	// policy elsewhere, which the evaluation would have loaded.
	t.Run("config dir cannot be created, labels in the --policy file", func(t *testing.T) {
		newFailSafeHome(t, false, "")
		ro := filepath.Join(t.TempDir(), "ro")
		if err := os.MkdirAll(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })
		t.Setenv("HOME", filepath.Join(ro, "home"))
		labelled := filepath.Join(t.TempDir(), "policy.yaml")
		if err := os.WriteFile(labelled, []byte(labelledPolicy4805), 0o600); err != nil {
			t.Fatal(err)
		}
		policyPath = labelled
		result, ev := evaluateCommand(labelCmd4805(), "/tmp", "cursor-hook", "")
		if !strings.Contains(ev.Error, "permission denied") {
			t.Fatalf("control: error %q; config.Load did not fail on the config directory", ev.Error)
		}
		checkRecord4805(t, payload(t, ev), "AUDIT", "scrubbed", false)
		if result.Decision != policy.DecisionAudit {
			t.Errorf("decision %s, want AUDIT (main's)", result.Decision)
		}
	})

	// No home directory: nothing says where the labels live.
	t.Run("no home directory", func(t *testing.T) {
		newFailSafeHome(t, false, "")
		t.Setenv("HOME", "")
		result, ev := evaluateCommand(labelCmd4805(), "/tmp", "cursor-hook", "")
		if !strings.Contains(ev.Error, "HOME") {
			t.Fatalf("control: error %q; config.Load did not fail on the home directory", ev.Error)
		}
		rec := payload(t, ev)
		checkRecord4805(t, rec, "AUDIT", "withheld", false)
		if !strings.Contains(rec.wireText(), "the home directory is unknown") {
			t.Errorf("the %s note does not say the home directory is unknown:\n%s", withheldKind, rec.wireText())
		}
		if result.Decision != policy.DecisionAudit {
			t.Errorf("decision %s, want AUDIT (main's)", result.Decision)
		}
	})
}

// TestFailSafeRecord_ToolCallBudgetIsNotScrubbed_4805 pins a gap #4805 left
// as it is: a tool call only MCP policy reads records its arguments
// unscrubbed, on the normal path (#4448: "the hook's MCP path, which
// evaluates no data labels") and so on its fail-safe path. Closing it is a
// change to the normal path's record, Gary's call; this row makes that
// change deliberate.
func TestFailSafeRecord_ToolCallBudgetIsNotScrubbed_4805(t *testing.T) {
	wire := newWireCapture(t)
	home, configDir := newFailSafeHome(t, false, labelledPolicy4805)
	wire.enroll(t)
	payload := claudeShaped(t, "PreToolUse", "mcp__notes__append", map[string]interface{}{"text": labelValue4805()}, map[string]interface{}{"turn_id": "turn-4805"})
	r := runChild4805(t, home, configDir, wire, payload, envTestHookBudget+"=1ns")
	if r.exit != 0 || len(r.wire) != 1 || r.wire[0]["decision"] != "AUDIT" || len(budgetNotes(oneEvent(t, configDir).Notes)) != 1 {
		t.Fatalf("control: exit %d, wire %s; want the budget's AUDIT of the tool call", r.exit, r.wireText())
	}
	if !strings.Contains(r.line, labelValue4805()) || !strings.Contains(r.wireText(), labelValue4805()) {
		t.Errorf("the tool call's arguments were scrubbed or dropped; if that was deliberate, update #4448's 'not covered' and this test:\nline %s\nwire %s", r.line, r.wireText())
	}
}

// TestFailSafeRecord_BudgetLabelReadIsBounded_4805: when the watchdog has to
// read the labels itself and the read is slow, the answer does not wait for
// it: a BLOCK lands within the bound plus the ordinary tail.
func TestFailSafeRecord_BudgetLabelReadIsBounded_4805(t *testing.T) {
	wire := newWireCapture(t)
	home, configDir := newFailSafeHome(t, true, labelledPolicy4805)
	wire.enroll(t)
	start := time.Now()
	r := runChild4805(t, home, configDir, wire, codexPayload4805(t, labelCmd4805()), envTestHookBudget+"=1ns", envTestHookSlow+"=load=30s,read-labels=20s")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("the answer took %s: the watchdog waited on its label read", elapsed)
	}
	if r.exit != 2 {
		t.Fatalf("exit %d, want the BLOCK", r.exit)
	}
	checkRecord4805(t, r, "BLOCK", "withheld", true)
}

// TestFailSafeRecord_HookInputFailureHasNoAgentText_4805: the one fail-safe
// reading with no command records a placeholder. A malformed payload carrying
// a label value never put the value in the record, on main or here; the
// label read runs and changes nothing.
func TestFailSafeRecord_HookInputFailureHasNoAgentText_4805(t *testing.T) {
	wire := newWireCapture(t)
	home, configDir := newFailSafeHome(t, false, labelledPolicy4805)
	wire.enroll(t)
	r := runChild4805(t, home, configDir, wire, `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo `+labelValue4805())
	if r.exit != 0 || len(r.wire) != 1 || r.wire[0]["command"] != "<unparseable hook input>" {
		t.Fatalf("control: exit %d wire %s; want the input failure's AUDIT", r.exit, r.wireText())
	}
	if strings.Contains(r.line+r.wireText(), labelValue4805()) || strings.Contains(r.line+r.wireText(), withheldKind) {
		t.Errorf("record changed: line %s wire %s", r.line, r.wireText())
	}
}

// TestFailSafeRecord_NoLabelsIsUnchanged_4805: on a host with no data labels
// the label read finds none and the fail-safe event carries neither a
// scrubber nor a withheld mark, so its record is the one main wrote. A copy
// of the event made through JSON (which drops both) must redact to the same
// thing. Control: with labels the two differ.
func TestFailSafeRecord_NoLabelsIsUnchanged_4805(t *testing.T) {
	cmd := "echo " + labelValue4805() + " > notes.txt"
	roundTrip := func(t *testing.T, ev *logger.AuditEvent) logger.AuditEvent {
		t.Helper()
		b, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		var plain logger.AuditEvent
		if err := json.Unmarshal(b, &plain); err != nil {
			t.Fatal(err)
		}
		return plain
	}
	same := func(t *testing.T, ev *logger.AuditEvent) bool {
		t.Helper()
		a, _ := json.Marshal(ev.Redacted())
		b, _ := json.Marshal(roundTrip(t, ev).Redacted())
		return string(a) == string(b)
	}
	for _, c := range []struct {
		name, noLabels, withLabels string
		setup                      func(t *testing.T, configDir string)
	}{
		{"policy load", "rules: [\n", brokenElsewhere4805, nil},
		{"engine init", failSafePolicyBadLabel, failSafePolicyBadLabel + labelBlock4805, nil},
		{"audit log init", failSafePolicyGood, labelledPolicy4805, func(t *testing.T, configDir string) {
			p := filepath.Join(configDir, "audit.jsonl")
			if err := os.WriteFile(p, nil, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(p, 0o600) })
		}},
		{"pack parse, managed", failSafePolicyGood, labelledPolicy4805, func(t *testing.T, configDir string) {
			if err := os.MkdirAll(filepath.Join(configDir, "packs"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(configDir, "packs", "team.yaml"), []byte("name: team\nrules: [\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if os.Geteuid() == 0 && c.setup != nil {
				t.Skip("needs file permission bits")
			}
			for _, labelled := range []bool{false, true} {
				policyYAML := c.noLabels
				if labelled {
					policyYAML = c.withLabels
				}
				_, configDir := newFailSafeHome(t, c.name == "pack parse, managed", policyYAML)
				if c.setup != nil {
					c.setup(t, configDir)
				}
				result, ev := evaluateCommand(cmd, "/tmp", "cursor-hook", "")
				if !containsStr(result.TriggeredRules, evalErrorRuleID) && !containsStr(result.TriggeredRules, failClosedRuleID) {
					t.Fatalf("control: rules %v; the stage did not fail", result.TriggeredRules)
				}
				if got := same(t, ev); got == labelled {
					t.Errorf("labels=%v: record unchanged by the label read = %v, want %v", labelled, got, !labelled)
				}
			}
		})
	}
}

// shortKeyword4805 is a codename-shaped keyword short enough that yaml.v3
// quotes it whole in a type error (it cuts a longer scalar to 7 characters
// and "...").
func shortKeyword4805() string { return "OSP" + "REY" }

// TestFailSafeRecord_FailureTextQuotingALabel_IsWithheld_4805 (Gary,
// 2026-11-06): when the record withholds the agent text, the reason and the
// error withhold what the failure quoted too. A policy load broken inside
// data_labels quotes the scalar it choked on, and an engine init failed on a
// label quotes its pattern; either can be the customer's codename. Both
// copies keep the decision, rule id, mode and identity, and say which source
// failed and how, in AgentShield's words only.
func TestFailSafeRecord_FailureTextQuotingALabel_IsWithheld_4805(t *testing.T) {
	keyword := shortKeyword4805()
	for _, c := range []struct {
		name, policy, stage, source string
		managed                     bool
		decision                    string
		exit                        int
	}{
		{"policy load, keyword as a scalar, unmanaged",
			"version: \"0.1\"\ndata_labels:\n  - id: \"customer-records\"\n    patterns:\n      - keywords: " + keyword + "\n",
			"policy load", "policy.yaml: data_labels does not parse", false, "AUDIT", 0},
		{"policy load, keyword as a scalar, managed fail_closed",
			"version: \"0.1\"\ndata_labels:\n  - id: \"customer-records\"\n    patterns:\n      - keywords: " + keyword + "\n",
			"policy load", "policy.yaml: data_labels does not parse", true, "BLOCK", 2},
		{"engine init, keyword in a pattern that does not compile",
			labelledPolicy4805 + "  - id: \"codename\"\n    decision: \"BLOCK\"\n    patterns:\n      - regex: '" + keyword + "('\n",
			"engine init", "do not compile", false, "AUDIT", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, c.managed, c.policy)
			wire.enroll(t)
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, "echo "+keyword))
			if r.exit != c.exit || len(r.wire) != 1 || r.decision != c.decision {
				t.Fatalf("exit %d, %d wire entries, decision %s; want main's %s, exit %d", r.exit, len(r.wire), r.decision, c.decision, c.exit)
			}
			if r.wire[0]["command"] != withheld4805 || !strings.Contains(r.wireText(), withheldKind) {
				t.Fatalf("control: wire %s; want the withheld command and its note", r.wireText())
			}
			if strings.Contains(r.line, keyword) || strings.Contains(r.wireText(), keyword) {
				t.Errorf("LEAK: the record carries the keyword:\nline %s\nwire %s", r.line, r.wireText())
			}
			var e logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
				t.Fatalf("line: %v", err)
			}
			// The stage failed on text it would quote, so its cause is
			// withheld (#4814 item 2); the note says which source of labels
			// failed and how.
			for _, field := range append(append([]string{e.Error}, e.Reasons...), fmt.Sprint(r.wire[0]["reason"])) {
				if !strings.HasSuffix(field, "(cause withheld)") {
					t.Errorf("%q: want the cause withheld", field)
				}
			}
			if n := e.Notes[len(e.Notes)-1]; n.Kind != withheldKind || !strings.Contains(n.Detail, c.source) {
				t.Errorf("note %+v does not say which source failed and how (%q)", n, c.source)
			}
			wording := "evaluated as AUDIT (fail-safe default, not enforced)"
			if c.decision == "BLOCK" {
				wording = "blocking (fail_closed enabled)"
			}
			if !strings.HasPrefix(firstReason(e.Reasons), "AgentShield: "+c.stage+" failed — "+wording+": ") {
				t.Errorf("reason %q, want the stage and the decision's wording", firstReason(e.Reasons))
			}
			// What stays: the decision's record and the identity.
			if e.Decision != c.decision || fmt.Sprint(r.wire[0]["rule_id"]) != e.TriggeredRules[0] ||
				e.Source != "codex-hook" || e.SessionID != "route-char" || e.Principal == "" {
				t.Errorf("a kept field changed: %+v", e)
			}
			checkRecord4805(t, r, c.decision, "withheld", true)
		})
	}
}

// utf16Policy4805 encodes a policy as Windows Notepad saves "Unicode" (LE)
// or "Unicode big endian" (BE), with a byte-order mark.
func utf16Policy4805(text string, bigEndian bool) []byte {
	out := []byte{0xFF, 0xFE}
	if bigEndian {
		out = []byte{0xFE, 0xFF}
	}
	for _, r := range text {
		c := uint16(r) // every rune of these policies is in the BMP
		if bigEndian {
			out = append(out, byte(c>>8), byte(c))
		} else {
			out = append(out, byte(c), byte(c>>8))
		}
	}
	return out
}

func utf32Policy4805(text string) []byte {
	out := []byte{0xFF, 0xFE, 0, 0}
	for _, r := range text {
		out = append(out, byte(r), byte(r>>8), byte(r>>16), byte(r>>24))
	}
	return out
}

// TestFailSafeRecord_CodexRound_4805 holds the second round's findings to
// the hook as a harness runs it. Codex F1: the label read missed labels a
// valid YAML encoding or spelling declares (UTF-16 with a byte-order mark, an
// escaped key, a U+2028 line break), so the record carried the value,
// neither scrubbed nor withheld. Codex F2: a withheld record kept note
// details and a working directory taken from the payload, which can quote
// the value. Each row: no value anywhere in the line or the wire entry,
// scrubbed or withheld, and main's decision, exit code and stdout. The file
// still uses no symbol #4805 added, so it runs on main and on the first
// round's head, where these rows leak.
func TestFailSafeRecord_CodexRound_4805(t *testing.T) {
	value := labelValue4805()
	brokenRule := "rules:\n  - id: broken\n    match: {command_regex: \"x\"\n"
	labelled := "version: \"0.1\"\n" + labelBlock4805
	escaped := "version: \"0.1\"\n" + strings.Replace(labelBlock4805, "data_labels:", "\"data\\x5flabels\":", 1)
	lineSep := "version: \"0.1\"\ndata_labels:\n  - id: \"first\"\n    decision: \"AUDIT\"\n    patterns:\n      - keywords: [\"ZQXJ\"]\n" +
		"   - id: \"customer-records\"\n    decision: \"BLOCK\"\n    patterns:\n      - regex: 'CUST-[0-9]{6}'\nrules: []\n"
	before := []string{envTestHookBudget + "=1ns", envTestHookSlow + "=load=8s", "AGENTSHIELD_TEST_HOOK_LABEL_LIMIT=30s"}
	type row struct {
		name     string
		managed  bool
		policy   []byte
		setup    func(t *testing.T, home, configDir string)
		cwd      func(home string) string
		tool     string // "Bash" (Codex) or "Monitor" (Claude Code)
		env      []string
		decision string
		exit     int
		want     string
		kinds    []string // withheld: the note kinds, in order (kinds stay)
	}
	relativeCwd := func(string) string { return value }
	rows := []row{
		// F1: encodings and spellings yaml.v3 reads.
		{name: "UTF-16 LE policy with a broken rule", managed: true, policy: utf16Policy4805(labelled+brokenRule, false),
			decision: "BLOCK", exit: 2, want: "withheld"},
		{name: "UTF-16 BE policy with a broken rule", policy: utf16Policy4805(labelled+brokenRule, true),
			decision: "AUDIT", exit: 0, want: "withheld"},
		{name: "UTF-16 LE policy, budget answer before the policy loaded", policy: utf16Policy4805(labelled+"rules: []\n", false),
			env: before, decision: "AUDIT", exit: 0, want: "scrubbed"},
		{name: "UTF-32 policy (yaml.v3 reads none)", policy: utf32Policy4805(labelled + "rules: []\n"),
			decision: "AUDIT", exit: 0, want: "withheld"},
		{name: "escaped key, budget answer before the policy loaded", managed: true, policy: []byte(escaped + "rules: []\n"),
			env: before, decision: "BLOCK", exit: 2, want: "scrubbed"},
		{name: "escaped key with a broken rule", policy: []byte(escaped + brokenRule),
			decision: "AUDIT", exit: 0, want: "withheld"},
		{name: "U+2028 inside the block, budget answer before the policy loaded", policy: []byte(lineSep),
			env: before, decision: "AUDIT", exit: 0, want: "scrubbed"},
		// F2: payload-derived text on a withheld record.
		{name: "relative payload cwd naming the value, lock unopenable", managed: true, policy: []byte(brokenBlock4805),
			setup: func(t *testing.T, home, configDir string) {
				if err := os.Mkdir(filepath.Join(configDir, "audit.jsonl.lock"), 0o700); err != nil {
					t.Fatal(err)
				}
			}, cwd: relativeCwd, decision: "BLOCK", exit: 2, want: "withheld",
			kinds: []string{"payload_cwd_unusable", withheldKind, "audit_lock_unavailable"}},
		{name: "relative payload cwd naming the value, budget answer", policy: []byte(brokenBlock4805),
			cwd: relativeCwd, env: []string{envTestHookBudget + "=1ns", envTestHookSlow + "=load=8s"},
			decision: "AUDIT", exit: 0, want: "withheld",
			kinds: []string{"payload_cwd_unusable", "analysis_budget_exceeded", withheldKind}},
		{name: "relative payload cwd naming the value, Monitor's POSIX lane kept", managed: true, policy: []byte(uncompilable4805),
			cwd: relativeCwd, tool: "Monitor", decision: "BLOCK", exit: 2, want: "withheld",
			kinds: []string{"payload_cwd_unusable", withheldKind, "lane_readings"}},
		{name: "absolute payload cwd naming the value", policy: []byte(brokenBlock4805),
			cwd: func(home string) string {
				d := filepath.Join(home, "work", value)
				if err := os.MkdirAll(d, 0o700); err != nil {
					t.Fatal(err)
				}
				return d
			}, decision: "AUDIT", exit: 0, want: "withheld",
			kinds: []string{withheldKind}},
	}
	for _, c := range rows {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, c.managed, "")
			if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), c.policy, 0o600); err != nil {
				t.Fatal(err)
			}
			wire.enroll(t)
			if c.setup != nil {
				c.setup(t, home, configDir)
			}
			extra := map[string]interface{}{"turn_id": "turn-4805"}
			tool, input := "Bash", interface{}(routingCmd(labelCmd4805()))
			if c.tool == "Monitor" {
				extra = map[string]interface{}{}
				tool, input = "Monitor", monitorInput(labelCmd4805())
			}
			if c.cwd != nil {
				extra["cwd"] = c.cwd(home)
			}
			r := runChild4805(t, home, configDir, wire, claudeShaped(t, "PreToolUse", tool, input, extra), c.env...)
			if r.exit != c.exit || strings.TrimSpace(r.stdout) != "" {
				t.Errorf("exit %d stdout %q, want exit %d and no stdout (main's)", r.exit, r.stdout, c.exit)
			}
			checkRecord4805(t, r, c.decision, c.want, true)
			if c.kinds == nil || len(r.wire) != 1 {
				return
			}
			var e logger.AuditEvent
			if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
				t.Fatalf("line: %v", err)
			}
			if fmt.Sprint(noteKinds(e.Notes)) != fmt.Sprint(c.kinds) {
				t.Errorf("note kinds %v, want %v (kinds stay)", noteKinds(e.Notes), c.kinds)
			}
			if strings.Contains(e.Cwd, value) || strings.Contains(fmt.Sprint(r.wire[0]["cwd"]), value) {
				t.Errorf("cwd %q / %v carries the value", e.Cwd, r.wire[0]["cwd"])
			}
		})
	}
}
