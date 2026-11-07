package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// codenameSpans finds the codename label, the keyword PHOENIX in that case:
// a real engine's Spans, the scrubber the hook attaches (#4813).
var codenameSpans = func() func(string) []datalabel.Span {
	e, err := datalabel.NewEngine([]datalabel.DataLabelConfig{{ID: "codename", Patterns: []datalabel.PatternConfig{{Keywords: []string{"PHOENIX"}, CaseSensitive: true}}}})
	if err != nil {
		panic(err)
	}
	return e.Spans
}()

// #4781: the hook redacts each event once and builds both its copies, the
// audit.jsonl line and the SaaS wire entry, from that one redaction. Before,
// LogLinked redacted its copy and auditWireEntry redacted the original again.
// The two bodies must be what the two redactions produced, byte for byte.

// redactOnceCorpus is real-shaped hook events: every analyzer corpus command
// as a shell event that quotes it in its reasons and error, secret-shaped
// text in every field the redactor reads, MCP events with nested arguments,
// events with notes and with a data-label scrubber.
func redactOnceCorpus() []logger.AuditEvent {
	pw := testPassword()
	secrets := []string{
		`curl -sS -H "Authorization: Bearer ` + testBearerToken() + `" https://api.example.com/v1/me`,
		"pg_dump postgres://app:" + pw + "@db.internal/stage",
		"curl -u admin:" + pw + " https://x",
		"echo pass" + "word=" + pw + " >> .env",
		"git push https://x:" + "ghp_" + strings.Repeat("a1", 18) + "@github.com/o/r",
		"export AWS_SECRET_ACCESS_KEY=" + strings.Repeat("Ab1/", 10),
		"TOKEN=" + strings.Repeat("t0k", 6) + " ./deploy.sh",
		"PHOENIX launch codes --token " + pw,
	}
	shell := func(cmd string) logger.AuditEvent {
		return logger.AuditEvent{
			Timestamp: "2026-11-05T00:00:00Z", Command: cmd, Args: strings.Fields(cmd), Cwd: "/repo",
			Decision: "BLOCK", Flagged: true, TriggeredRules: []string{failClosedRuleID},
			Reasons:      []string{"AgentShield: analysis failed — blocking (fail_closed enabled): " + cmd},
			TaxonomyRefs: []string{"a/b/c"}, Mode: "managed", Source: "codex-hook", SessionID: "s1", Principal: "u",
			Error: "analysis_budget_exceeded: no verdict for " + cmd,
			Notes: []logger.Note{{Kind: "analysis_budget_exceeded", Detail: "budget=8.951s; harness=codex"}},
		}
	}
	var out []logger.AuditEvent
	for _, s := range secrets {
		out = append(out, shell(s))
		out = append(out, shell(s).WithScrubber(codenameSpans))
		out = append(out, logger.AuditEvent{
			Timestamp: "2026-11-05T00:00:00Z", ToolName: "mcp__db__connect", Decision: "AUDIT", Source: "claude-code-mcp-hook",
			MCPArguments: map[string]interface{}{"dsn": s, "opts": map[string]interface{}{"list": []interface{}{s, 1.0}}},
			Reasons:      []string{"argument scan: " + s}, Error: s,
		})
	}
	for _, tc := range testdata.AllTestCases() {
		out = append(out, shell(tc.Command))
	}
	return out
}

// TestRedactOnce_HookRecordMatchesTwoRedactions: for every corpus event the
// hook's record (redactForRecord, then LogLinkedRedacted and
// auditWireEntryRedacted from the one result) writes the audit.jsonl line and
// builds the wire entry that LogLinked and auditWireEntry build from two
// redactions of the original, byte for byte, with the same chain links.
func TestRedactOnce_HookRecordMatchesTwoRedactions(t *testing.T) {
	if activeBudget != nil {
		t.Fatal("control: a budget is armed in the test process")
	}
	corpus := redactOnceCorpus()
	if len(corpus) < 5000 {
		t.Fatalf("corpus has %d events; the analyzer corpus did not load", len(corpus))
	}
	dir := t.TempDir()
	twicePath, oncePath := filepath.Join(dir, "twice.jsonl"), filepath.Join(dir, "once.jsonl")
	twice, err := logger.New(twicePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = twice.Close() }()
	once, err := logger.New(oncePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = once.Close() }()

	redacted := 0
	for i := range corpus {
		ev := corpus[i]
		before, _ := json.Marshal(ev)

		link1, err1 := twice.LogLinked(ev)
		wire1, _ := json.Marshal(auditWireEntry(&ev, "id-4781", auditLink{MachineID: "m-1", Chain: link1}))

		red := redactForRecord(&ev)
		link2, err2 := once.LogLinkedRedacted(red)
		wire2, _ := json.Marshal(auditWireEntryRedacted(red, "id-4781", auditLink{MachineID: "m-1", Chain: link2}))

		if err1 != nil || err2 != nil {
			t.Fatalf("event %d: log errors %v / %v", i, err1, err2)
		}
		if *link1 != *link2 {
			t.Fatalf("event %d: chain links differ: %+v vs %+v", i, *link1, *link2)
		}
		if !bytes.Equal(wire1, wire2) {
			t.Fatalf("event %d: wire entries differ:\ntwo redactions %s\none redaction  %s", i, wire1, wire2)
		}
		if after, _ := json.Marshal(ev); !bytes.Equal(before, after) {
			t.Fatalf("event %d: the record mutated the caller's event", i)
		}
		if strings.Contains(string(wire1), "[REDACTED]") {
			redacted++
		}
	}
	a, _ := os.ReadFile(twicePath)
	b, _ := os.ReadFile(oncePath)
	if !bytes.Equal(a, b) {
		t.Fatalf("audit.jsonl differs: %d bytes from two redactions, %d from one", len(a), len(b))
	}
	if strings.Contains(string(a), redactionCanary) {
		t.Fatal("a secret reached the line")
	}
	// Positive control: enough events carry text the redactor rewrites that
	// a record skipping or doubling a field's redaction would differ.
	if redacted < 20 {
		t.Fatalf("only %d wire entries carry [REDACTED]", redacted)
	}
	t.Logf("%d events, %d with redacted text; lines (%d bytes) and wire entries identical", len(corpus), redacted, len(a))
}

// TestRedactOnce_RecordRedactsExactlyOnce counts the redaction passes the
// hook's record makes, with a data-label scrubber as the counter (Redacted
// calls it once per field per pass, #4448). One pass for the line and the
// wire entry together. A record that redacted either copy again would write
// the same bytes on most text, which is why the equivalence test above cannot
// see it, and would cost the budget a second pass (#4781).
func TestRedactOnce_RecordRedactsExactlyOnce(t *testing.T) {
	calls := 0
	count := func(s string) []datalabel.Span { calls++; return nil }
	ev := redactOnceCorpus()[0].WithScrubber(count)

	_ = ev.Redacted()
	perPass := calls
	if perPass < 3 {
		t.Fatalf("control: one Redacted() pass called the scrubber %d times; the event carries too few fields to count", perPass)
	}

	calls = 0
	l, err := logger.New(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	red := redactForRecord(&ev)
	link, err := l.LogLinkedRedacted(red)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = json.Marshal(auditWireEntryRedacted(red, "id-4781", auditLink{Chain: link}))
	if calls != perPass {
		t.Errorf("the record called the scrubber %d times, %d passes; want one pass (%d calls)", calls, calls/perPass, perPass)
	}

	// The legacy pair, for contrast: LogLinked and auditWireEntry each redact.
	calls = 0
	link, _ = l.LogLinked(ev)
	_, _ = json.Marshal(auditWireEntry(&ev, "id-4781", auditLink{Chain: link}))
	if calls != 2*perPass {
		t.Errorf("control: LogLinked plus auditWireEntry made %d calls; want two passes (%d)", calls, 2*perPass)
	}
}
