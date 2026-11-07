package cli

// #4818 (Gary, 2026-11-06): an evaluation's own record, like the budget's
// answer, withholds a labelled command it could not scrub before the harness
// timeout (withholdIfTooSlow), and says so when it starts within the exit
// guard of that timeout (markLate's late_answer note).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/route"
)

// valueScrubber finds every occurrence of the #4805 label value, as the
// labelled policy's engine would.
func valueScrubber(s string) []datalabel.Span {
	v := labelValue4805()
	var spans []datalabel.Span
	for i := 0; ; {
		j := strings.Index(s[i:], v)
		if j < 0 {
			return spans
		}
		spans = append(spans, datalabel.Span{Start: i + j, End: i + j + len(v), Label: "customer-records"})
		i += j + len(v)
	}
}

// TestWithholdIfTooSlow_4818 is the decision. An evaluation's labelled
// record is withheld only when its command would not scrub at
// budgetScrubCostPerKiB in the time left before the timeout less the exit
// guard. The watchdog's record, an event with no scrubber and a nil budget
// are left alone. A withheld record keeps its reasons, masked, its rules and
// its decision.
func TestWithholdIfTooSlow_4818(t *testing.T) {
	value := labelValue4805()
	kib := 1 << 10
	big := strings.Repeat("ticket "+value+" notes ", 300*kib/25)
	labelled := logger.AuditEvent{
		Command: "echo '" + big + "'", Args: []string{"echo", big}, Cwd: "/work",
		Decision: "BLOCK", TriggeredRules: []string{"dl-customer-records"},
		Reasons: []string{"customer id in agent action: " + value},
	}.WithScrubber(valueScrubber)
	plain := logger.AuditEvent{Command: labelled.Command, Decision: "AUDIT"}
	evaluation := &hookBudget{owner: budgetEvaluation, timeout: 10 * time.Second}
	watchdog := &hookBudget{owner: budgetWatchdog, timeout: 10 * time.Second}
	size := len(labelled.Command)
	edge := 10*time.Second - hookAnswerExitGuard - time.Duration(size)*budgetScrubCostPerKiB/1024

	for _, c := range []struct {
		name     string
		b        *hookBudget
		e        logger.AuditEvent
		elapsed  time.Duration
		withheld bool
	}{
		{"evaluation, labelled, past what is left", evaluation, labelled, edge + time.Millisecond, true},
		{"evaluation, labelled, exactly what is left", evaluation, labelled, edge, false},
		{"evaluation, labelled, early", evaluation, labelled, time.Second, false},
		{"evaluation, no scrubber, at the timeout", evaluation, plain, 10 * time.Second, false},
		{"watchdog, labelled, at the timeout (its answer checks for itself)", watchdog, labelled, 10 * time.Second, false},
		{"no budget armed", nil, labelled, 10 * time.Second, false},
		{"no known harness timeout (only the test override arms one)", &hookBudget{owner: budgetEvaluation}, labelled, 10 * time.Second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := c.e
			got := c.b.withholdIfTooSlow(&e, c.elapsed)
			r := got.Redacted()
			if !c.withheld {
				if got != &e {
					t.Fatalf("the event was replaced; want it unchanged")
				}
				return
			}
			if r.Command != logger.WithheldText || len(r.Args) != 0 || r.Cwd != logger.WithheldText {
				t.Errorf("command %q args %q cwd %q, want the agent text withheld", r.Command, r.Args, r.Cwd)
			}
			if countKind(r.Notes, logger.NoteAgentTextWithheld) != 1 {
				t.Fatalf("notes %v, want one %s note", noteKinds(r.Notes), logger.NoteAgentTextWithheld)
			}
			for _, n := range r.Notes {
				if n.Kind == logger.NoteAgentTextWithheld && !strings.Contains(n.Detail, "too large to scrub before the harness timeout") {
					t.Errorf("detail %q does not say why", n.Detail)
				}
			}
			want := "customer id in agent action: [LABEL:customer-records]"
			if len(r.Reasons) != 1 || r.Reasons[0] != want {
				t.Errorf("reasons %q, want the rule's own reason with the value masked: %q", r.Reasons, want)
			}
			if r.Decision != "BLOCK" || strings.Join(r.TriggeredRules, ",") != "dl-customer-records" {
				t.Errorf("decision %s rules %v, want the evaluation's", r.Decision, r.TriggeredRules)
			}
			raw, _ := json.Marshal(r)
			if strings.Contains(string(raw), value) {
				t.Errorf("LEAK: the withheld record carries the label value: %.400s", raw)
			}
			// The caller's event is the caller's: only the record withholds.
			if e.Command != c.e.Command || countKind(e.Notes, logger.NoteAgentTextWithheld) != 0 {
				t.Errorf("withholdIfTooSlow modified its input")
			}
		})
	}
}

// TestHookBudget_MarkLate_Evaluation_4818: an evaluation's record that starts
// within the exit guard of the timeout gets a late_answer note naming the
// harness; earlier it is untouched. The notes it already had are kept as
// they were.
func TestHookBudget_MarkLate_Evaluation_4818(t *testing.T) {
	ev := logger.AuditEvent{Command: "echo hi", Decision: "BLOCK", Notes: []logger.Note{{Kind: analyzer.NoteExcused, Rule: "r", Detail: "d"}}}
	red := ev.RedactOnce()
	b := &hookBudget{owner: budgetEvaluation, timeout: 10 * time.Second, call: budgetCall{harness: route.Codex}}
	onTime := 10*time.Second - hookAnswerExitGuard - time.Millisecond
	if got := b.markLate(red, onTime).Event(); fmt.Sprint(got.Notes) != fmt.Sprint(red.Event().Notes) {
		t.Errorf("on time: notes changed: %v", got.Notes)
	}
	// No known harness timeout (only the test override arms such a call): never late.
	if got := (&hookBudget{owner: budgetEvaluation}).markLate(red, time.Hour).Event(); fmt.Sprint(got.Notes) != fmt.Sprint(red.Event().Notes) {
		t.Errorf("no known timeout: notes changed: %v", got.Notes)
	}
	for _, at := range []time.Duration{10*time.Second - hookAnswerExitGuard, 10 * time.Second, 11 * time.Second} {
		got := b.markLate(red, at).Event()
		if len(got.Notes) != 2 || got.Notes[0] != red.Event().Notes[0] {
			t.Fatalf("at %s: notes %v, want the old note then late_answer", at, got.Notes)
		}
		verdict := "possible"
		if at >= 10*time.Second {
			verdict = "true"
		}
		want := logger.Note{Kind: analyzer.NoteLateAnswer, Detail: fmt.Sprintf(
			"answered_after_harness_timeout=%s; recorded_at=%s; harness=%s; harness_timeout=10s; exit_guard=%s",
			verdict, at.Truncate(time.Millisecond), route.Codex, hookAnswerExitGuard)}
		if got.Notes[1] != want {
			t.Errorf("at %s:\n got %+v\nwant %+v", at, got.Notes[1], want)
		}
		if got.Command != red.Event().Command || got.Decision != "BLOCK" {
			t.Errorf("at %s: the record's fields changed", at)
		}
	}
	// On a withheld record the note keeps its detail: it is AgentShield's own text.
	withheld := logger.AuditEvent{Command: "echo hi", Decision: "BLOCK"}.WithScrubber(valueScrubber).
		WithAgentTextWithheld(logger.Withheld{Detail: "x", KeepFailureText: true}).RedactOnce()
	got := b.markLate(withheld, 10*time.Second).Event()
	if n := got.Notes[len(got.Notes)-1]; n.Kind != analyzer.NoteLateAnswer || !strings.HasPrefix(n.Detail, "answered_after_harness_timeout=true") {
		t.Errorf("withheld record's late note %+v, want its detail kept", n)
	}
}

// evalRecord4818 reads one evaluation-path record's two copies.
type evalRecord4818 struct {
	line logger.AuditEvent
	wire map[string]any
}

func readEvalRecord4818(t *testing.T, r record4805) evalRecord4818 {
	t.Helper()
	if len(r.wire) != 1 {
		t.Fatalf("%d wire entries, want 1", len(r.wire))
	}
	var e logger.AuditEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(r.line)), &e); err != nil {
		t.Fatalf("line: %v\n%.400s", err, r.line)
	}
	if e.Command != r.wire[0]["command"] || firstReason(e.Reasons) != r.wire[0]["reason"] {
		t.Errorf("line and wire disagree: %q %q vs %q %q", e.Command, firstReason(e.Reasons), r.wire[0]["command"], r.wire[0]["reason"])
	}
	return evalRecord4818{line: e, wire: r.wire[0]}
}

// TestEvalRecord_TooLargeToScrub_Withheld_4818 runs the hook as Codex does on
// an enrolled host with data labels. The evaluation decides the call inside
// its budget, and the test-only before-redact slow point then holds its
// record for 8 s, which leaves at most 0.6 s before the exit guard: less than
// a 96 KiB command takes to scrub at budgetScrubCostPerKiB (0.77 s), however
// fast the evaluation was, and a slower one only leaves less. The record
// withholds the agent text and keeps the evaluation's decision and rule.
// Controls: a small labelled command held 7 s is scrubbed (it needs well
// under a millisecond of the 1.6 s left, less the evaluation's time), and on
// a host with no labels the large command is recorded as written. On main
// the slow point does not exist and the large row is scrubbed, so that row
// fails there. Wall time is logged, not asserted: on a CI runner shared with
// another Test job this hook child answered at 10.17 s (main CI on 0d814db3),
// the load's cost, not the record's. That the answer lands in time is the
// budget test's and the #4818 box measurement's to show.
func TestEvalRecord_TooLargeToScrub_Withheld_4818(t *testing.T) {
	if testing.Short() {
		t.Skip("holds each record for 8 s")
	}
	value := labelValue4805()
	big := "echo '" + strings.Repeat("ticket "+value+" notes ", (96<<10)/25) + "' > notes.txt"
	for _, c := range []struct {
		name, policy, cmd string
		hold              string // the before-redact slow point
		want              string // "withheld", "scrubbed" or "verbatim"
	}{
		{"labelled, 96 KiB", labelledPolicy4805, big, "8s", "withheld"},
		{"labelled, small (control)", labelledPolicy4805, labelCmd4805(), "7s", "scrubbed"},
		{"no labels, 96 KiB (control)", failSafePolicyGood, big, "8s", "verbatim"},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, false, c.policy)
			wire.enroll(t)
			start := time.Now()
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, c.cmd), budgetEnv("7s", "before-redact="+c.hold)...)
			t.Logf("%d KiB command answered after %s (Codex timeout 10s)", len(c.cmd)>>10, time.Since(start))
			rec := readEvalRecord4818(t, r)
			raw := r.line + r.wireText()
			if strings.Contains(raw, analyzer.NoteAnalysisBudgetExceeded) {
				t.Fatalf("the budget answered; this row needs the evaluation's own record")
			}
			if c.want != "verbatim" {
				if r.exit != 2 || r.decision != "BLOCK" || fmt.Sprint(rec.wire["rule_id"]) != "dl-customer-records" {
					t.Errorf("exit %d decision %s rule %v, want the evaluation's BLOCK dl-customer-records", r.exit, r.decision, rec.wire["rule_id"])
				}
				if strings.Contains(raw, value) {
					t.Errorf("LEAK: the record carries the label value")
				}
			}
			switch c.want {
			case "withheld":
				if rec.line.Command != withheld4805 || len(rec.line.Args) != 0 || countKind(rec.line.Notes, withheldKind) != 1 {
					t.Errorf("line command %.60q args %d notes %v, want the command withheld with one %s note", rec.line.Command, len(rec.line.Args), noteKinds(rec.line.Notes), withheldKind)
				}
				if !strings.Contains(raw, "too large to scrub before the harness timeout") {
					t.Errorf("the %s note does not say the text was too large to scrub", withheldKind)
				}
				if !strings.Contains(firstReason(rec.line.Reasons), "customer id in agent action") {
					t.Errorf("reason %q, want the label's own reason", firstReason(rec.line.Reasons))
				}
			case "scrubbed":
				if !strings.Contains(rec.line.Command, labelHolder4805) || strings.Contains(raw, withheldKind) {
					t.Errorf("line command %q, want it scrubbed and not withheld", rec.line.Command)
				}
			case "verbatim":
				if rec.line.Command != c.cmd || strings.Contains(raw, withheldKind) {
					t.Errorf("a no-label host's command was not recorded as written (%d bytes, want %d)", len(rec.line.Command), len(c.cmd))
				}
			}
		})
	}
}

// TestEvalRecord_LateAnswerIsMarked_4818: the evaluation decides a small
// labelled call at once, and the test-only before-record slow point holds its
// record for 9 s, inside the exit guard of Codex's 10 s timeout. The record
// carries a late_answer note (answered_after_harness_timeout=possible, or
// true when a loaded runner starts it past the timeout) naming Codex's 10 s
// timeout, on the line and the wire alike, and the verdict is the
// evaluation's BLOCK, exit 2. The control, not held, has no such note. On
// main neither row is marked.
func TestEvalRecord_LateAnswerIsMarked_4818(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a record for most of Codex's 10 s timeout")
	}
	for _, c := range []struct {
		name string
		slow string
		late bool
	}{
		{"held into the exit guard", "before-record=9s", true},
		{"on time (control)", "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			wire := newWireCapture(t)
			home, configDir := newFailSafeHome(t, false, labelledPolicy4805)
			wire.enroll(t)
			r := runChild4805(t, home, configDir, wire, codexPayload4805(t, labelCmd4805()), budgetEnv("7s", c.slow)...)
			rec := readEvalRecord4818(t, r)
			if r.exit != 2 || r.decision != "BLOCK" || fmt.Sprint(rec.wire["rule_id"]) != "dl-customer-records" {
				t.Errorf("exit %d decision %s rule %v, want the evaluation's BLOCK", r.exit, r.decision, rec.wire["rule_id"])
			}
			n := countKind(rec.line.Notes, analyzer.NoteLateAnswer)
			if !c.late {
				if n != 0 {
					t.Errorf("an on-time record carries %s: %v", analyzer.NoteLateAnswer, rec.line.Notes)
				}
				return
			}
			if n != 1 {
				t.Fatalf("notes %v, want one %s note", noteKinds(rec.line.Notes), analyzer.NoteLateAnswer)
			}
			for _, note := range rec.line.Notes {
				late := strings.HasPrefix(note.Detail, "answered_after_harness_timeout=possible; recorded_at=") || strings.HasPrefix(note.Detail, "answered_after_harness_timeout=true; recorded_at=")
				if note.Kind == analyzer.NoteLateAnswer && (!late || !strings.Contains(note.Detail, "harness=codex; harness_timeout=10s")) {
					t.Errorf("detail %q, want possible or true, with Codex's 10 s timeout", note.Detail)
				}
			}
			if !strings.Contains(r.wireText(), analyzer.NoteLateAnswer) {
				t.Errorf("the wire entry has no %s note", analyzer.NoteLateAnswer)
			}
		})
	}
}
