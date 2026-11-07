package logger

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #4805: an event the hook could not scrub of customer data labels, because
// it could not read them, carries none of the agent's text. The withholding
// lives in Redacted(), so the audit.jsonl line and the SaaS payload, both
// built from it, cannot disagree.

const withheldDetail = "data labels unreadable: /home/u/.agentshield/policy.yaml: data_labels does not parse"

// withheldWith is what the hook passes: the note's detail, and the error and
// reason that replace the failure's own (which quotes the keyword OSPREY).
var withheldWith = Withheld{
	Detail:  withheldDetail,
	Error:   withheldDetail,
	Reasons: []string{"AgentShield: policy load failed — blocking (fail_closed enabled): " + withheldDetail},
}

func withheldEvent() AuditEvent {
	return AuditEvent{
		Timestamp: "2026-11-06T00:00:00Z", Command: "echo FALCON-7 > out.txt", Args: []string{"echo", "FALCON-7", ">", "out.txt"},
		Cwd: "/repo", Decision: "BLOCK", Flagged: true, TriggeredRules: []string{"enterprise-fail-closed"},
		Reasons:      []string{"AgentShield: policy load failed — blocking (fail_closed enabled): yaml: cannot unmarshal !!str `OSPREY` into []string"},
		TaxonomyRefs: []string{"a/b/c"}, Mode: "managed", Source: "codex-hook", SessionID: "s1", Principal: "u",
		Error: "yaml: cannot unmarshal !!str `OSPREY` into []string",
		Notes: []Note{{Kind: "payload_cwd_unusable", Detail: "cwd note"}},
	}
}

func TestRedacted_WithheldDropsTheAgentTextAndKeepsTheRest(t *testing.T) {
	e := withheldEvent()
	w := e.WithAgentTextWithheld(withheldWith)
	r := w.Redacted()

	if r.Command != WithheldText || len(r.Args) != 0 || r.MCPArguments != nil {
		t.Fatalf("agent text survived: command %q args %q arguments %v", r.Command, r.Args, r.MCPArguments)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), "FALCON") || strings.Contains(string(raw), "out.txt") {
		t.Fatalf("a word of the command survived: %s", raw)
	}
	// The failure's own words are replaced (Gary, 2026-11-06).
	if strings.Contains(string(raw), "OSPREY") || r.Error != withheldWith.Error ||
		strings.Join(r.Reasons, "|") != strings.Join(withheldWith.Reasons, "|") {
		t.Fatalf("the failure's text survived: error %q reasons %q", r.Error, r.Reasons)
	}
	// Everything else is the unwithheld redaction's.
	plain := e.Redacted()
	if r.Decision != plain.Decision || strings.Join(r.TriggeredRules, ",") != strings.Join(plain.TriggeredRules, ",") ||
		strings.Join(r.TaxonomyRefs, ",") != strings.Join(plain.TaxonomyRefs, ",") || r.Mode != plain.Mode ||
		r.Source != plain.Source || r.SessionID != plain.SessionID || r.Principal != plain.Principal ||
		r.Flagged != plain.Flagged {
		t.Fatalf("withholding changed a field it must keep:\n got %+v\nwant %+v", r, plain)
	}
	// The payload's cwd and a note quoting it are agent text too (#4805
	// Codex F2): withheld, the kind kept.
	if r.Cwd != WithheldText {
		t.Fatalf("cwd %q, want %q", r.Cwd, WithheldText)
	}
	want := []Note{{Kind: "payload_cwd_unusable", Detail: WithheldText}, {Kind: NoteAgentTextWithheld, Detail: withheldDetail}}
	if len(r.Notes) != 2 || r.Notes[0] != want[0] || r.Notes[1] != want[1] {
		t.Fatalf("notes %+v, want %+v", r.Notes, want)
	}
	// The caller's event is not modified: its notes slice is not shared.
	if len(e.Notes) != 1 || e.Command != "echo FALCON-7 > out.txt" || !strings.Contains(e.Error, "OSPREY") || !strings.Contains(e.Reasons[0], "OSPREY") {
		t.Fatalf("WithAgentTextWithheld modified the original: %+v", e)
	}
	// Idempotent, as redaction is: redacting the redacted event again changes nothing.
	again, _ := json.Marshal(r.Redacted())
	if string(again) != string(raw) {
		t.Fatalf("a second Redacted() changed the event:\n%s\n%s", raw, again)
	}
}

func TestRedacted_WithheldToolCallKeepsItsEmptyCommand(t *testing.T) {
	e := AuditEvent{ToolName: "mcp__fs__write_file", MCPArguments: map[string]interface{}{"content": "FALCON-7"}, Decision: "AUDIT"}
	r := e.WithAgentTextWithheld(withheldWith).Redacted()
	if r.Command != "" || r.MCPArguments != nil {
		t.Fatalf("tool call: command %q arguments %v; want the empty command kept and the arguments dropped", r.Command, r.MCPArguments)
	}
}

// The flag is never serialised, so an event that is not withheld writes the
// same line as before, and the flag cannot be planted from a log line.
func TestWithhold_IsNeverSerialised(t *testing.T) {
	plain, _ := json.Marshal(AuditEvent{Command: "ls"})
	var probe AuditEvent
	if err := json.Unmarshal([]byte(`{"command":"FALCON","withhold":true}`), &probe); err != nil {
		t.Fatal(err)
	}
	if probe.Redacted().Command != "FALCON" {
		t.Fatal("a log line set the withhold flag")
	}
	if strings.Contains(string(plain), "withhold") {
		t.Fatalf("the flag reached the line: %s", plain)
	}
}

// The line LogLinkedRedacted writes is the withheld redaction, and a
// degraded logger's own note goes after the withheld note, as on any event.
func TestLogLinkedRedacted_WritesTheWithheldLine(t *testing.T) {
	for _, degraded := range []bool{false, true} {
		path := filepath.Join(t.TempDir(), "audit.jsonl")
		if degraded {
			if err := os.Mkdir(path+lockSuffix, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		l, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		ev := withheldEvent().WithAgentTextWithheld(withheldWith)
		if note, ok := l.LockUnavailableNote(); ok {
			ev.Notes = append(ev.Notes, note)
		}
		if _, err := l.LogLinkedRedacted(ev.RedactOnce()); err != nil {
			t.Fatal(err)
		}
		_ = l.Close()
		data, _ := os.ReadFile(path)
		var got ChainedEvent
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "FALCON") || got.Command != WithheldText {
			t.Fatalf("degraded=%v: line carries the agent text: %s", degraded, data)
		}
		if got.Notes[1].Kind != NoteAgentTextWithheld || (degraded && got.Notes[len(got.Notes)-1].Kind != NoteAuditLockUnavailable) {
			t.Fatalf("degraded=%v: notes %+v", degraded, got.Notes)
		}
	}
}

// A note that quotes the failure's error or reason has the quote replaced
// too, whether it was on the event when it was redacted or added after
// (RedactedEvent.WithNotes, as markLate does), and a note that quotes
// neither is untouched.
func TestRedacted_WithheldReplacesTheFailureQuotedInNotes(t *testing.T) {
	e := withheldEvent()
	e.Notes = append(e.Notes,
		Note{Kind: "lane_readings", Detail: "posix failed: " + e.Error},
		Note{Kind: "policy_degraded", Detail: "reason was " + e.Reasons[0]},
	)
	red := e.WithAgentTextWithheld(withheldWith).RedactOnce()
	later := red.WithNotes(append(red.Event().Notes, Note{Kind: "analysis_budget_exceeded", Detail: "budget=1s; err=" + e.Error}))
	for _, r := range []AuditEvent{red.Event(), later.Event(), later.Event().Redacted()} {
		raw, _ := json.Marshal(r)
		if strings.Contains(string(raw), "OSPREY") {
			t.Fatalf("a note kept the failure's text: %s", raw)
		}
	}
	got := later.Event().Notes
	if got[0].Detail != WithheldText || got[1].Detail != "posix failed: "+withheldWith.Error ||
		got[2].Detail != "reason was "+withheldWith.Reasons[0] || got[4].Detail != "budget=1s; err="+withheldWith.Error {
		t.Fatalf("notes %+v", got)
	}
}

// An empty error or reason quotes nothing: replacing "" would write the new
// text between every character of every note.
func TestRedacted_WithheldEmptyFailureTextQuotesNothing(t *testing.T) {
	e := withheldEvent()
	e.Error = ""
	e.Reasons = []string{""}
	r := e.WithAgentTextWithheld(withheldWith).Redacted()
	if r.Notes[0].Detail != WithheldText || r.Notes[1].Detail != withheldDetail {
		t.Fatalf("notes %+v", r.Notes)
	}
}

// Redacting a redacted event again keeps the failure text it replaced, so a
// note added after the second redaction is cleared of it too.
func TestRedacted_WithheldQuotesSurviveARedactionOfTheRedacted(t *testing.T) {
	e := withheldEvent()
	again := e.WithAgentTextWithheld(withheldWith).Redacted().RedactOnce()
	got := again.WithNotes(append(again.Event().Notes, Note{Kind: "lane_readings", Detail: "err=" + e.Error}))
	if d := got.Event().Notes[len(got.Event().Notes)-1].Detail; d != "err="+withheldWith.Error {
		t.Fatalf("note %q, want the old error replaced", d)
	}
}

// #4805 Codex F2: on a withheld event only the note kinds AgentShield writes
// from its own text keep their detail; every other kind's detail, the
// payload's cwd among them, is withheld, on the event and on a note added
// after the redaction. Kinds and rules stay. An event that is not withheld
// keeps every detail.
func TestRedacted_WithheldKeepsOnlyOwnTextNoteDetails(t *testing.T) {
	value := "FAL" + "CON77"
	kinds := []string{"payload_cwd_unusable", "routing_gap", "dynamic_name", "parse_error", "excused", "a_kind_added_next_year",
		NoteAgentTextWithheld, NoteAuditLockUnavailable, "analysis_budget_exceeded", "policy_degraded", "lane_readings", "late_answer"}
	// The own-text set, spelled out: a kind joins it only by changing this
	// line, so the review sees it.
	wantOwn := map[string]bool{NoteAgentTextWithheld: true, NoteAuditLockUnavailable: true,
		"analysis_budget_exceeded": true, "policy_degraded": true, "lane_readings": true, "late_answer": true}
	for _, k := range kinds {
		if OwnTextNoteKind(k) != wantOwn[k] {
			t.Errorf("OwnTextNoteKind(%q) = %v, want %v", k, OwnTextNoteKind(k), wantOwn[k])
		}
	}
	var notes []Note
	for _, k := range kinds {
		notes = append(notes, Note{Kind: k, Rule: "r-" + k, Detail: k + " " + value})
	}
	e := withheldEvent()
	e.Cwd = "/work/" + value
	e.Notes = notes
	red := e.WithAgentTextWithheld(withheldWith).RedactOnce()
	later := red.WithNotes(append(red.Event().Notes, Note{Kind: "payload_cwd_unusable", Rule: "late", Detail: "late " + value}))
	for name, r := range map[string]AuditEvent{"redacted": red.Event(), "note added later": later.Event()} {
		if r.Cwd != WithheldText {
			t.Errorf("%s: cwd %q", name, r.Cwd)
		}
		for i, n := range r.Notes {
			switch {
			case i == len(kinds): // WithAgentTextWithheld's own note
				if n.Kind != NoteAgentTextWithheld || n.Detail != withheldDetail {
					t.Errorf("%s: withheld note %+v", name, n)
				}
				continue
			case i > len(kinds):
				if n.Detail != WithheldText || n.Kind != "payload_cwd_unusable" || n.Rule != "late" {
					t.Errorf("%s: late note %+v", name, n)
				}
				continue
			}
			own := OwnTextNoteKind(kinds[i])
			if n.Kind != kinds[i] || n.Rule != "r-"+kinds[i] || (own && n.Detail != kinds[i]+" "+value) || (!own && n.Detail != WithheldText) {
				t.Errorf("%s: note %+v (own text %v)", name, n, own)
			}
		}
	}
	// A note with no detail keeps none: the marker stands for withheld text,
	// not for an absent one.
	if r := (AuditEvent{Notes: []Note{{Kind: "routing_gap"}}}).WithAgentTextWithheld(withheldWith).Redacted(); r.Notes[0].Detail != "" {
		t.Errorf("an empty detail became %q", r.Notes[0].Detail)
	}
	if plain := (AuditEvent{Cwd: "/work/" + value, Notes: notes}).Redacted(); plain.Cwd != "/work/"+value || plain.Notes[0].Detail != kinds[0]+" "+value {
		t.Errorf("an event that is not withheld lost a detail: %+v", plain)
	}
}
