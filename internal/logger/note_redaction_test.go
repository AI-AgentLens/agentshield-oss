package logger

import (
	"encoding/json"
	"strings"
	"testing"
)

// A note's detail can quote agent input: a PowerShell dynamic_name note
// quotes the computed command name. Before Redacted() covered notes, a token
// there reached audit.jsonl and the SaaS in plain text while the command
// beside it read [REDACTED] (found by #4800's Opus pass).
func TestRedacted_NoteDetail(t *testing.T) {
	// Assembled at runtime: AgentShield guards the machine this is written on.
	tok := "gh" + "p_" + strings.Repeat("Ab3", 12)
	e := AuditEvent{
		Command: "& ('" + tok + "' + 'x') /list",
		Notes: []Note{
			{Kind: "dynamic_name", Detail: `command name "('` + tok + `' + 'x')" is computed`},
			{Kind: "excused", Rule: "sec-block-example", Detail: "intent label applied near " + tok},
			{Kind: "lane_readings", Detail: "tool=powershell; posix=BLOCK(guardian-secrets_in_command); powershell=AUDIT; kept=posix"},
		},
	}

	r := e.Redacted()
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), tok) {
		t.Fatalf("token survived Redacted(): %s", raw)
	}
	for i := range e.Notes[:2] {
		if !strings.Contains(r.Notes[i].Detail, "[REDACTED]") {
			t.Errorf("note %d: detail %q has no [REDACTED] marker", i, r.Notes[i].Detail)
		}
	}
	// Kind and rule are not agent text: they stay as they are.
	if r.Notes[0].Kind != "dynamic_name" || r.Notes[1].Kind != "excused" || r.Notes[1].Rule != "sec-block-example" {
		t.Errorf("kind or rule changed: %+v", r.Notes)
	}
	// A note with no secret is unchanged.
	if r.Notes[2] != e.Notes[2] {
		t.Errorf("a note with no secret changed: %+v -> %+v", e.Notes[2], r.Notes[2])
	}
	// Redaction works on a copy: the caller still holds these notes.
	if !strings.Contains(e.Notes[0].Detail, tok) {
		t.Fatal("Redacted mutated the caller's notes")
	}
}

// An event without notes keeps omitting the field, so its bytes and its
// chain hash are what they were before notes were redacted.
func TestRedacted_NoNotesStaysOmitted(t *testing.T) {
	r := AuditEvent{Command: "ls"}.Redacted()
	if r.Notes != nil {
		t.Fatalf("Notes = %#v, want nil", r.Notes)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), `"notes"`) {
		t.Fatalf("an event without notes now writes the field: %s", raw)
	}
}
