package logger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// #4818: an evaluation's record withheld because its scrubber could not
// finish in time (Withheld.KeepFailureText) drops the agent text as any
// withheld event does, but keeps its own error and reasons, which the
// scrubber it still carries masks.
func TestRedacted_WithheldForTimeKeepsItsOwnReasonsMasked_4818(t *testing.T) {
	value := "CUST-" + "104" + "233"
	scrub := func(s string) []datalabel.Span {
		if i := strings.Index(s, value); i >= 0 {
			return []datalabel.Span{{Start: i, End: i + len(value), Label: "customer-records"}}
		}
		return nil
	}
	e := AuditEvent{
		Command: "echo " + value + " > notes.txt", Args: []string{"echo", value}, Cwd: "/work",
		MCPArguments: map[string]interface{}{"k": value},
		Decision:     "BLOCK", TriggeredRules: []string{"dl-customer-records"},
		Reasons: []string{"customer id in agent action", "matched " + value},
		Error:   "lane note quoting " + value,
		Notes:   []Note{{Kind: "excused", Rule: "r", Detail: "quotes " + value}},
	}.WithScrubber(scrub)
	if !e.Scrubs() {
		t.Fatal("Scrubs() is false on an event with a scrubber")
	}
	if (AuditEvent{}).Scrubs() {
		t.Fatal("Scrubs() is true on an event with none")
	}
	r := e.WithAgentTextWithheld(Withheld{Detail: "agent text too large to scrub", KeepFailureText: true}).Redacted()

	if r.Command != WithheldText || len(r.Args) != 0 || r.MCPArguments != nil || r.Cwd != WithheldText {
		t.Errorf("agent text survived: command %q args %q arguments %v cwd %q", r.Command, r.Args, r.MCPArguments, r.Cwd)
	}
	wantReasons := []string{"customer id in agent action", "matched [LABEL:customer-records]"}
	if strings.Join(r.Reasons, "|") != strings.Join(wantReasons, "|") {
		t.Errorf("reasons %q, want the event's own, masked: %q", r.Reasons, wantReasons)
	}
	if r.Error != "lane note quoting [LABEL:customer-records]" {
		t.Errorf("error %q, want the event's own, masked", r.Error)
	}
	// Every other rule of a withheld event holds: a note kind that is not
	// AgentShield's own text loses its detail, and the withheld note is added.
	if r.Notes[0].Detail != WithheldText || r.Notes[len(r.Notes)-1].Kind != NoteAgentTextWithheld {
		t.Errorf("notes %+v, want the excused detail withheld and the %s note last", r.Notes, NoteAgentTextWithheld)
	}
	raw, _ := json.Marshal(r)
	if strings.Contains(string(raw), value) {
		t.Errorf("LEAK: %s", raw)
	}
	// Without KeepFailureText the Withheld's own error and reasons replace
	// them, as before (#4805).
	r2 := e.WithAgentTextWithheld(Withheld{Detail: "d", Error: "(cause withheld)", Reasons: []string{"why"}}).Redacted()
	if r2.Error != "(cause withheld)" || strings.Join(r2.Reasons, "|") != "why" {
		t.Errorf("error %q reasons %q, want the Withheld's", r2.Error, r2.Reasons)
	}
}
