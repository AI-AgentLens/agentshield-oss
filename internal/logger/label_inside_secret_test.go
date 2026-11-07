package logger

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/redact"
)

// #4813 (Gary, 2026-11-06). Redacted() applied the data-label scrubber
// before secret redaction, so a label value inside a secret's value cut the
// secret's pattern short and the rest of the secret stayed in the record, on
// the normal path since #4448 and on the fail-safe path since #4805. It now
// masks the label spans and the secret spans, both found on the text as
// written, together (redact.RedactWithLabels).

// issueTail and issueShape are the issue's row, assembled at runtime:
// AgentShield reads test sources as content.
const issueTail = "zz9yy8xx7ww6vv5u"

func issueShape() string { return "export TO" + "KEN=abcdefghijklmn" + "CUST-104233" + issueTail }

// emailShape is the other order's failure: a secret run straight into an
// email label value. Redacting first leaves the email's domain.
func emailShape() string { return "TO" + "KEN=abcdefghijklmn" + "alice" + "@corp.example.com" }

// unionScrub finds the customer-records and email labels.
var unionScrub = mustLabelSpans(
	datalabel.DataLabelConfig{ID: "customer-records", Patterns: []datalabel.PatternConfig{{Regex: `CUST-[0-9]{6}`}}},
	datalabel.DataLabelConfig{ID: "email", Patterns: []datalabel.PatternConfig{{Regex: `[A-Za-z0-9._%+-]+@corp\.example\.com`}}},
)

// render is the scrubber main attached: the spans replaced by their
// placeholders (datalabel.Engine.Scrub, which TestScrub_IsMainsScrub_4813
// holds to main's).
func render(find func(string) []datalabel.Span) func(string) string {
	if find == nil {
		return nil
	}
	return func(s string) string {
		var sb strings.Builder
		pos := 0
		for _, sp := range find(s) {
			sb.WriteString(s[pos:sp.Start] + sp.Placeholder())
			pos = sp.End
		}
		return sb.String() + s[pos:]
	}
}

// mainRedacted is Redacted() as it was on main (c4458c7e) for an event that
// withholds nothing, frozen: scrub every field, then redact it.
func mainRedacted(e AuditEvent, s func(string) string) AuditEvent {
	if s != nil {
		e.Command = s(e.Command)
		if e.Args != nil {
			args := make([]string, len(e.Args))
			for i, a := range e.Args {
				args[i] = s(a)
			}
			e.Args = args
		}
		if e.Reasons != nil {
			reasons := make([]string, len(e.Reasons))
			for i, r := range e.Reasons {
				reasons[i] = s(r)
			}
			e.Reasons = reasons
		}
		e.Error = s(e.Error)
		e.MCPArguments = mainScrubArguments(s, e.MCPArguments)
		e.Notes = mapNoteDetails(e.Notes, s)
	}
	e.Command = redact.Redact(e.Command)
	e.Args = redact.RedactArgs(e.Args)
	if e.Reasons != nil {
		reasons := make([]string, len(e.Reasons))
		for i, r := range e.Reasons {
			reasons[i] = redact.Redact(r)
		}
		e.Reasons = reasons
	}
	e.Error = redact.Redact(e.Error)
	e.MCPArguments = redact.RedactArguments(e.MCPArguments)
	e.Notes = mapNoteDetails(e.Notes, redact.Redact)
	return e
}

func mainScrubArguments(s func(string) string, args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		out[k] = mainScrubValue(s, v)
	}
	return out
}

func mainScrubValue(s func(string) string, v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return s(t)
	case map[string]interface{}:
		return mainScrubArguments(s, t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = mainScrubValue(s, e)
		}
		return out
	}
	return v
}

// TestRedacted_LabelInsideSecret_TailIsMasked_4813 is
// TestRedacted_LabelInsideSecret_IsAPinnedResidual flipped: the issue's row
// records the whole assignment as [REDACTED]. Controls: main's order leaves
// the tail, and the same secret with no label inside was already redacted
// whole.
func TestRedacted_LabelInsideSecret_TailIsMasked_4813(t *testing.T) {
	r := AuditEvent{Command: issueShape()}.WithScrubber(fakeScrub).Redacted()
	if r.Command != "export [REDACTED]" {
		t.Fatalf("got %q, want %q: the tail or the label value survived", r.Command, "export [REDACTED]")
	}
	if main := mainRedacted(AuditEvent{Command: issueShape()}, render(fakeScrub)); !strings.Contains(main.Command, issueTail) {
		t.Fatalf("control: main's order no longer leaves the tail (%q); the row proves nothing", main.Command)
	}
	plain := "export TO" + "KEN=abcdefghijklmn" + "QQ" + issueTail
	if c := (AuditEvent{Command: plain}.WithScrubber(fakeScrub).Redacted()); strings.Contains(c.Command, issueTail) {
		t.Fatalf("control: a secret with no label inside kept its tail: %q", c.Command)
	}
}

// redactFirst is the other order, for the control: redact every field as
// main did, then scrub what is left.
func redactFirst(e AuditEvent, s func(string) string) AuditEvent {
	r := mainRedacted(e, nil)
	r.Command, r.Error = s(r.Command), s(r.Error)
	for i := range r.Args {
		r.Args[i] = s(r.Args[i])
	}
	for i := range r.Reasons {
		r.Reasons[i] = s(r.Reasons[i])
	}
	r.MCPArguments = mainScrubArguments(s, r.MCPArguments)
	r.Notes = mapNoteDetails(r.Notes, s)
	return r
}

// TestRedacted_UnionCoversEveryField_4813: both shapes in every field
// Redacted() covers (command, args, reasons, error, MCP arguments at depth,
// note details): no field carries the issue's tail, a label value or the
// email's domain. Controls: in every field, main's order leaks the issue's
// shape, and the redact-first order leaks the email's.
func TestRedacted_UnionCoversEveryField_4813(t *testing.T) {
	gone := []string{issueTail, "CUST-104233", "corp.example", "abcdefghijklmn"}
	orders := map[string]func(AuditEvent, func(string) string) AuditEvent{"main's order": mainRedacted, "redact-first": redactFirst}
	for shape, order := range map[string]string{issueShape(): "main's order", emailShape(): "redact-first"} {
		e := AuditEvent{
			Command: "sh -c " + shape,
			Args:    strings.Fields("sh -c " + shape),
			Reasons: []string{"matched in " + shape},
			Error:   "failed on " + shape,
			MCPArguments: map[string]interface{}{
				"content": shape,
				"n":       map[string]interface{}{"list": []interface{}{"x " + shape, 7.0}},
			},
			Notes: []Note{{Kind: "dynamic_name", Detail: "computed from " + shape}},
		}
		fields := func(r AuditEvent) map[string]string {
			return map[string]string{
				"command": r.Command, "args": strings.Join(r.Args, " "), "reasons": strings.Join(r.Reasons, " "),
				"error": r.Error, "mcp_arguments": jsonString(r.MCPArguments), "notes": jsonString(r.Notes),
			}
		}
		got := fields(e.WithScrubber(unionScrub).Redacted())
		main := fields(orders[order](e, render(unionScrub)))
		for name, v := range got {
			for _, g := range gone {
				if strings.Contains(v, g) {
					t.Errorf("%s: %q survived in %s: %q", name, g, name, v)
				}
			}
			leaked := false
			for _, g := range gone {
				leaked = leaked || strings.Contains(main[name], g)
			}
			if !leaked {
				t.Errorf("control: %s's %s (%q) leaks nothing of %q; the row proves nothing", order, name, main[name], shape)
			}
		}
	}
}

func jsonString(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// TestRedacted_NoScrubberIsMain_4813: over the redaction corpus (the analyzer
// corpus as shell events, secret shapes in every field, MCP events), an
// event with no scrubber redacts byte for byte as main's frozen Redacted()
// did, and so does one whose scrubber finds no label in it. An event whose
// scrubber finds a label carries no label value; how it may differ from main
// is internal/redact's property test (TestRedactWithLabels_Property_4813).
// Positive control: the corpus is redacted.
func TestRedacted_NoScrubberIsMain_4813(t *testing.T) {
	corpus := redactionCorpus()
	same, scrubbed, differs := 0, 0, 0
	for i, e := range corpus {
		if e.scrub == nil {
			got, want := jsonString(e.Redacted()), jsonString(mainRedacted(e, nil))
			if got != want {
				t.Fatalf("event %d without a scrubber:\n got %s\nwant %s", i, got, want)
			}
			if got != jsonString(e) {
				same++
			}
			// The same event with a scrubber that finds nothing.
			if g := jsonString(e.WithScrubber(func(string) []datalabel.Span { return nil }).Redacted()); g != want {
				t.Fatalf("event %d with a scrubber that finds nothing:\n got %s\nwant %s", i, g, want)
			}
			continue
		}
		scrubbed++
		got, want := jsonString(e.Redacted()), jsonString(mainRedacted(e, render(e.scrub)))
		if got != want {
			differs++
			t.Logf("event %d with a label differs from main:\n got %s\nmain %s", i, got, want)
		}
		if strings.Contains(got, "PHOENIX") {
			t.Fatalf("event %d: the label value survived: %s", i, got)
		}
	}
	t.Logf("%d events without a scrubber identical to main (%d of them redacted); %d with a label scrubber, %d recorded differently", len(corpus)-scrubbed, same, scrubbed, differs)
	if same < 20 || scrubbed == 0 {
		t.Fatalf("control: %d redacted events, %d scrubbed: the equivalence says little", same, scrubbed)
	}
}
