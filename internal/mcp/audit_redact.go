package mcp

import (
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/redact"
)

// Redacted returns a copy of e that is safe to write to an audit file (#4463).
//
// The shell hook has redacted its audit event since #4332 and scrubbed data
// labels since #4448; the MCP proxies marshalled AuditEntry as it was, so a
// tool call carrying a secret or a labelled value left it in the entry. The
// proxies call this in their OnAudit sink. Rule decisions and the entry's
// shape are untouched: only agent- or server-supplied strings change.
//
// labels returns a text's data-label spans (datalabel.Engine.Spans) and may be
// nil (no data labels). Every string in Arguments and Reasons is redacted
// exactly as logger.AuditEvent.Redacted redacts it: the label spans and the
// secrets, both found on the string as written, are masked together
// (redact.RedactWithLabels, #4813), and a string no label matches is redacted
// as it was before. The input is never modified.
func (e AuditEntry) Redacted(labels func(string) []datalabel.Span) AuditEntry {
	e.Arguments = redact.RedactArgumentsWithLabels(e.Arguments, labels)
	if e.Reasons != nil {
		reasons := make([]string, len(e.Reasons))
		for i, r := range e.Reasons {
			reasons[i] = redact.RedactWithLabels(r, labels)
		}
		e.Reasons = reasons
	}
	return e
}
