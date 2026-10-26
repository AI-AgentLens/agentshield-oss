package mcp

import "github.com/AI-AgentLens/agentshield/internal/redact"

// Redacted returns a copy of e that is safe to write to an audit file (#4463).
//
// The shell hook has redacted its audit event since #4332 and scrubbed data
// labels since #4448; the MCP proxies marshalled AuditEntry as it was, so a
// tool call carrying a secret or a labelled value left it in the entry. The
// proxies call this in their OnAudit sink. Rule decisions and the entry's
// shape are untouched: only agent- or server-supplied strings change.
//
// scrub may be nil (no data labels). When set it runs first, over every string
// in Arguments and Reasons, exactly as logger.AuditEvent.Redacted does, then
// secret redaction runs over the result. The input is never modified.
func (e AuditEntry) Redacted(scrub func(string) string) AuditEntry {
	args := e.Arguments
	if scrub != nil {
		args = scrubAuditValues(scrub, args)
	}
	e.Arguments = redact.RedactArguments(args)
	if e.Reasons != nil {
		reasons := make([]string, len(e.Reasons))
		for i, r := range e.Reasons {
			if scrub != nil {
				r = scrub(r)
			}
			reasons[i] = redact.Redact(r)
		}
		e.Reasons = reasons
	}
	return e
}

// scrubAuditValues deep-copies args with scrub applied to every string value,
// including strings inside nested maps and lists. Keys are left alone.
func scrubAuditValues(scrub func(string) string, args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		out[k] = scrubAuditValue(scrub, v)
	}
	return out
}

func scrubAuditValue(scrub func(string) string, v interface{}) interface{} {
	switch t := v.(type) {
	case string:
		return scrub(t)
	case map[string]interface{}:
		return scrubAuditValues(scrub, t)
	case []interface{}:
		out := make([]interface{}, len(t))
		for i, e := range t {
			out[i] = scrubAuditValue(scrub, e)
		}
		return out
	}
	return v
}
