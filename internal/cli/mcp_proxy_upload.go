package cli

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

// newMCPProxyAuditSink is the OnAudit callback of both MCP proxies. Each entry
// is redacted and data-label scrubbed (#4463), given its rules' taxonomy when
// it names rules but carries none, appended to the local audit log when that
// is open, and queued for AI Agent Lens (#4734), even when the local log could
// not be opened, as the hook does.
//
// dlEngine is read per entry because the proxies compile their data labels
// after building the sink; a nil engine scrubs nothing. ruleTaxonomy may be
// nil.
func newMCPProxyAuditSink(auditFile *os.File, dlEngine func() *datalabel.Engine, ruleTaxonomy func([]string) []string) mcp.AuditFunc {
	var mu sync.Mutex
	return func(entry mcp.AuditEntry) {
		redacted := withRuleTaxonomy(entry.Redacted(dlEngine().Spans), ruleTaxonomy)
		if auditFile != nil {
			if data, err := json.Marshal(redacted); err == nil {
				mu.Lock()
				_, _ = auditFile.Write(append(data, '\n'))
				mu.Unlock()
			}
		}
		uploadMCPProxyAudit(redacted)
	}
}

// withRuleTaxonomy fills the taxonomy of a proxy audit entry that names its
// rules but carries none, from those rules' declared taxonomy (#4734). The
// description scan, schema drift and rug-pull sites name sentinel or pack
// rules without a ref, and MCP rules have no rule-id fallback in the SaaS, so
// without this their receipts arrive unmapped. An entry that already carries a
// ref is returned unchanged.
func withRuleTaxonomy(entry mcp.AuditEntry, lookup func([]string) []string) mcp.AuditEntry {
	if lookup == nil || len(entry.TriggeredRules) == 0 || len(entry.AllTaxonomyRefs()) > 0 {
		return entry
	}
	entry.TaxonomyRefs = lookup(entry.TriggeredRules)
	return entry
}

// mcpProxyAuditEvent is a proxy decision as the hook's audit event, the shape
// sendRemoteAudit uploads (#4734). Cwd and session are left empty: the proxy
// runs in whatever directory its client launched it from and has no agent
// session, and an empty field is an honest "not observable" on the wire.
func mcpProxyAuditEvent(entry mcp.AuditEntry) logger.AuditEvent {
	return logger.AuditEvent{
		Timestamp:        entry.Timestamp,
		ToolName:         entry.ToolName,
		MCPArguments:     entry.Arguments,
		ServerName:       entry.ServerName,
		Decision:         entry.Decision,
		Flagged:          entry.Flagged,
		TriggeredRules:   entry.TriggeredRules,
		Reasons:          entry.Reasons,
		TaxonomyRefs:     entry.AllTaxonomyRefs(),
		Mode:             entry.Mode,
		OriginalDecision: entry.OriginalDecision,
		Source:           entry.Source,
		Principal:        osPrincipal(),
	}
}

// uploadMCPProxyAudit queues a proxy decision for AI Agent Lens through the
// hook's upload path: the same queue, redaction and machine id. Before #4734
// the MCP proxies wrote only the local audit line, so no decision about a
// Claude Desktop or Cursor MCP server reached the SaaS. entry must already be
// redacted (AuditEntry.Redacted), as the local line is. There is no local
// chain link: the proxies append their lines without the hook's chain.
func uploadMCPProxyAudit(entry mcp.AuditEntry) {
	event := mcpProxyAuditEvent(entry)
	sendRemoteAudit(&event, nil)
}
