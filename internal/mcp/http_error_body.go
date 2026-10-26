package mcp

import (
	"fmt"
	"net/http"
	"time"
)

// screenErrorStatusBody scans the body of a non-2xx upstream answer that is
// not shaped like a JSON-RPC message (#4408).
//
// The TS SDK's StreamableHTTP transport turns a non-2xx POST body into the
// text of the error callTool rejects with, and a host reports that text to the
// model. It is the same channel as a JSON-RPC error.message, which
// FilterErrorResponse already scans, with the JSON taken off, and the
// message-shaped screen relays such a body without reading it. A hit replaces
// the body with a neutral one that keeps the status. A clean body (an HTML
// error page with no directive in it) stays receipt-free, as the mediation
// doc's design decision #2 says. A 2xx body is not this channel and is left to
// the existing screens. The scan is uncapped on purpose: a length cap is a
// bypass. It reports whether the reply has already been written.
func (hp *HTTPProxy) screenErrorStatusBody(w http.ResponseWriter, resp *http.Response, body []byte) bool {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return false
	}
	if looksLikeJSONRPCPayload(body) {
		return false
	}
	signal, detail := ScanErrorMessage(string(body))
	if signal == "" {
		return false
	}
	rule := "mcp-error-message-injection"
	if s := hp.handler.Evaluator.LookupSentinel(rule); s != nil {
		rule = s.ID
	}
	reason := fmt.Sprintf("%s: %s (field: http %d body)", signal, detail, resp.StatusCode)
	_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] AUDIT non-2xx response body — injection: %s\n", reason)
	if hp.cfg.OnAudit != nil {
		hp.cfg.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "error-response",
			Decision:       "AUDIT",
			Flagged:        true,
			TriggeredRules: []string{rule},
			Reasons:        []string{reason},
			Source:         "mcp-proxy-error-scan",
			ServerName:     hp.cfg.ServerName,
			TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-error-message-injection",
		})
	}
	neutral := []byte(fmt.Sprintf("Upstream error (HTTP %d) [AgentShield: error body sanitized — injection pattern detected]", resp.StatusCode))
	resp.Header.Set("Content-Type", "text/plain; charset=utf-8")
	hp.writeJSONResponse(w, resp, neutral, true)
	return true
}
