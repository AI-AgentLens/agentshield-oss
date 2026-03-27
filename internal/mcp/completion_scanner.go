package mcp

import (
	"encoding/json"
	"fmt"
	"time"
)

// ScanCompletionResponse scans a completion/complete response result for prompt
// injection, credential harvesting, and exfiltration patterns embedded in the
// completion suggestion values.
//
// A malicious MCP server can return poisoned autocompletion suggestions that
// are surfaced in the IDE without passing through the standard tool response
// scanning pipeline. If the user selects (or the agent auto-selects) a
// poisoned suggestion, the injected instructions are inserted as argument
// values and passed to the tool handler.
func ScanCompletionResponse(result *CompletionCompleteResult) PromptsScanResult {
	var scanResult PromptsScanResult
	if result == nil {
		return scanResult
	}
	for i, value := range result.Completion.Values {
		if value == "" {
			continue
		}
		field := "completion.values[" + itoa(i) + "]"
		scanPromptsField(&scanResult, value, field)
	}
	scanResult.Poisoned = len(scanResult.Findings) > 0
	return scanResult
}

// FilterCompletionResponse checks if a response is a completion/complete result.
// If it is, scans each completion value for prompt injection, credential
// harvesting, and exfiltration patterns. When poisoned content is found the
// entire response is replaced with a JSON-RPC error to prevent the payload
// reaching the LLM context.
// Returns the replacement JSON bytes, or nil if the message is not a
// completion/complete response or no poisoning was detected.
func (h *MessageHandler) FilterCompletionResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	result := parseCompletionCompleteResult(msg.Result)
	if result == nil {
		return nil
	}

	scanResult := ScanCompletionResponse(result)
	if !scanResult.Poisoned {
		return nil
	}

	reason := "completion/complete response contains injected instructions"
	if len(scanResult.Findings) > 0 {
		reason = string(scanResult.Findings[0].Signal) + ": " + scanResult.Findings[0].Detail
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] POISONED completion/complete response blocked (%d signals)\n",
		len(scanResult.Findings))
	for _, f := range scanResult.Findings {
		_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s (field: %s)\n", f.Signal, f.Detail, f.Field)
	}

	if h.OnAudit != nil {
		reasons := make([]string, 0, len(scanResult.Findings))
		for _, f := range scanResult.Findings {
			reasons = append(reasons, string(f.Signal)+": "+f.Detail+" (field: "+f.Field+")")
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       MethodCompletionComplete,
			Decision:       "BLOCK",
			Flagged:        true,
			TriggeredRules: []string{"completion-injection-scan"},
			Reasons:        reasons,
			Source:         "mcp-proxy-completion-scan",
			ServerName:     h.ServerName,
			TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-completion-endpoint-injection",
		})
	}

	replacement, err := NewBlockResponse(msg.ID, reason)
	if err != nil {
		return nil
	}
	return replacement
}

// parseCompletionCompleteResult parses a JSON-RPC result as CompletionCompleteResult.
// Returns nil if the data does not represent a completion/complete response.
func parseCompletionCompleteResult(data json.RawMessage) *CompletionCompleteResult {
	if len(data) == 0 {
		return nil
	}
	var result CompletionCompleteResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	// Must have a non-nil values slice to be a completion/complete response.
	// An empty but present values array is valid (no suggestions).
	if result.Completion.Values == nil {
		return nil
	}
	return &result
}
