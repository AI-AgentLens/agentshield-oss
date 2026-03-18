package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// MessageHandler encapsulates the shared MCP message evaluation logic
// used by both stdio and HTTP transport proxies.
type MessageHandler struct {
	Evaluator    *PolicyEvaluator
	OnAudit      AuditFunc
	Stderr       io.Writer
	ServerName   string             // identifies the downstream MCP server in audit entries
	SchemaDrift  *SchemaDriftScanner // optional; nil disables schema drift detection
}

// HandleToolCall evaluates a tools/call message against policy, content scanning,
// value limits, and config guard. Returns (true, blockResponseJSON) if blocked.
func (h *MessageHandler) HandleToolCall(msg *Message) (bool, []byte) {
	params, err := ExtractToolCall(msg)
	if err != nil {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] warning: failed to extract tool call: %v\n", err)
		return false, nil // fail open
	}

	result := h.Evaluator.EvaluateToolCall(params.Name, params.Arguments)

	// If policy didn't block, scan argument content for secrets/exfiltration
	if result.Decision != "BLOCK" {
		contentResult := ScanToolCallContent(params.Name, params.Arguments)
		if contentResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "argument-content-scan")
			for _, f := range contentResult.Findings {
				result.TriggeredRules = append(result.TriggeredRules, "content:"+string(f.Signal))
				result.Reasons = append(result.Reasons, string(f.Signal)+": "+f.Detail+" (arg: "+f.ArgName+")")
			}
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED by content scan: %s (%d signals)\n",
				params.Name, len(contentResult.Findings))
			for _, f := range contentResult.Findings {
				_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s (arg: %s)\n", f.Signal, f.Detail, f.ArgName)
			}
		}
	}

	// If still not blocked, check value limits on numeric arguments
	if result.Decision != "BLOCK" {
		vlResult := h.Evaluator.CheckValueLimits(params.Name, params.Arguments)
		if vlResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "value-limit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED by value limit: %s (%d violations)\n",
				params.Name, len(vlResult.Findings))
			for _, f := range vlResult.Findings {
				_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s=%.2f (%s)\n", f.RuleID, f.ArgName, f.Value, f.Limit)
			}
		} else if len(vlResult.Findings) > 0 {
			// AUDIT-level findings
			result.TriggeredRules = append(result.TriggeredRules, "value-limit-audit")
			for _, f := range vlResult.Findings {
				if f.RuleID != "" {
					result.TriggeredRules = append(result.TriggeredRules, f.RuleID)
				}
				result.Reasons = append(result.Reasons, fmt.Sprintf("value_limit_audit: %s (arg: %s, value: %.2f, %s)", f.Reason, f.ArgName, f.Value, f.Limit))
			}
		}
	}

	// If still not blocked, check for config file write attempts
	if result.Decision != "BLOCK" {
		guardResult := CheckConfigGuard(params.Name, params.Arguments)
		if guardResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "config-file-guard")
			for _, f := range guardResult.Findings {
				result.Reasons = append(result.Reasons, "["+f.Category+"] "+f.Reason+" (path: "+f.Path+")")
			}
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED by config guard: %s (%d findings)\n",
				params.Name, len(guardResult.Findings))
			for _, f := range guardResult.Findings {
				_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s (path: %s)\n", f.Category, f.Reason, f.Path)
			}
		}
	}

	// Log the audit entry
	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       params.Name,
			Arguments:      params.Arguments,
			Decision:       string(result.Decision),
			Flagged:        result.Decision == "BLOCK" || result.Decision == "AUDIT",
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
			Source:         "mcp-proxy",
			ServerName:     h.ServerName,
		})
	}

	if result.Decision == "BLOCK" {
		reason := "Blocked by policy"
		if len(result.Reasons) > 0 {
			reason = result.Reasons[0]
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED tool call: %s — %s\n", params.Name, reason)

		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	if result.Decision == "AUDIT" {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT tool call: %s\n", params.Name)
	}

	return false, nil
}

// HandleResourceRead evaluates a resources/read message against MCP policy.
// Returns (true, blockResponseJSON) if blocked.
func (h *MessageHandler) HandleResourceRead(msg *Message) (bool, []byte) {
	params, err := ExtractResourceRead(msg)
	if err != nil {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] warning: failed to extract resource read: %v\n", err)
		return false, nil // fail open
	}

	result := h.Evaluator.EvaluateResourceRead(params.URI)

	// Log the audit entry
	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "resources/read",
			Arguments:      map[string]interface{}{"uri": params.URI},
			Decision:       string(result.Decision),
			Flagged:        result.Decision == "BLOCK" || result.Decision == "AUDIT",
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
			Source:         "mcp-proxy",
			ServerName:     h.ServerName,
		})
	}

	if result.Decision == "BLOCK" {
		reason := "Blocked by policy"
		if len(result.Reasons) > 0 {
			reason = result.Reasons[0]
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED resource read: %s — %s\n", params.URI, reason)

		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	if result.Decision == "AUDIT" {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT resource read: %s\n", params.URI)
	}

	return false, nil
}

// FilterToolsListResponse checks if a response is a tools/list result.
// If it is, scans each tool description for poisoning and removes poisoned tools.
// Returns the modified JSON bytes, or nil if the message is not a tools/list response
// or no modifications were needed.
func (h *MessageHandler) FilterToolsListResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process responses (has result, no method)
	if msg.Method != "" || msg.Result == nil {
		return nil
	}

	// Try to parse as ListToolsResult
	var listResult ListToolsResult
	if err := json.Unmarshal(msg.Result, &listResult); err != nil {
		return nil
	}

	// Must have a tools array to be a tools/list response
	if listResult.Tools == nil {
		return nil
	}

	// Check for schema drift against the cached baseline.
	if h.SchemaDrift != nil {
		serverKey := h.ServerName
		if serverKey == "" {
			serverKey = "default"
		}
		drift := h.SchemaDrift.CheckDrift(serverKey, listResult.Tools)
		if drift != nil && drift.Drifted {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] SCHEMA DRIFT detected for server %q: %s\n",
				serverKey, drift.DriftSummary())
			if h.OnAudit != nil {
				h.OnAudit(AuditEntry{
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
					Decision:       "AUDIT",
					Flagged:        true,
					TriggeredRules: []string{"mcp-supply-chain-schema-drift"},
					Reasons:        []string{drift.DriftSummary()},
					Source:         "mcp-proxy-schema-drift",
					ServerName:     serverKey,
				})
			}
		}
	}

	// Scan each tool and filter out poisoned ones
	var clean []ToolDefinition
	removed := 0
	for _, tool := range listResult.Tools {
		scanResult := ScanToolDescription(tool)
		if scanResult.Poisoned {
			removed++
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] POISONED tool hidden: %s (%d signals)\n",
				tool.Name, len(scanResult.Findings))
			for _, f := range scanResult.Findings {
				_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s\n", f.Signal, f.Detail)
			}

			// Audit the poisoned tool
			if h.OnAudit != nil {
				reasons := make([]string, 0, len(scanResult.Findings))
				for _, f := range scanResult.Findings {
					reasons = append(reasons, string(f.Signal)+": "+f.Detail)
				}
				h.OnAudit(AuditEntry{
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
					ToolName:       tool.Name,
					Decision:       "BLOCK",
					Flagged:        true,
					TriggeredRules: []string{"tool-description-poisoning"},
					Reasons:        reasons,
					Source:         "mcp-proxy-description-scan",
					ServerName:     h.ServerName,
				})
			}
			continue
		}
		clean = append(clean, tool)
	}

	if removed == 0 {
		return nil // no changes needed, use original bytes
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] tools/list: %d/%d tools passed, %d hidden\n",
		len(clean), len(listResult.Tools), removed)

	// Rebuild the response with filtered tools
	listResult.Tools = clean
	newResult, err := json.Marshal(listResult)
	if err != nil {
		return nil
	}

	msg.Result = newResult
	out, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return out
}

// FilterToolCallResponse checks if a response is a tools/call result.
// If it is, scans each text content item for prompt injection, action directives,
// exfiltration instructions, and encoded payloads. When poisoned content is found
// the entire response is replaced with an error to prevent the payload reaching
// the LLM context.
// Returns the replacement JSON bytes, or nil if the message is not a tools/call
// response or no poisoning was detected.
func (h *MessageHandler) FilterToolCallResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	// Try to parse as CallToolResult — must have a content array
	var callResult CallToolResult
	if err := json.Unmarshal(msg.Result, &callResult); err != nil {
		return nil
	}
	if len(callResult.Content) == 0 {
		return nil
	}

	scanResult := ScanToolCallResponse(callResult.Content)
	if !scanResult.Poisoned {
		return nil
	}

	// Build human-readable reason from the first finding
	reason := "tool response contains injected instructions"
	if len(scanResult.Findings) > 0 {
		reason = string(scanResult.Findings[0].Signal) + ": " + scanResult.Findings[0].Detail
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] POISONED tool response blocked (%d signals)\n",
		len(scanResult.Findings))
	for _, f := range scanResult.Findings {
		_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s\n", f.Signal, f.Detail)
	}

	// Audit the poisoned response
	if h.OnAudit != nil {
		reasons := make([]string, 0, len(scanResult.Findings))
		for _, f := range scanResult.Findings {
			reasons = append(reasons, string(f.Signal)+": "+f.Detail)
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "unknown", // response path doesn't carry tool name
			Decision:       "BLOCK",
			Flagged:        true,
			TriggeredRules: []string{"tool-response-poisoning"},
			Reasons:        reasons,
			Source:         "mcp-proxy-response-scan",
			ServerName:     h.ServerName,
		})
	}

	// Replace the response with a JSON-RPC error so the client is informed
	// without the poisoned payload entering the LLM context.
	replacement, err := NewBlockResponse(msg.ID, reason)
	if err != nil {
		return nil
	}
	return replacement
}
