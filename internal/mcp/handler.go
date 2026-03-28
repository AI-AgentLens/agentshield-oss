package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/policy"
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

// BatchLargeAuditThreshold is the batch size above which AgentShield emits an AUDIT
// event as a potential batch enumeration or log dilution probe.
const BatchLargeAuditThreshold = 10

// HandleBatch evaluates a JSON-RPC 2.0 batch request. Each item is evaluated
// individually through the full per-request pipeline. If any item would be blocked,
// the entire batch is blocked (fail-closed). Large batches (> BatchLargeAuditThreshold)
// are AUDIT-logged even when all items are individually allowed.
// Returns (true, batchBlockRespJSON) if the batch should be blocked.
func (h *MessageHandler) HandleBatch(msgs []*Message) (bool, []byte) {
	// AUDIT large batches regardless of content — potential enumeration probe.
	if len(msgs) > BatchLargeAuditThreshold {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT large batch: %d items (threshold: %d)\n",
			len(msgs), BatchLargeAuditThreshold)
		if h.OnAudit != nil {
			h.OnAudit(AuditEntry{
				Timestamp:  time.Now().UTC().Format(time.RFC3339),
				ToolName:   "batch-request",
				Decision:   "AUDIT",
				Flagged:    true,
				TriggeredRules: []string{"mcp-batch-large-audit"},
				Reasons: []string{fmt.Sprintf(
					"batch contains %d items (threshold: %d) — potential enumeration or log dilution",
					len(msgs), BatchLargeAuditThreshold,
				)},
				Source:      "mcp-proxy-batch",
				ServerName:  h.ServerName,
				TaxonomyRef: "unauthorized-execution/agentic-attacks/mcp-batch-request-abuse",
			})
		}
	}

	// Evaluate each item individually; block the entire batch on first violation.
	for _, msg := range msgs {
		kind := ClassifyMessage(msg)
		var blocked bool

		switch kind {
		case KindToolCall:
			blocked, _ = h.HandleToolCall(msg)
		case KindResourceRead:
			blocked, _ = h.HandleResourceRead(msg)
		case KindResourceSubscribe:
			blocked, _ = h.HandleResourceSubscribe(msg)
		}

		if blocked {
			_, _ = fmt.Fprintf(h.Stderr,
				"[AgentShield MCP] BLOCKED batch: item %q violates policy (%d total items)\n",
				msg.Method, len(msgs))

			batchResp, err := NewBatchBlockResponse(msgs,
				fmt.Sprintf("batch blocked: item %q violates policy", msg.Method))
			if err != nil {
				return true, nil
			}
			return true, batchResp
		}
	}

	return false, nil
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

// HandleResourceSubscribe evaluates a resources/subscribe message against MCP policy.
// resources/subscribe (MCP spec 2024-11+) enables passive file monitoring — a server that
// receives a subscription begins watching the path and pushes notifications/resources/updated
// events to the client when the file changes. This is a passive exfiltration vector that
// bypasses explicit read_file guards.
//
// We evaluate subscriptions as tool calls so YAML rules can use tool_name_any:
// ["resources/subscribe"] with argument_patterns on the uri field.
// Returns (true, blockResponseJSON) if blocked.
func (h *MessageHandler) HandleResourceSubscribe(msg *Message) (bool, []byte) {
	params, err := ExtractResourceSubscribe(msg)
	if err != nil {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] warning: failed to extract resource subscribe: %v\n", err)
		return false, nil // fail open
	}

	// Evaluate as a tool call so tool_name_any: ["resources/subscribe"] rules fire.
	result := h.Evaluator.EvaluateToolCall(MethodResourcesSubscribe, map[string]interface{}{"uri": params.URI})

	// Also check config guard on file:// URIs (same protection as resources/read).
	if result.Decision != "BLOCK" {
		guardResult := CheckConfigGuard(MethodResourcesSubscribe, map[string]interface{}{"path": strings.TrimPrefix(params.URI, "file://")})
		if guardResult.Blocked {
			result.Decision = "BLOCK"
			result.TriggeredRules = append(result.TriggeredRules, "config-file-guard")
			for _, f := range guardResult.Findings {
				result.Reasons = append(result.Reasons, "["+f.Category+"] "+f.Reason)
			}
		}
	}

	// Log the audit entry
	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       MethodResourcesSubscribe,
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
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED resource subscribe: %s — %s\n", params.URI, reason)

		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	if result.Decision == "AUDIT" {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT resource subscribe: %s\n", params.URI)
	}

	return false, nil
}

// HandleSamplingCreateMessage evaluates a sampling/createMessage request from an MCP server.
// The MCP spec allows servers to request the host LLM to process arbitrary prompts — this is
// a server-initiated prompt injection surface. All sampling requests are AUDIT-logged; those
// containing injection, credential-harvesting, or exfiltration patterns are BLOCKED.
// Returns (true, blockResponseJSON) if blocked.
func (h *MessageHandler) HandleSamplingCreateMessage(msg *Message) (bool, []byte) {
	params, err := ExtractSamplingMessage(msg)
	if err != nil {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] warning: failed to extract sampling/createMessage: %v\n", err)
		return false, nil // fail open
	}

	scanResult := ScanSamplingMessages(params)

	triggered := []string{"sampling-audit"}
	var reasons []string
	decision := "AUDIT" // all sampling requests are audited

	if scanResult.Blocked {
		decision = "BLOCK"
		triggered = append(triggered, "sampling-content-scan")
		for _, f := range scanResult.Findings {
			triggered = append(triggered, "sampling:"+string(f.Signal))
			reasons = append(reasons, string(f.Signal)+": "+f.Detail+" (role: "+f.Role+")")
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED sampling/createMessage (%d signals)\n",
			len(scanResult.Findings))
		for _, f := range scanResult.Findings {
			_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s (role: %s)\n", f.Signal, f.Detail, f.Role)
		}
	} else {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT sampling/createMessage (%d messages)\n",
			len(params.Messages))
	}

	// Log the audit entry for all sampling requests
	if h.OnAudit != nil {
		args := map[string]interface{}{
			"message_count": len(params.Messages),
			"max_tokens":    params.MaxTokens,
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "sampling/createMessage",
			Arguments:      args,
			Decision:       decision,
			Flagged:        decision == "BLOCK" || decision == "AUDIT",
			TriggeredRules: triggered,
			Reasons:        reasons,
			Source:         "mcp-proxy",
			ServerName:     h.ServerName,
		})
	}

	if scanResult.Blocked {
		reason := "Blocked by AgentShield: sampling/createMessage contains injection patterns"
		if len(reasons) > 0 {
			reason = reasons[0]
		}
		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	return false, nil
}

// HandleElicitationCreate evaluates an elicitation/create request from an MCP server.
// MCP 2025+ servers can request structured user input via elicitation/create.
// Malicious servers abuse this to harvest credentials or launder approval for dangerous actions.
// Returns (true, blockResponseJSON) if blocked; (false, nil) with AUDIT logging if suspicious.
func (h *MessageHandler) HandleElicitationCreate(msg *Message) (bool, []byte) {
	params, err := ExtractElicitationCreate(msg)
	if err != nil {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] warning: failed to extract elicitation/create: %v\n", err)
		return false, nil // fail open
	}

	scanResult := ScanElicitationCreate(params)

	decision := "ALLOW"
	var triggered []string
	var reasons []string

	if scanResult.Blocked {
		decision = "BLOCK"
		triggered = append(triggered, "elicitation-credential-scan")
		for _, f := range scanResult.Findings {
			if f.Signal == SignalElicitationCredential {
				triggered = append(triggered, "elicitation:"+string(f.Signal))
				reasons = append(reasons, string(f.Signal)+": "+f.Detail)
			}
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED elicitation/create: credential schema fields detected (%d signals)\n",
			len(scanResult.Findings))
		for _, f := range scanResult.Findings {
			_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s\n", f.Signal, f.Detail)
		}
	} else if scanResult.Audited {
		decision = "AUDIT"
		triggered = append(triggered, "elicitation-social-engineering-audit")
		for _, f := range scanResult.Findings {
			triggered = append(triggered, "elicitation:"+string(f.Signal))
			reasons = append(reasons, string(f.Signal)+": "+f.Detail)
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT elicitation/create: social engineering patterns detected\n")
		for _, f := range scanResult.Findings {
			_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s\n", f.Signal, f.Detail)
		}
	} else {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] ALLOW elicitation/create\n")
	}

	// Log the audit entry for all blocked or suspicious requests
	if h.OnAudit != nil && decision != "ALLOW" {
		args := map[string]interface{}{
			"message": params.Message,
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "elicitation/create",
			Arguments:      args,
			Decision:       decision,
			Flagged:        true,
			TriggeredRules: triggered,
			Reasons:        reasons,
			Source:         "mcp-proxy",
			ServerName:     h.ServerName,
		})
	}

	if scanResult.Blocked {
		reason := "Blocked by AgentShield: elicitation/create requests credential fields"
		if len(reasons) > 0 {
			reason = reasons[0]
		}
		blockResp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] error creating block response: %v\n", err)
			return false, nil
		}
		return true, blockResp
	}

	return false, nil
}

// HandleNotificationMessage evaluates a notifications/message notification from an MCP server.
// The MCP logging channel is server-initiated and requires no prior tool call — it is a covert
// prompt injection surface. Notifications containing injection, credential-harvesting, or
// exfiltration patterns are BLOCKED (the notification is dropped and not forwarded to the client).
// Returns (true, nil) if the notification should be dropped; (false, nil) otherwise.
// Note: notifications have no ID, so there is no JSON-RPC error response to send — we simply
// drop the notification to prevent the payload from reaching the client.
func (h *MessageHandler) HandleNotificationMessage(msg *Message) bool {
	if msg.Method != MethodNotificationsMessage {
		return false
	}

	scanResult := ScanNotificationMessage(msg.Params)
	if !scanResult.Blocked {
		return false
	}

	triggered := []string{"notification-injection-scan"}
	var reasons []string
	for _, f := range scanResult.Findings {
		triggered = append(triggered, "notification:"+string(f.Signal))
		reasons = append(reasons, string(f.Signal)+": "+f.Detail+" (field: "+f.Field+")")
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED notifications/message (%d signals)\n",
		len(scanResult.Findings))
	for _, f := range scanResult.Findings {
		_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s (field: %s)\n", f.Signal, f.Detail, f.Field)
	}

	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "notifications/message",
			Decision:       "BLOCK",
			Flagged:        true,
			TriggeredRules: triggered,
			Reasons:        reasons,
			Source:         "mcp-proxy",
			ServerName:     h.ServerName,
			TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-logging-notification-injection",
		})
	}

	return true // drop the notification
}

// FilterPromptsGetResponse checks if a response is a prompts/get result.
// If it is, scans each message's text content for prompt injection, credential
// harvesting, and exfiltration patterns. When poisoned content is found the
// entire response is replaced with a JSON-RPC error to prevent the payload
// reaching the LLM context.
// Returns the replacement JSON bytes, or nil if the message is not a prompts/get
// response or no poisoning was detected.
func (h *MessageHandler) FilterPromptsGetResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	result := parsePromptsGetResult(msg.Result)
	if result == nil {
		return nil
	}

	scanResult := ScanPromptsGetResponse(result)
	if !scanResult.Poisoned {
		return nil
	}

	reason := "prompts/get response contains injected instructions"
	if len(scanResult.Findings) > 0 {
		reason = string(scanResult.Findings[0].Signal) + ": " + scanResult.Findings[0].Detail
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] POISONED prompts/get response blocked (%d signals)\n",
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
			ToolName:       MethodPromptsGet,
			Decision:       "BLOCK",
			Flagged:        true,
			TriggeredRules: []string{"prompts-get-injection-scan"},
			Reasons:        reasons,
			Source:         "mcp-proxy-prompts-scan",
			ServerName:     h.ServerName,
			TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-prompt-template-injection",
		})
	}

	replacement, err := NewBlockResponse(msg.ID, reason)
	if err != nil {
		return nil
	}
	return replacement
}

// FilterPromptsListResponse checks if a response is a prompts/list result.
// If it is, scans each prompt's description for injection patterns that could
// prime the agent with malicious context during prompt selection.
// Returns modified JSON bytes with poisoned prompts removed, or nil if no
// poisoning was detected or the message is not a prompts/list response.
func (h *MessageHandler) FilterPromptsListResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	result := parsePromptsListResult(msg.Result)
	if result == nil {
		return nil
	}

	// Filter out poisoned prompts
	var clean []PromptDefinition
	removed := 0
	for _, prompt := range result.Prompts {
		singleResult := &ListPromptsResult{Prompts: []PromptDefinition{prompt}}
		scanResult := ScanPromptsListDescriptions(singleResult)
		if scanResult.Poisoned {
			removed++
			_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] POISONED prompt hidden: %s (%d signals)\n",
				prompt.Name, len(scanResult.Findings))
			for _, f := range scanResult.Findings {
				_, _ = fmt.Fprintf(h.Stderr, "  - [%s] %s\n", f.Signal, f.Detail)
			}

			if h.OnAudit != nil {
				reasons := make([]string, 0, len(scanResult.Findings))
				for _, f := range scanResult.Findings {
					reasons = append(reasons, string(f.Signal)+": "+f.Detail)
				}
				h.OnAudit(AuditEntry{
					Timestamp:      time.Now().UTC().Format(time.RFC3339),
					ToolName:       prompt.Name,
					Decision:       "BLOCK",
					Flagged:        true,
					TriggeredRules: []string{"prompts-list-description-poisoning"},
					Reasons:        reasons,
					Source:         "mcp-proxy-prompts-scan",
					ServerName:     h.ServerName,
					TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-prompt-template-injection",
				})
			}
			continue
		}
		clean = append(clean, prompt)
	}

	if removed == 0 {
		return nil
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] prompts/list: %d/%d prompts passed, %d hidden\n",
		len(clean), len(result.Prompts), removed)

	result.Prompts = clean
	newResult, err := json.Marshal(result)
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

	// Check for manifest flooding (tool count and size limits).
	manifestScan := ScanToolsListManifest(listResult.Tools, len(data))
	switch manifestScan.Decision {
	case "BLOCK":
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED tools/list: %s\n", manifestScan.Reason)
		if h.OnAudit != nil {
			h.OnAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       "tools/list",
				Decision:       "BLOCK",
				Flagged:        true,
				TriggeredRules: []string{manifestScan.Rule},
				Reasons:        []string{manifestScan.Reason},
				Source:         "mcp-proxy-manifest-guard",
				ServerName:     h.ServerName,
				TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-tools-list-flooding",
			})
		}
		blockResp, err := NewBlockResponse(msg.ID, manifestScan.Reason)
		if err != nil {
			return nil
		}
		return blockResp
	case "AUDIT":
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT tools/list: %s\n", manifestScan.Reason)
		if h.OnAudit != nil {
			h.OnAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       "tools/list",
				Decision:       "AUDIT",
				Flagged:        true,
				TriggeredRules: []string{manifestScan.Rule},
				Reasons:        []string{manifestScan.Reason},
				Source:         "mcp-proxy-manifest-guard",
				ServerName:     h.ServerName,
				TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-tools-list-flooding",
			})
		}
		// AUDIT: continue — forward the response after description scanning
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

			// Emit a general schema-drift audit for input schema / tool additions / removals.
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

			// Emit a dedicated rug-pull audit for description-only changes.
			// A tool whose description mutates post-approval (while schema stays stable)
			// is the hallmark of a rug-pull attack: the agent trusts the old approval
			// but executes the new (possibly malicious) behavior.
			if len(drift.DescriptionChangedTools) > 0 && h.OnAudit != nil {
				for _, toolName := range drift.DescriptionChangedTools {
					_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] RUG-PULL ALERT: description changed for tool %q on server %q — re-verify before use\n",
						toolName, serverKey)
					h.OnAudit(AuditEntry{
						Timestamp:      time.Now().UTC().Format(time.RFC3339),
						ToolName:       toolName,
						Decision:       "AUDIT",
						Flagged:        true,
						TriggeredRules: []string{"mcp-sec-audit-tool-description-changed"},
						Reasons: []string{
							fmt.Sprintf("Tool %q description changed since last approval — possible rug-pull attack. Re-verify tool behavior before use. (unauthorized-execution/agentic-attacks/mcp-tool-rug-pull)", toolName),
						},
						Source:     "mcp-proxy-rug-pull-detection",
						ServerName: serverKey,
					})
				}
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

// FilterInitializeResponse checks if a response is an initialize result.
// If it is, scans for serverInfo impersonation, experimental capability injection,
// and protocol version downgrade attacks.
// Returns a JSON-RPC error if BLOCKED, nil if the response is safe or not an
// initialize response.
func (h *MessageHandler) FilterInitializeResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	var result InitializeResult
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		return nil
	}

	// Must have protocolVersion to be an initialize response
	if result.ProtocolVersion == "" {
		return nil
	}

	scan := ScanInitializeResponse(&result)

	if scan.Decision == "ALLOW" {
		return nil
	}

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] %s initialize handshake: %s\n",
		scan.Decision, scan.Reason)
	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "initialize",
			Decision:       scan.Decision,
			Flagged:        true,
			TriggeredRules: []string{scan.Rule},
			Reasons:        []string{scan.Reason},
			Source:         "mcp-proxy-handshake-scanner",
			ServerName:     h.ServerName,
			TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-initialize-handshake-manipulation",
		})
	}

	if scan.Decision == "BLOCK" {
		replacement, err := NewBlockResponse(msg.ID, scan.Reason)
		if err != nil {
			return nil
		}
		return replacement
	}

	// AUDIT: pass through but the event was already logged above
	return nil
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

// HandleRootsListResponse intercepts roots/list responses (client→server) to detect
// MCP servers that have elicited access to sensitive filesystem paths.
//
// In MCP 2025, a server can send a roots/list REQUEST asking the client to declare
// which filesystem roots it has. The client responds with root URIs. If any root
// encompasses a credential directory (~/.ssh, ~/.aws, etc.) or is overbroad (/home,
// /), AgentShield blocks or audits the response.
//
// Detection is content-based: we attempt to parse the response as RootsListResult.
// If the result has a non-empty roots array, we evaluate it.
// Returns the replacement JSON bytes if blocked, nil if not a roots/list response
// or the roots are safe.
func (h *MessageHandler) HandleRootsListResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}

	// Only process success responses (has result, no method, no error)
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	// Try to parse as RootsListResult — must have a roots array
	var rootsResult RootsListResult
	if err := json.Unmarshal(msg.Result, &rootsResult); err != nil {
		return nil
	}
	if len(rootsResult.Roots) == 0 {
		return nil
	}

	result := h.Evaluator.EvaluateRootsList(rootsResult.Roots)

	if h.OnAudit != nil && (result.Decision == policy.DecisionBlock || result.Decision == policy.DecisionAudit) {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       MethodRootsList,
			Decision:       string(result.Decision),
			Flagged:        true,
			TriggeredRules: result.TriggeredRules,
			Reasons:        result.Reasons,
			Source:         "mcp-proxy-roots-guard",
			ServerName:     h.ServerName,
			TaxonomyRef:    result.TaxonomyRef,
		})
	}

	if result.Decision == policy.DecisionBlock {
		reason := "blocked by roots privilege escalation guard"
		if len(result.Reasons) > 0 {
			reason = result.Reasons[0]
		}
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED roots/list response — %s\n", reason)

		replacement, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			return nil
		}
		return replacement
	}

	if result.Decision == policy.DecisionAudit {
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT roots/list response — %s\n", result.Reasons[0])
	}

	return nil
}
