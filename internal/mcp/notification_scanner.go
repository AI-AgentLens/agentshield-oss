package mcp

import (
	"encoding/json"
	"strings"
)

// NotificationSignal identifies a type of threat found in an MCP notification.
type NotificationSignal string

const (
	SignalNotificationInjection  NotificationSignal = "notification_injection"  // prompt injection / instruction override
	SignalNotificationCredential NotificationSignal = "notification_credential"  // credential harvesting reference
	SignalNotificationExfil      NotificationSignal = "notification_exfiltration" // data exfiltration instruction
)

// NotificationFinding records one detected threat in an MCP notification payload.
type NotificationFinding struct {
	Signal  NotificationSignal `json:"signal"`
	Detail  string             `json:"detail"`
	Field   string             `json:"field"`            // which field triggered (data, logger, etc.)
	Snippet string             `json:"snippet,omitempty"` // up to 80 chars of matching text
}

// NotificationScanResult is the result of scanning a notifications/message payload.
type NotificationScanResult struct {
	Blocked  bool                  `json:"blocked"`
	Findings []NotificationFinding `json:"findings,omitempty"`
}

// LoggingMessageParams represents the params of a notifications/message payload.
// Per the MCP spec, the server sends this to deliver log messages to the client.
type LoggingMessageParams struct {
	Level  string      `json:"level"`
	Logger string      `json:"logger,omitempty"`
	Data   interface{} `json:"data"`
}

// ScanNotificationMessage scans a notifications/message payload for prompt injection,
// credential harvesting, and exfiltration patterns. Because notifications are
// server-initiated push events (no prior tool call required), any injection pattern
// in the data field is treated as high-confidence — attacker-controlled content.
func ScanNotificationMessage(rawParams json.RawMessage) NotificationScanResult {
	var result NotificationScanResult
	if len(rawParams) == 0 {
		return result
	}

	var params LoggingMessageParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return result // fail open on parse error
	}

	// Extract string representation of the data field
	dataStr := extractNotificationDataString(params.Data)
	loggerStr := params.Logger

	// Scan the data field (primary injection surface)
	if dataStr != "" {
		scanNotificationField(&result, dataStr, "data")
	}

	// Scan the logger field (secondary injection surface — less common but possible)
	if loggerStr != "" {
		scanNotificationField(&result, loggerStr, "logger")
	}

	result.Blocked = len(result.Findings) > 0
	return result
}

// scanNotificationField checks one field of the notification for injection patterns.
func scanNotificationField(result *NotificationScanResult, text, field string) {
	lower := strings.ToLower(text)
	snip := text
	if len(snip) > 80 {
		snip = snip[:80] + "..."
	}

	// Injection / instruction override patterns (highest priority)
	for _, p := range hiddenInstructionPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationInjection,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break // one finding per category per field
		}
	}

	// Behavioral manipulation / jailbreak patterns
	for _, p := range behavioralManipulationPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationInjection,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Credential harvesting references
	for _, p := range credentialHarvestPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationCredential,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Exfiltration instruction patterns
	for _, p := range exfiltrationPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationExfil,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}
}

// extractNotificationDataString converts the data field to a string for scanning.
// MCP spec allows data to be any JSON value; we coerce it to a string.
func extractNotificationDataString(data interface{}) string {
	if data == nil {
		return ""
	}
	switch v := data.(type) {
	case string:
		return v
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(b)
	}
}
