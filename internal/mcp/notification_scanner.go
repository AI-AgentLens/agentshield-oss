package mcp

import (
	"encoding/json"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// NotificationSignal identifies a type of threat found in an MCP notification.
type NotificationSignal string

const (
	SignalNotificationInjection  NotificationSignal = "notification_injection"  // prompt injection / instruction override
	SignalNotificationCredential NotificationSignal = "notification_credential"  // credential harvesting reference
	SignalNotificationExfil      NotificationSignal = "notification_exfiltration" // data exfiltration instruction
	// SignalNotificationConfusable flags a programmatic identifier (an MCP prompt
	// NAME or prompt-argument NAME) that contains Unicode confusables, invisible
	// characters, bidi overrides, Unicode tag chars, or control characters. Prompt
	// names are slash-command identifiers the host renders verbatim and the user
	// selects by sight; a homoglyph (`cоde_review`, Cyrillic о) or zero-width
	// character impersonates a trusted prompt — the prompts-surface analogue of
	// the tool-name confusable check (SignalToolNameConfusable). See prompts_scanner.go.
	SignalNotificationConfusable  NotificationSignal = "notification_confusable"
	// SignalNotificationControlToken flags a forged LLM tokenizer role delimiter
	// (<|im_start|>, [INST], <<SYS>>) or tool-call dispatch syntax
	// (<function_calls>/<invoke name=>, <|python_tag|>/<|tool_call|>,
	// [TOOL_REQUEST]/[TOOL_CALLS]) embedded in a server-push notification field.
	// Notifications arrive without a prior tool call, so any embedded control
	// token is unambiguously attacker-supplied. Same vocabulary as the description/
	// prompts/elicitation/sampling surfaces — no legitimate MCP notification carries
	// tokenizer-architecture syntax in its data or message fields.
	SignalNotificationControlToken NotificationSignal = "notification_control_token"
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

// ProgressNotificationParams represents the params of a notifications/progress payload.
// Per the MCP 2025 spec, the server sends this to report progress on long-running operations.
// The message field is free text — it is the primary injection surface.
type ProgressNotificationParams struct {
	ProgressToken interface{} `json:"progressToken"`
	Progress      float64     `json:"progress"`
	Total         float64     `json:"total,omitempty"`
	Message       string      `json:"message,omitempty"`
}

// ScanProgressNotification scans a notifications/progress payload for prompt injection,
// credential harvesting, and exfiltration patterns in the message field.
// Structurally identical attack surface to notifications/message but uses a different
// method and field — a server can embed adversarial instructions in progress messages
// to bypass argument-level scanning (the notification arrives with no prior tool call).
func ScanProgressNotification(rawParams json.RawMessage) NotificationScanResult {
	var result NotificationScanResult
	if len(rawParams) == 0 {
		return result
	}

	var params ProgressNotificationParams
	if err := json.Unmarshal(rawParams, &params); err != nil {
		return result // fail open on parse error
	}

	if params.Message != "" {
		scanNotificationField(&result, params.Message, "message")
	}

	result.Blocked = len(result.Findings) > 0
	return result
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
// scanNotificationField scans one notification field, then re-scans a
// separator-normalized rendering of it and keeps whatever the raw pass missed.
//
// Notifications are the purest form of this problem: they are server-initiated
// push events that arrive with no prior tool call, so the text goes into the
// model's context without any argument-level scanning in front of it. The
// patterns reused here (hiddenInstructionPatterns, behavioralManipulationPatterns,
// …) are the same `\s+`-spelled groups the description scanner uses, and RE2's
// `\s` is ASCII-only — so before this wrapper, an override directive fired on
// `notifications/message` in ASCII and produced ZERO findings when its spaces
// were U+00A0. Same for `notifications/progress`, which shares this function.
//
// Wrapping here rather than at the two call sites is deliberate: it is the one
// chokepoint both entry points already funnel through, so a third notification
// surface added later inherits the coverage instead of quietly missing it.
//
// Additive by construction — only findings absent from the raw pass are kept,
// so benign text carrying a Unicode space folds to benign text and yields
// nothing. See scanResponseSeparatorFolded for the full rationale.
func scanNotificationField(result *NotificationScanResult, text, field string) {
	before := len(result.Findings)
	scanNotificationFieldRaw(result, text, field)

	folded, changed := unicode.FoldUnicodeSeparators(text)
	if !changed {
		return
	}

	seen := make(map[string]bool, len(result.Findings)-before)
	for _, f := range result.Findings[before:] {
		seen[string(f.Signal)+"\x00"+f.Detail] = true
	}

	var foldedResult NotificationScanResult
	scanNotificationFieldRaw(&foldedResult, folded, field)
	for _, f := range foldedResult.Findings {
		if seen[string(f.Signal)+"\x00"+f.Detail] {
			continue
		}
		f.Detail += " — recovered by folding non-ASCII Unicode separator characters to ASCII" +
			" (RE2's `\\s` class is ASCII-only, so the text as sent matched no pattern)"
		result.Findings = append(result.Findings, f)
	}
}

func scanNotificationFieldRaw(result *NotificationScanResult, text, field string) {
	forms := newProseForms(text)
	snip := text
	if len(snip) > 80 {
		snip = snip[:80] + "..."
	}

	// Injection / instruction override patterns (highest priority)
	for _, p := range hiddenInstructionPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationInjection,
				Detail:  p.description + note,
				Field:   field,
				Snippet: snip,
			})
			break // one finding per category per field
		}
	}

	// Behavioral manipulation / jailbreak patterns
	for _, p := range behavioralManipulationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationInjection,
				Detail:  p.description + note,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Credential harvesting references
	for _, p := range credentialHarvestPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationCredential,
				Detail:  p.description + note,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Exfiltration instruction patterns
	for _, p := range exfiltrationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			result.Findings = append(result.Findings, NotificationFinding{
				Signal:  SignalNotificationExfil,
				Detail:  p.description + note,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Control-token injection: forged LLM role delimiters + tool-call dispatch syntax.
	// Checked case-sensitively against the raw text (not lowercased) because these
	// are architecture-specific tokenizer literals.
	result.Findings = append(result.Findings, scanNotificationControlTokens(text, field, snip)...)
}

// scanNotificationControlTokens detects forged LLM control-protocol tokens in a
// notification field. Notifications are server-initiated push events (no prior tool
// call required), so any embedded tokenizer role delimiter or tool-call dispatch
// syntax is unambiguously attacker-supplied — there is no legitimate reason for a
// build-log or progress message to carry <|im_start|> or <function_calls> syntax.
// Mirrors scanSamplingControlTokens; reuses the package-level pattern sets defined
// in description_scanner.go.
func scanNotificationControlTokens(text, field, snip string) []NotificationFinding {
	var findings []NotificationFinding
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(text) {
			findings = append(findings, NotificationFinding{
				Signal:  SignalNotificationControlToken,
				Detail:  "notification " + field + " contains LLM tokenizer role delimiter: " + p.description,
				Field:   field,
				Snippet: snip,
			})
			break // one role-token finding per field
		}
	}
	if toolCallDispatchTokenRE.MatchString(text) {
		findings = append(findings, NotificationFinding{
			Signal:  SignalNotificationControlToken,
			Detail:  "notification " + field + " contains forged tool-call dispatch syntax (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>, or [TOOL_REQUEST]/[TOOL_CALLS]) — a harness parsing tool-call syntax from push events may dispatch an unsanctioned call",
			Field:   field,
			Snippet: snip,
		})
	}
	return findings
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
