package mcp

import (
	"encoding/json"
	"strings"
)

// PromptsScanResult is the result of scanning a prompts/get or prompts/list payload.
type PromptsScanResult struct {
	Poisoned bool            `json:"poisoned"`
	Findings []PromptFinding `json:"findings,omitempty"`
}

// PromptFinding records one detected threat in a prompts response.
type PromptFinding struct {
	Signal  NotificationSignal `json:"signal"`
	Detail  string             `json:"detail"`
	Field   string             `json:"field"`             // "message[N].content", "description", etc.
	Snippet string             `json:"snippet,omitempty"` // up to 80 chars of matching text
}

// ScanPromptsGetResponse scans a prompts/get response result for prompt injection,
// credential harvesting, and exfiltration patterns embedded in prompt templates.
//
// The prompts/get response contains a messages array — each message is rendered
// directly into the agent's conversation context. A malicious server can poison
// these templates with instruction-override payloads that the agent executes as
// if they were legitimate user/system instructions.
func ScanPromptsGetResponse(result *GetPromptResult) PromptsScanResult {
	var scanResult PromptsScanResult
	if result == nil {
		return scanResult
	}

	// Scan the top-level description field (injection seed for future calls)
	if result.Description != "" {
		scanPromptsField(&scanResult, result.Description, "description")
	}

	// Scan each message's text content (primary injection surface)
	for i, msg := range result.Messages {
		if msg.Content.Type == "text" && msg.Content.Text != "" {
			field := "message[" + itoa(i) + "].content"
			scanPromptsField(&scanResult, msg.Content.Text, field)
		}
	}

	scanResult.Poisoned = len(scanResult.Findings) > 0
	return scanResult
}

// ScanPromptsListDescriptions scans a prompts/list response for injection
// patterns embedded in prompt template descriptions. Descriptions shown to
// the agent during tool selection can prime it with malicious context.
func ScanPromptsListDescriptions(result *ListPromptsResult) PromptsScanResult {
	var scanResult PromptsScanResult
	if result == nil {
		return scanResult
	}

	for _, prompt := range result.Prompts {
		if prompt.Description != "" {
			field := "prompt[" + prompt.Name + "].description"
			scanPromptsField(&scanResult, prompt.Description, field)
		}
	}

	scanResult.Poisoned = len(scanResult.Findings) > 0
	return scanResult
}

// scanPromptsField checks one text field of a prompts response for injection patterns.
func scanPromptsField(result *PromptsScanResult, text, field string) {
	lower := strings.ToLower(text)
	snip := text
	if len(snip) > 80 {
		snip = snip[:80] + "..."
	}

	// Injection / instruction override patterns
	for _, p := range hiddenInstructionPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationInjection,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Behavioral manipulation / jailbreak patterns
	for _, p := range behavioralManipulationPatterns {
		if p.re.MatchString(lower) {
			result.Findings = append(result.Findings, PromptFinding{
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
			result.Findings = append(result.Findings, PromptFinding{
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
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationExfil,
				Detail:  p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}
}

// itoa converts a small integer to a string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}

// parsePromptsGetResult parses a JSON-RPC result as GetPromptResult.
// Returns nil if the data does not represent a prompts/get response.
func parsePromptsGetResult(data json.RawMessage) *GetPromptResult {
	if len(data) == 0 {
		return nil
	}
	var result GetPromptResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	// Must have a messages array to be a prompts/get response
	if result.Messages == nil {
		return nil
	}
	return &result
}

// parsePromptsListResult parses a JSON-RPC result as ListPromptsResult.
// Returns nil if the data does not represent a prompts/list response.
func parsePromptsListResult(data json.RawMessage) *ListPromptsResult {
	if len(data) == 0 {
		return nil
	}
	var result ListPromptsResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}
	// Must have a prompts array to be a prompts/list response
	if result.Prompts == nil {
		return nil
	}
	return &result
}
