package mcp

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// ResponsePoisonSignal identifies a type of malicious content in a tool call response.
type ResponsePoisonSignal string

const (
	// SignalResponsePromptInjection indicates hidden instructions attempting to
	// hijack the LLM's behaviour after reading a tool response.
	SignalResponsePromptInjection ResponsePoisonSignal = "response_prompt_injection"

	// SignalResponseActionDirective indicates a fabricated directive inside a
	// tool response that instructs the agent to take an action (e.g. exfiltrate
	// data, call another tool, change behaviour).
	SignalResponseActionDirective ResponsePoisonSignal = "response_action_directive"

	// SignalResponseExfilDirective indicates instructions embedded in a response
	// telling the agent to exfiltrate data to an external endpoint.
	SignalResponseExfilDirective ResponsePoisonSignal = "response_exfil_directive"

	// SignalResponseBase64Payload indicates a suspiciously large base64-encoded
	// blob in a text response field, which may be used to smuggle payloads past
	// content filters.
	SignalResponseBase64Payload ResponsePoisonSignal = "response_base64_payload"

	// SignalResponseBehavioralOverride indicates an attempt to override the
	// agent's safety guidelines or role via tool response content.
	SignalResponseBehavioralOverride ResponsePoisonSignal = "response_behavioral_override"
)

// ResponsePoisonFinding records one detected poisoning signal in a tool response.
type ResponsePoisonFinding struct {
	Signal  ResponsePoisonSignal `json:"signal"`
	Detail  string               `json:"detail"`
	Snippet string               `json:"snippet,omitempty"`
}

// ResponseScanResult is the result of scanning a single tool call response.
type ResponseScanResult struct {
	Poisoned bool                    `json:"poisoned"`
	Findings []ResponsePoisonFinding `json:"findings,omitempty"`
}

// ScanToolCallResponse scans the text content items of a tool call response for
// prompt injection, action directives, exfiltration instructions, and encoded payloads.
// It only processes ContentItems with type "text"; other types are ignored.
func ScanToolCallResponse(items []ContentItem) ResponseScanResult {
	var result ResponseScanResult

	for _, item := range items {
		if item.Type != "text" || item.Text == "" {
			continue
		}
		scanResponseText(&result, item.Text)
	}

	result.Poisoned = len(result.Findings) > 0
	return result
}

func scanResponseText(result *ResponseScanResult, text string) {
	lower := strings.ToLower(text)

	// Signal 1: Prompt injection patterns
	for _, p := range responseInjectionPatterns {
		if loc := p.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, ResponsePoisonFinding{
				Signal:  SignalResponsePromptInjection,
				Detail:  p.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 2: Action directives embedded in response text
	for _, p := range responseActionPatterns {
		if loc := p.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, ResponsePoisonFinding{
				Signal:  SignalResponseActionDirective,
				Detail:  p.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 3: Exfiltration directives
	for _, p := range responseExfilPatterns {
		if loc := p.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, ResponsePoisonFinding{
				Signal:  SignalResponseExfilDirective,
				Detail:  p.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 4: Behavioral override attempts
	for _, p := range responseBehavioralPatterns {
		if loc := p.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, ResponsePoisonFinding{
				Signal:  SignalResponseBehavioralOverride,
				Detail:  p.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 5: Large base64 blobs (>512 bytes encoded) may smuggle payloads
	scanResponseBase64(result, text)
}

// scanResponseBase64 detects suspiciously large base64-encoded content blocks.
// Legitimate tool responses occasionally include small base64 values; payloads
// used for prompt-injection or data smuggling are typically much larger.
const base64MinSuspiciousLen = 512

func scanResponseBase64(result *ResponseScanResult, text string) {
	for _, m := range base64BlockRe.FindAllString(text, -1) {
		if len(m) < base64MinSuspiciousLen {
			continue
		}
		// Attempt to decode — if it decodes cleanly it's more suspicious
		decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(m, "\n", ""))
		if err != nil {
			// Try URL-safe variant
			decoded, err = base64.URLEncoding.DecodeString(strings.ReplaceAll(m, "\n", ""))
		}
		if err == nil && len(decoded) > 256 {
			result.Findings = append(result.Findings, ResponsePoisonFinding{
				Signal:  SignalResponseBase64Payload,
				Detail:  "Large base64-encoded payload in tool response (possible data smuggling)",
				Snippet: m[:64] + "...",
			})
		}
	}
}

// base64BlockRe matches runs of base64 characters (standard and URL-safe).
var base64BlockRe = regexp.MustCompile(`[A-Za-z0-9+/\-_]{64,}={0,2}`)

// responseSignalPattern pairs a compiled regex with a human-readable description.
type responseSignalPattern struct {
	re          *regexp.Regexp
	description string
}

// responseInjectionPatterns detects classic prompt-injection markers in response text.
var responseInjectionPatterns = []responseSignalPattern{
	{regexp.MustCompile(`<important>`), "Hidden <IMPORTANT> tag in tool response"},
	{regexp.MustCompile(`<system>`), "Hidden <SYSTEM> tag in tool response"},
	{regexp.MustCompile(`<instruction>`), "Hidden <INSTRUCTION> tag in tool response"},
	{regexp.MustCompile(`\[system\]`), "Hidden [SYSTEM] marker in tool response"},
	{regexp.MustCompile(`ignore\s+(all\s+)?previous\s+instructions`), "Prompt injection: ignore previous instructions"},
	{regexp.MustCompile(`ignore\s+(all\s+)?safety`), "Prompt injection: ignore safety directives"},
	{regexp.MustCompile(`override\s+(all\s+)?(previous|system)\s+(instructions?|prompt)`), "Prompt injection: override system instructions"},
	{regexp.MustCompile(`new\s+instructions?\s+from\s+(the\s+)?(user|admin|system|owner)`), "Prompt injection: fake authority instructions"},
	{regexp.MustCompile(`\[new\s+task\]|\[override\]|\[admin\s+command\]`), "Prompt injection: fake task/command brackets"},
}

// responseActionPatterns detects directives that instruct the agent to take
// autonomous actions it would not otherwise take.
var responseActionPatterns = []responseSignalPattern{
	{regexp.MustCompile(`(you\s+must|please\s+now|next\s+(you\s+should|step\s+is\s+to))\s+(call|invoke|run|execute|send|post|upload|delete|remove|create|write)`),
		"Response instructs agent to call a tool or execute an action"},
	{regexp.MustCompile(`call\s+(the\s+)?(tool|function|api|endpoint)\s+\w+\s+(with|using|and\s+pass)`),
		"Response instructs agent to call a specific tool"},
	{regexp.MustCompile(`execute\s+(this|the\s+following)\s+(command|script|code|shell)`),
		"Response instructs agent to execute a command"},
	{regexp.MustCompile(`(delete|remove|destroy|wipe)\s+(all\s+)?(the\s+)?(files?|data|logs?|records?)`),
		"Response instructs agent to delete data"},
	{regexp.MustCompile(`(upload|send|post|transmit|forward)\s+(the\s+)?(file|data|output|result|content)\s+(to|at)\s+https?://`),
		"Response directs data upload to an external URL"},
	{regexp.MustCompile(`do\s+not\s+(tell|inform|show|display|reveal|mention)\s+(the\s+)?(user|human|operator)`),
		"Response instructs agent to hide actions from user"},
}

// responseExfilPatterns detects instructions in tool responses that attempt to
// exfiltrate data to an attacker-controlled endpoint.
var responseExfilPatterns = []responseSignalPattern{
	{regexp.MustCompile(`(read|open|cat|load)\s+.*(\.ssh|id_rsa|id_ed25519|authorized_keys|\.aws/credentials|\.env)\b`),
		"Response instructs agent to read credential files"},
	{regexp.MustCompile(`(curl|wget|fetch)\s+.*(attacker|evil|exfil|collect|receive|c2\.|c&c)`),
		"Explicit exfiltration via HTTP tool in response"},
	{regexp.MustCompile(`(send|post|upload|exfiltrate)\s+(the\s+)?(ssh|aws|api|secret|private)\s+(key|token|credential)`),
		"Response instructs exfiltration of specific credentials"},
	{regexp.MustCompile(`https?://[^\s]+[?&](data|payload|content|key|token|secret|exfil)=`),
		"URL with suspicious exfiltration query parameter in response"},
	{regexp.MustCompile(`(base64\s+encode|encode\s+in\s+base64|convert\s+to\s+base64).{0,80}(send|post|upload|forward)`),
		"Response instructs encoding and sending data"},
}

// responseBehavioralPatterns detects attempts to override agent safety guidelines
// or role via content embedded in a tool response.
var responseBehavioralPatterns = []responseSignalPattern{
	{regexp.MustCompile(`(disable|bypass|remove|ignore|circumvent)\s+(your\s+)?(safety|restrictions|filters|guidelines|limits|rules)`),
		"Response attempts to disable agent safety controls"},
	{regexp.MustCompile(`from\s+now\s+on\s+(you|your|always|never|do\s+not)`),
		"Behavioral takeover: from-now-on directive in response"},
	{regexp.MustCompile(`your\s+new\s+(role|instructions?|goal|objective)\s+(is|are)\s+`),
		"Behavioral takeover: role reassignment in response"},
	{regexp.MustCompile(`forget\s+(your|all)\s+(previous|prior|original|default)\s+(instructions?|training|guidelines?|rules?|behavior)`),
		"Behavioral takeover: forget instructions directive in response"},
	{regexp.MustCompile(`(jailbreak|developer\s+mode|dan\s+mode|unrestricted\s+mode)`),
		"Jailbreak attempt embedded in tool response"},
	{regexp.MustCompile(`you\s+are\s+(no\s+longer|now\s+free\s+from|released\s+from)\s+(your\s+)?(safety|guidelines|restrictions)`),
		"Liberation claim in tool response"},
	{regexp.MustCompile(`act\s+as\s+(if\s+you\s+(have\s+no|are\s+free|don'?t\s+have)|a\s+different\s+(ai|agent|model))`),
		"Behavioral directive: act as unrestricted agent in response"},
}
