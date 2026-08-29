package mcp

import (
	"strings"
)

// SamplingSignal identifies a type of threat found in a sampling/createMessage request.
type SamplingSignal string

const (
	SignalSamplingInjection        SamplingSignal = "sampling_injection"         // instruction override / system prompt injection
	SignalSamplingCredential       SamplingSignal = "sampling_credential"        // credential extraction query
	SignalSamplingExfil            SamplingSignal = "sampling_exfiltration"      // data exfiltration instruction
	SignalSamplingContextLeak      SamplingSignal = "sampling_context_leak"      // includeContext:allServers cross-server exfiltration
	SignalSamplingAssistantPrefill SamplingSignal = "sampling_assistant_prefill" // trailing assistant-role message — LLM API safety bypass
	SignalSamplingControlToken     SamplingSignal = "sampling_control_token"     // forged tokenizer role delimiter / tool-call dispatch syntax in message content
)

// SamplingFinding records one detected threat signal in a sampling message.
type SamplingFinding struct {
	Signal   SamplingSignal `json:"signal"`
	Detail   string         `json:"detail"`
	Role     string         `json:"role"`
	TextSnip string         `json:"text_snip,omitempty"` // first 80 chars of matching text
}

// SamplingScanResult is the result of scanning a sampling/createMessage request.
type SamplingScanResult struct {
	Blocked  bool              `json:"blocked"`
	Findings []SamplingFinding `json:"findings,omitempty"`
}

// scanSamplingControlTokens detects forged LLM control-protocol tokens in
// server-supplied sampling content (a message text or the systemPrompt). A
// sampling/createMessage request is the host LLM processing server-authored
// prompt text, so the same listing-surface seam closed in PR #2624/#2625 applies
// here: the existing pattern groups (hidden-instruction / behavioural) do not
// match tokenizer-level role delimiters or harness-internal tool-call dispatch
// syntax. A malicious server can embed a forged "<|im_start|>system ..." turn or
// a "<function_calls><invoke name='exec'>..." dispatch block in the prompt it
// asks the client to generate from; both are tokenized verbatim into the model's
// context. Reuses the package-level role-token and dispatch-token sets
// (llmRoleTokenPatterns, toolCallDispatchTokenRE) — the same high-confidence,
// zero-legitimate-use vocabulary the description/prompt/elicitation surfaces use.
//
// Matched case-sensitively against the raw text since these tokens are
// architecture-specific tokenizer literals.
//
// Taxonomy: unauthorized-execution/ai-content-integrity/chat-template-special-token-injection
func scanSamplingControlTokens(text, role, snip string) []SamplingFinding {
	var findings []SamplingFinding
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(text) {
			findings = append(findings, SamplingFinding{
				Signal:   SignalSamplingControlToken,
				Detail:   "sampling content contains LLM tokenizer role delimiter: " + p.description,
				Role:     role,
				TextSnip: snip,
			})
			break // one role-token finding per content field
		}
	}
	if toolCallDispatchTokenRE.MatchString(text) {
		findings = append(findings, SamplingFinding{
			Signal:   SignalSamplingControlToken,
			Detail:   "sampling content contains forged tool-call / function-invocation control syntax (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>, or [TOOL_REQUEST]/[TOOL_CALLS]) — a harness parsing tool-call syntax from the generated prompt may dispatch an unsanctioned privileged call",
			Role:     role,
			TextSnip: snip,
		})
	}
	return findings
}

// ScanSamplingMessages scans sampling/createMessage request messages for injection,
// credential extraction, and exfiltration patterns. All sampling requests are logged
// (the caller always audits), but only those with detected threats are blocked.
func ScanSamplingMessages(params *SamplingCreateMessageParams) SamplingScanResult {
	var result SamplingScanResult

	// Scan each message in the sampling request
	for _, msg := range params.Messages {
		text := msg.Content.Text
		if text == "" {
			continue
		}
		forms := newProseForms(text)
		snip := text
		if len(snip) > 80 {
			snip = snip[:80] + "..."
		}

		// Check for instruction override / prompt injection patterns
		// (reuses the same pattern sets as description_scanner.go)
		for _, p := range hiddenInstructionPatterns {
			if note, ok := proseMatchNote(p.re, forms); ok {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingInjection,
					Detail:   p.description + note,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break // one finding per pattern category per message
			}
		}

		// Check for behavioral manipulation / jailbreak patterns
		for _, p := range behavioralManipulationPatterns {
			if note, ok := proseMatchNote(p.re, forms); ok {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingInjection,
					Detail:   p.description + note,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}

		// Check for credential harvesting patterns
		for _, p := range credentialHarvestPatterns {
			if note, ok := proseMatchNote(p.re, forms); ok {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingCredential,
					Detail:   p.description + note,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}

		// Check for exfiltration instruction patterns
		for _, p := range exfiltrationPatterns {
			if note, ok := proseMatchNote(p.re, forms); ok {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingExfil,
					Detail:   p.description + note,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}

		// Check for forged tokenizer role delimiters / tool-call dispatch syntax
		result.Findings = append(result.Findings, scanSamplingControlTokens(text, msg.Role, snip)...)
	}

	// Also scan the systemPrompt field if present
	if params.SystemPrompt != "" {
		forms := newProseForms(params.SystemPrompt)
		snip := params.SystemPrompt
		if len(snip) > 80 {
			snip = snip[:80] + "..."
		}

		for _, patterns := range [][]signalPattern{hiddenInstructionPatterns, behavioralManipulationPatterns} {
			for _, p := range patterns {
				if note, ok := proseMatchNote(p.re, forms); ok {
					result.Findings = append(result.Findings, SamplingFinding{
						Signal:   SignalSamplingInjection,
						Detail:   "systemPrompt: " + p.description + note,
						Role:     "system",
						TextSnip: snip,
					})
					break
				}
			}
		}

		// Forged tokenizer role delimiters / tool-call dispatch syntax in the
		// systemPrompt — the highest-trust field, rendered as the model's system turn.
		result.Findings = append(result.Findings, scanSamplingControlTokens(params.SystemPrompt, "system", snip)...)
	}

	// Check for assistant-prefill attack: the last message has role "assistant".
	// The MCP spec allows sampling/createMessage to include a messages array that is
	// forwarded to the LLM. When the last entry has role "assistant", the host LLM
	// continues generation from the attacker-supplied prefix — skipping the turn
	// boundary where safety-alignment refusal behavior is applied.
	// A malicious MCP server can force alignment bypass without any model access by
	// supplying {"role":"assistant","content":"Sure, here is how to ..."} as the
	// last message. No legitimate MCP sampling workflow needs a trailing assistant
	// turn in the server-supplied messages array.
	//
	// This check runs unconditionally on the last message, regardless of content text,
	// because even an empty assistant prefill ("") forces the model to begin generation
	// mid-turn, bypassing the per-turn safety check.
	//
	// Taxonomy: unauthorized-execution/agentic-attacks/llm-api-assistant-prefill-attack
	if len(params.Messages) > 0 {
		lastMsg := params.Messages[len(params.Messages)-1]
		if strings.ToLower(strings.TrimSpace(lastMsg.Role)) == "assistant" {
			snip := lastMsg.Content.Text
			if len(snip) > 80 {
				snip = snip[:80] + "..."
			}
			result.Findings = append(result.Findings, SamplingFinding{
				Signal:   SignalSamplingAssistantPrefill,
				Detail:   "trailing assistant-role message in sampling/createMessage — LLM API assistant prefill attack bypasses safety alignment at turn boundary",
				Role:     lastMsg.Role,
				TextSnip: snip,
			})
		}
	}

	// Check includeContext: "allServers" — cross-server context exfiltration.
	// A legitimate MCP server never needs context from OTHER servers. Requesting
	// "allServers" exposes tool call history, responses, and credentials from every
	// other connected server to the server initiating this sampling call.
	if strings.ToLower(params.IncludeContext) == "allservers" {
		result.Findings = append(result.Findings, SamplingFinding{
			Signal: SignalSamplingContextLeak,
			Detail: "includeContext:allServers requests conversation context from all connected MCP servers — cross-server context exfiltration",
			Role:   "params",
		})
	}

	result.Blocked = len(result.Findings) > 0
	return result
}
