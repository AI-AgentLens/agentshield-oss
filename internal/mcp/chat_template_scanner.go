package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// ChatTemplateSignal identifies a chat-template role-delimiter token found in an
// MCP tool-call argument value (or a tool result flowing back to the agent).
type ChatTemplateSignal string

const (
	// SignalChatTemplateToken fires when an inert content field of a tool call (or a
	// tool result) carries a model-family chat-template role-delimiter control token —
	// ChatML (<|im_start|>/<|im_end|>), Mistral/Llama-2 ([INST]/[/INST], <<SYS>>),
	// Llama-3 (<|start_header_id|>/<|eot_id|>), Gemma (<start_of_turn>), Phi-3
	// (<|system|>). When an application renders the conversation through the chat
	// template without escaping these tokens, the injected delimiters are tokenized
	// as genuine turn boundaries, letting an attacker forge a system/assistant turn.
	//
	// AUDIT by default: these tokens legitimately appear in code, docs, and
	// taxonomy/test fixtures *about* LLMs, so a bare occurrence is not proof of
	// attack. Precision is kept high by only escalating to BLOCK when a corroborating
	// forged-turn / instruction-override phrase co-occurs in the same value.
	SignalChatTemplateToken ChatTemplateSignal = "chat_template_token"

	// SignalToolInvocationToken fires when an inert content field of a tool call — or
	// a tool result / resource flowing back to the agent — carries forged
	// tool-CALL / function-INVOCATION control syntax: the Anthropic harness
	// wrapper / invoke element, generic <tool_call>/<tool_use> elements, the
	// pipe-delimited python-tag / tool-call tokens, or the Llama/Mistral bracket
	// request markers. Distinct from SignalChatTemplateToken: a role delimiter forges
	// a conversation TURN; tool-invocation syntax forges a tool CALL that an agent
	// harness may parse and dispatch — a response-to-tool-call confusion that
	// promotes attacker-chosen content into an unsanctioned privileged invocation.
	//
	// Same precision model as the role-delimiter signal: AUDIT on a bare token
	// (coding agents legitimately read source/docs containing this syntax via
	// read_file / docs-search), BLOCK only when a corroborating instruction-override
	// / forged-turn phrase co-occurs in the same value.
	SignalToolInvocationToken ChatTemplateSignal = "tool_invocation_token"
)

// ChatTemplateFinding records one detected chat-template token occurrence.
type ChatTemplateFinding struct {
	Signal  ChatTemplateSignal
	Detail  string
	ArgName string
	// Corroborated is true when an instruction-override / forged-turn phrase
	// co-occurs with the token in the same value — the BLOCK trigger.
	Corroborated bool
}

// ChatTemplateScanResult is the result of a chat-template token scan.
type ChatTemplateScanResult struct {
	// Blocked is true when at least one finding is corroborated by injection phrasing.
	Blocked bool
	// Audited is true when at least one (uncorroborated) token finding was recorded.
	Audited  bool
	Findings []ChatTemplateFinding
}

// chatTemplateContentArgNames are the argument keys that carry inert content an
// agent may later splice into a prompt — the surface where a smuggled delimiter
// becomes a forged turn. Path/URL/numeric args are deliberately excluded (a
// delimiter in a `path` is not a template-rendering vector).
var chatTemplateContentArgNames = map[string]bool{
	"content":     true,
	"text":        true,
	"body":        true,
	"message":     true,
	"messages":    true,
	"prompt":      true,
	"input":       true,
	"data":        true,
	"value":       true,
	"document":    true,
	"chunk":       true,
	"context":     true,
	"note":        true,
	"comment":     true,
	"description": true,
	"result":      true,
	"output":      true,
	"response":    true,
	"completion":  true,
	"answer":      true,
	"snippet":     true,
	"html":        true,
	"html_body":   true,
	"plain_text":  true,
	"summary":     true,
	"transcript":  true,
}

// ScanChatTemplateTokens inspects the inert content arguments of a tool call for
// model-family chat-template role-delimiter tokens.
//
// Decision model (precision-first, per the taxonomy entry
// unauthorized-execution/ai-content-integrity/chat-template-special-token-injection):
//   - A bare delimiter token → AUDIT (legitimately appears in LLM code/docs).
//   - A delimiter token + a forged-turn / instruction-override phrase in the same
//     value → BLOCK (a forged "system" turn that countermands instructions is the
//     signature of an actual special-token injection, not documentation).
func ScanChatTemplateTokens(toolName string, arguments map[string]interface{}) ChatTemplateScanResult {
	var result ChatTemplateScanResult

	for argName, argValue := range arguments {
		if !chatTemplateContentArgNames[strings.ToLower(argName)] {
			continue
		}
		text := argValueToString(argValue)
		if text == "" {
			continue
		}
		scanControlTokensInValue(argName, text, &result)
	}

	if len(result.Findings) > 0 {
		result.Audited = true
	}
	return result
}

// ScanResponseControlTokens scans a single tool-result / resource text blob for
// chat-template role-delimiter tokens and forged tool-invocation control syntax
// flowing back to the agent (server → agent direction). A compromised MCP server
// that returns these tokens in its result attempts to forge a conversation turn or
// an unsanctioned tool call inside the agent's context. Same precision model as the
// argument-direction scan: AUDIT on a bare token, BLOCK on a corroborated one.
//
// Unlike the argument scan, no arg-name allowlist applies — a tool RESULT is
// inherently content the agent ingests, so the whole text is in scope.
func ScanResponseControlTokens(text string) ChatTemplateScanResult {
	var result ChatTemplateScanResult
	if text == "" {
		return result
	}
	scanControlTokensInValue("response", text, &result)
	if len(result.Findings) > 0 {
		result.Audited = true
	}
	return result
}

// scanControlTokensInValue detects chat-template role-delimiter tokens and
// tool-invocation control syntax in a single value and appends findings to result.
// A bare token is recorded (AUDIT); a token co-occurring with an instruction-
// override / forged-turn phrase is marked Corroborated and sets result.Blocked.
func scanControlTokensInValue(argName, text string, result *ChatTemplateScanResult) {
	roleTok := chatTemplateTokenRE.FindString(text)
	invokeTok := toolInvocationTokenRE.FindString(text)
	if roleTok == "" && invokeTok == "" {
		return
	}
	corroborated := chatTemplateInjectionPhraseRE.MatchString(text)

	if roleTok != "" {
		detail := fmt.Sprintf(
			"chat-template role-delimiter token %q in tool %s %q — content rendered through a "+
				"chat template without escaping lets this delimiter forge a conversation turn (role-delimiter forgery)",
			truncToken(roleTok), surfaceWord(argName), argName)
		if corroborated {
			detail += "; co-occurs with an instruction-override / forged-turn phrase — high-confidence special-token injection"
		}
		result.Findings = append(result.Findings, ChatTemplateFinding{
			Signal:       SignalChatTemplateToken,
			Detail:       detail,
			ArgName:      argName,
			Corroborated: corroborated,
		})
	}

	if invokeTok != "" {
		detail := fmt.Sprintf(
			"forged tool-invocation control token %q in tool %s %q — an agent harness that parses "+
				"tool-call syntax from content may dispatch this as an unsanctioned tool call "+
				"(response-to-tool-call confusion)",
			truncToken(invokeTok), surfaceWord(argName), argName)
		if corroborated {
			detail += "; co-occurs with an instruction-override / forged-turn phrase — high-confidence tool-call injection"
		}
		result.Findings = append(result.Findings, ChatTemplateFinding{
			Signal:       SignalToolInvocationToken,
			Detail:       detail,
			ArgName:      argName,
			Corroborated: corroborated,
		})
	}

	if corroborated {
		result.Blocked = true
	}
}

// surfaceWord renders the surface noun for a finding detail: a tool result uses
// "result", any other name is an "argument".
func surfaceWord(argName string) string {
	if argName == "response" {
		return "result"
	}
	return "argument"
}

// truncToken caps a matched token for inclusion in a human-readable detail string.
func truncToken(m string) string {
	if len(m) > 48 {
		return m[:48] + "…"
	}
	return m
}

// chatTemplateTokenRE matches model-family chat-template role-delimiter control
// tokens. Built from fragments so the literal protected delimiters never appear
// raw in this source file (keeps the dogfooding shell hook / the description
// scanner's own llm_role_token signal from tripping on this file). Mirrors the
// vocabulary of description_scanner.go's llmRoleTokenPatterns, but applied to
// tool-call ARGUMENT content rather than tool descriptions.
var chatTemplateTokenRE = func() *regexp.Regexp {
	pipe := `<` + `\|`
	pipeEnd := `\|` + `>`
	chatml := pipe + `im_(?:start|end)` + pipeEnd // <|im_start|> / <|im_end|>
	llama3 := pipe + `(?:start_header_id|end_header_id|eot_id)` + pipeEnd
	phi3 := pipe + `(?:system|user|assistant)` + pipeEnd
	mistralSys := `<<` + `SYS>>|<<` + `/SYS>>`
	mistralInst := `\[` + `/?INST\]` // [INST] and [/INST]
	gemma := `<(?:start|end)_of_turn>`
	return regexp.MustCompile(`(?i)(` +
		chatml + `|` +
		llama3 + `|` +
		phi3 + `|` +
		mistralSys + `|` +
		mistralInst + `|` +
		gemma + `)`)
}()

// toolInvocationTokenRE matches forged tool-CALL / function-INVOCATION control
// syntax — the delimiters an agent harness uses to mark a tool call it should
// dispatch. Built from fragments so the literal tokens never appear raw in this
// source file (keeps the dogfooding shell/content scanner and the description
// scanner's llm_role_token signal from tripping on this file).
//
// Families: the Anthropic harness call wrapper / invoke element, generic
// <tool_call>/<tool_use> XML elements, the pipe-delimited python-tag / tool-call
// tokens, the Llama/Mistral bracket request markers, and the Gemini CLI
// tool-response boundary markers.
//
// Gemini CLI's <~> tool-call marker (arXiv:2607.05120, "Agent Data Injection
// Attacks", Sec 4.3 "ADI against Real-World Coding Agents") is deliberately
// NOT included: unlike every other token in this family it is pure punctuation
// with no distinguishing word content, and a 3-character <~> sequence has a
// real collision surface in ASCII diagrams and approximate-value notation. The
// <ctrl46>/<tool_response_start>/<tool_response_end> markers are included —
// each carries distinctive word content with negligible collision risk, same
// bar as the other alternatives here.
var toolInvocationTokenRE = func() *regexp.Regexp {
	lt := `<`
	lb := `\[`
	pipe := lt + `\|`
	pipeEnd := `\|` + `>`
	fnCalls := lt + `/?\s*function_calls\s*>`                 // <function_calls> / </function_calls>
	invoke := lt + `invoke\s+name\s*=`                        // <invoke name=
	toolCallXML := lt + `/?\s*tool_(?:call|use)\s*>`          // <tool_call> </tool_call> <tool_use>
	pyTag := pipe + `python_tag` + pipeEnd                    // <|python_tag|>
	toolCallPipe := pipe + `tool_call` + pipeEnd              // <|tool_call|>
	toolReq := lb + `TOOL_REQUEST\]`                          // [TOOL_REQUEST]
	toolCalls := lb + `/?TOOL_CALLS\]`                        // [TOOL_CALLS] / [/TOOL_CALLS]
	geminiCtrl := lt + `ctrl46>`                              // <ctrl46> (Gemini CLI tool-response marker)
	geminiResp := lt + `/?\s*tool_response_(?:start|end)\s*>` // <tool_response_start> / <tool_response_end>
	return regexp.MustCompile(`(?i)(` +
		fnCalls + `|` +
		invoke + `|` +
		toolCallXML + `|` +
		pyTag + `|` +
		toolCallPipe + `|` +
		toolReq + `|` +
		toolCalls + `|` +
		geminiCtrl + `|` +
		geminiResp + `)`)
}()

// chatTemplateInjectionPhraseRE matches the corroborating injection phrasing that
// escalates a token finding from AUDIT to BLOCK: a forged role turn that
// countermands the real instructions. Fragmented to avoid self-triggering.
var chatTemplateInjectionPhraseRE = func() *regexp.Regexp {
	ignore := `ign` + `ore\s+(?:all\s+)?(?:prior|previous|above|earlier)\s+(?:instruction|rule|direction|message)`
	disregard := `disreg` + `ard\s+(?:all\s+)?(?:prior|previous|the\s+above)\s+(?:instruction|rule|direction)`
	youAreNow := `you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|in\s+unrestricted|developer|dan|jailbroken|admin)`
	newSystem := `(?:new\s+)?system\s+(?:prompt|message|instruction)s?\s*[:=]`
	overrideSafety := `(?:override|bypass|ignore|disable)\s+(?:all\s+)?(?:safety|guard ?rails?|restrictions?|filters?)`
	forgedRole := `(?:^|\n)\s*(?:system|assistant)\s*[:>]\s*\S` // forged "system:" / "assistant>" turn
	return regexp.MustCompile(`(?i)(` +
		ignore + `|` +
		disregard + `|` +
		youAreNow + `|` +
		newSystem + `|` +
		overrideSafety + `|` +
		forgedRole + `)`)
}()
