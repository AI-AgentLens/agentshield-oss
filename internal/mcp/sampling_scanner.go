package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SamplingSignal identifies a type of threat found in a sampling/createMessage request.
type SamplingSignal string

const (
	SignalSamplingInjection         SamplingSignal = "sampling_injection"                 // instruction override / system prompt injection
	SignalSamplingCredential        SamplingSignal = "sampling_credential"                // credential extraction query
	SignalSamplingExfil             SamplingSignal = "sampling_exfiltration"              // data exfiltration instruction
	SignalSamplingContextLeak       SamplingSignal = "sampling_context_leak"              // includeContext:allServers cross-server exfiltration
	SignalSamplingAssistantPrefill  SamplingSignal = "sampling_assistant_prefill"         // trailing assistant-role message — LLM API safety bypass
	SignalSamplingControlToken      SamplingSignal = "sampling_control_token"             // forged tokenizer role delimiter / tool-call dispatch syntax in message content
	SignalSamplingToolDefinition    SamplingSignal = "sampling_tool_definition_poisoning" // SEP-1577 tools[] entry the tools/list description scanner would hide
	SignalSamplingToolLoopInjection SamplingSignal = "sampling_tool_loop_injection"       // SEP-1577 tool_use/tool_result block the tools/call response scanner would block
)

// samplingToolDefinitionSentinelEngine names the sentinel that attributes a
// SignalSamplingToolDefinition finding to a rule id and taxonomy node.
const samplingToolDefinitionSentinelEngine = "mcp-sampling-tool-definition-poisoning"

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

	// Scan each message in the sampling request. Every block the host model
	// will read is scanned, not only a single text block: see
	// samplingMessageText.
	for _, msg := range params.Messages {
		text := samplingMessageText(msg)
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

	// SEP-1577 tool-loop blocks, scanned as the tool data they are.
	for _, msg := range params.Messages {
		result.Findings = append(result.Findings, scanSamplingToolLoop(msg)...)
	}

	// Server-defined tools (SEP-1577). Same definition shape as tools/list,
	// same model-read prose, and no listing filter on the path.
	result.Findings = append(result.Findings, scanSamplingTools(params.Tools)...)

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

// samplingMessageText returns the text of every block in one sampling
// message, joined with newlines, for the per-message prompt-pattern scan.
//
// MCP 2025-11-25 (SEP-1577) made `content` a block OR an array of blocks. The
// array form used to be dropped whole by the single-object decode (see
// SamplingMessage.Blocks), so a prompt that BLOCKed as `{"type":"text",...}`
// was skipped as empty when wrapped in `[...]`. Every block's `text` is read
// regardless of its declared `type`: the type is attacker-chosen, and letting
// it decide whether a field is scanned is the same switch as letting a JSON
// shape decide it.
func samplingMessageText(msg SamplingMessage) string {
	var parts []string
	for _, b := range msg.contentBlocks() {
		if b.Text != "" {
			parts = append(parts, b.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// scanSamplingToolLoop scans the SEP-1577 tool-loop fields of one sampling
// message: a tool_result block's nested `content` and `structuredContent`, and
// a tool_use block's `name` and `input`. It does NOT use the sampling prompt
// patterns, and each half gets the scanner built for what it is.
//
// A tool_result is a CallToolResult body — the same bytes, from the same
// server, that FilterToolCallResponse blocks when they arrive as a tools/call
// response — so it gets the tools/call response scanner plus the tools/call
// control-token check (ScanResponseControlTokens: a forged role turn or
// dispatch block corroborated by an override phrase blocks; a bare token, as a
// docs page about chat templates contains, does not). The prompt patterns are
// wrong here: they fire on mentions, and a mention of "credentials" in a
// search hit is the 7-of-7 false-positive shape found when description
// patterns were ported to responses. The tools/call false positives are
// inherited with the scanner (#4060). This is NOT parity with tools/call.
// FilterToolCallResponse runs seven BLOCK-tier scanners and gates this loop
// does not: result-level `_meta` and error remediation (the projection into
// SamplingMessageContent drops `_meta` and `isError`, so neither can run),
// the 4 MiB serialized-response gate, data labels, non-text content blocks,
// formula injection and GhostSplice. An eighth gap is a decode divergence,
// not a scanner: duplicate structuredContent members resolve differently on
// the two paths. TestSamplingToolResultKnownGaps4130 pins all eight. The fix is one
// shared result-scanning pipeline for both entry points — #4130 — not a
// longer hand-picked list here.
//
// A tool_use `input` is the model's own earlier query, echoed back by the
// server and therefore forgeable. It is also where ordinary questions live
// ("how to delete files in Python?"), which the response scanner's action
// patterns block. So it gets only the high-precision sets: instruction-override
// markers (hiddenInstructionPatterns) and corroborated control tokens — the
// evidence a forged-history injection needs, and nothing a topic can trip.
//
// Measured before the fix with a directive that BLOCKs as a plain text block:
// array content, tool_result, tool_use input and a poisoned tools[]
// description all decided AUDIT.
func scanSamplingToolLoop(msg SamplingMessage) []SamplingFinding {
	var resultTexts, inputTexts []string
	for _, b := range msg.contentBlocks() {
		resultTexts = append(resultTexts, toolResultContentStrings(b.Content)...)
		resultTexts = append(resultTexts, samplingStringLeaves(b.StructuredContent)...)
		if b.Name != "" {
			inputTexts = append(inputTexts, b.Name)
		}
		inputTexts = append(inputTexts, samplingStringLeaves(b.Input)...)
	}

	var out []SamplingFinding
	add := func(block, detail, snip string) {
		out = append(out, SamplingFinding{
			Signal:   SignalSamplingToolLoopInjection,
			Detail:   block + ": " + detail,
			Role:     msg.Role,
			TextSnip: snip,
		})
	}

	if len(resultTexts) > 0 {
		items := make([]ContentItem, 0, len(resultTexts))
		for _, t := range resultTexts {
			items = append(items, ContentItem{Type: "text", Text: t})
		}
		for _, f := range ScanToolCallResponse(items).Findings {
			add("tool_result", string(f.Signal)+": "+f.Detail, f.Snippet)
		}
	}

	if joined := strings.Join(inputTexts, "\n"); joined != "" {
		forms := newProseForms(joined)
		for _, set := range [][]signalPattern{hiddenInstructionPatterns, toolLoopOverridePatterns} {
			if f, ok := firstProseMatch(set, forms); ok {
				add("tool_use", f, truncateSnip(joined))
				break
			}
		}
	}
	if joined := strings.Join(resultTexts, "\n"); joined != "" {
		if f, ok := firstProseMatch(toolLoopOverridePatterns, newProseForms(joined)); ok {
			add("tool_result", f, truncateSnip(joined))
		}
	}

	// Typed pass: three of the typed tools/call result scanners — the
	// annotation-channel scanners (audience, ranking) and the vendor-secret
	// scanner — run on the TYPED content items, because the string flattening
	// above discards the annotations they read. The post-merge review of
	// #4058 executed both gaps: an annotation-only ranking forgery and an
	// access-key/secret pair each blocked on tools/call and passed as a
	// sampling tool_result. Only BLOCK-tier results are taken: any finding
	// blocks a sampling request, so an AUDIT-tier one would block what
	// tools/call only records. Three scanners, not the full set: this pass
	// does not make the loop as strict as tools/call (see the function
	// comment and #4130).
	for _, b := range msg.contentBlocks() {
		items := toolResultContentItems(b.Content)
		structured := structuredObject(b.StructuredContent)
		if len(items) == 0 && structured == nil {
			continue
		}
		if r := ScanContentAudienceChannel(items); r.Blocked {
			for _, f := range r.Findings {
				add("tool_result", string(f.Signal)+": "+f.Detail, "")
			}
		}
		if r := ScanContentRankingChannel(items); r.Blocked {
			for _, f := range r.Findings {
				add("tool_result", string(f.Signal)+": "+f.Detail, "")
			}
		}
		if r := ScanToolCallResponseForSecrets(items, structured); r.Blocked {
			for _, f := range r.Findings {
				add("tool_result", string(f.Signal)+": "+f.Detail, "")
			}
		}
	}

	for _, set := range []struct {
		block string
		texts []string
	}{{"tool_result", resultTexts}, {"tool_use", inputTexts}} {
		for _, t := range set.texts {
			if r := ScanResponseControlTokens(t); r.Blocked {
				detail := "forged chat-template / tool-invocation control token corroborated by an override phrase"
				if len(r.Findings) > 0 {
					detail += ": " + r.Findings[0].Detail
				}
				add(set.block, detail, truncateSnip(t))
				break
			}
		}
	}
	return out
}

// toolLoopOverridePatterns are the override directives that have no reading
// on a DATA surface other than an attempt to take over the model. Both
// tool-loop halves share them (Codex review of #4058, pass 2, finding 2): the
// response scanner's override pattern accepts a single verb, so the same
// directive with "discard" in its place passed a tool_result, and the
// tool_use half had no disable-safety check at all.
//
// Deliberately narrower than a2aHardInjectionPatterns, which it is drawn from.
// Tool data is where ordinary prose lives, and several members of that set
// have data-surface readings: "developer mode" (Android, browsers),
// "jailbreak" (phones), "turn off filters" (spreadsheets), "you are no longer
// required to". The disable pattern here requires "your", so it names the
// reader rather than a product setting, and omits "security" ("temporarily
// disable your security software" is install-guide boilerplate).
var toolLoopOverridePatterns = []signalPattern{
	{regexp.MustCompile(`(ignore|disregard|discard|forget)\s+(all\s+)?(of\s+)?(the\s+|your\s+)?(previous|prior|earlier|above|preceding)\s+(instructions?|prompts?|messages?|rules?|directives?)`), "instruction override (disregard earlier instructions)"},
	{regexp.MustCompile(`(disable|bypass|circumvent|turn\s+off|ignore)\s+your\s+(safety|guardrails?|filters?|restrictions?|guidelines?|content\s+polic(y|ies))`), "behavioral takeover (disable your safety controls)"},
	{regexp.MustCompile(`your\s+(new|real|true|actual)\s+(role|instructions?|goal|objective|task)\s+(is|are)\b`), "behavioral takeover (role reassignment)"},
}

// firstProseMatch returns the description of the first pattern in set that
// matches any rendering of the text (recovery-aware), with its fold note.
func firstProseMatch(set []signalPattern, forms proseForms) (string, bool) {
	for _, p := range set {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return p.description + note, true
		}
	}
	return "", false
}

func truncateSnip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// toolResultContentStrings returns the model-read strings of a tool_result
// block's nested ContentBlock[] (or a single block, or anything else — the
// shape is attacker-chosen and must not decide whether text is read).
//
// Protocol binary payloads are the only thing skipped, and only where the
// protocol puts them: the `data` of a content block typed "image" or "audio",
// and an embedded resource's `blob` unless it decodes to text. A text blob is
// decoded and returned, exactly as the tools/call path decodes and re-scans
// one. Everywhere else — including a `data` key on any other object — every
// string is returned: a field named "data" in arbitrary JSON is application
// text, not a binary payload (Codex review of #4058, finding 1).
func toolResultContentStrings(raw json.RawMessage) []string {
	v, ok := decodeJSONValue(raw)
	if !ok {
		return nil
	}
	var out []string
	var visitBlock func(node interface{})
	visitBlock = func(node interface{}) {
		m, isMap := node.(map[string]interface{})
		if !isMap {
			out = appendJSONStrings(out, node)
			return
		}
		typ, _ := m["type"].(string)
		for _, k := range sortedKeys(m) {
			e := m[k]
			out = append(out, k)
			if k == "data" && (typ == "image" || typ == "audio") {
				continue
			}
			if k == "resource" {
				if res, ok := e.(map[string]interface{}); ok {
					for _, rk := range sortedKeys(res) {
						if rk == "blob" {
							if bs, ok := res[rk].(string); ok {
								if text, ok := decodeTextBlob(bs); ok {
									out = append(out, text)
								}
								continue
							}
						}
						out = appendJSONStrings(out, res[rk])
					}
					continue
				}
			}
			out = appendJSONStrings(out, e)
		}
	}
	if arr, isArr := v.([]interface{}); isArr {
		for _, item := range arr {
			visitBlock(item)
		}
	} else {
		visitBlock(v)
	}
	return out
}

// toolResultContentItems decodes a tool_result's nested content (an array of
// blocks, or one block) as typed ContentItems, annotations included. A block
// whose values do not fit the types keeps every field that did decode.
func toolResultContentItems(raw json.RawMessage) []ContentItem {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	var elems []json.RawMessage
	switch trimmed[0] {
	case '[':
		if json.Unmarshal(trimmed, &elems) != nil {
			return nil
		}
	case '{':
		elems = []json.RawMessage{trimmed}
	default:
		return nil
	}
	items := make([]ContentItem, 0, len(elems))
	for _, e := range elems {
		var it ContentItem
		if bytes.HasPrefix(bytes.TrimSpace(e), []byte("{")) {
			_ = json.Unmarshal(e, &it)
			items = append(items, it)
		}
	}
	return items
}

// structuredObject decodes a structuredContent object with UseNumber, or
// returns nil when it is not an object.
func structuredObject(raw json.RawMessage) map[string]interface{} {
	v, ok := decodeJSONValue(raw)
	if !ok {
		return nil
	}
	m, _ := v.(map[string]interface{})
	return m
}

// decodeTextBlob base64-decodes a resource blob and returns it when it is
// readable text (the same test the tools/call base64 re-scan uses).
func decodeTextBlob(s string) (string, bool) {
	cleaned := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(cleaned); err == nil {
			if decodedLooksLikeText(b) {
				return string(b), true
			}
			return "", false
		}
	}
	return "", false
}

// samplingStringLeaves returns every non-empty string value in raw, at any
// depth. Nothing is skipped: tool_use input and structuredContent are
// arbitrary JSON the model reads as-is.
func samplingStringLeaves(raw json.RawMessage) []string {
	v, ok := decodeJSONValue(raw)
	if !ok {
		return nil
	}
	return appendJSONStrings(nil, v)
}

// decodeJSONValue decodes raw with UseNumber, so a valid but unrepresentable
// number (1e400) cannot fail the decode and take every sibling string with it
// (Codex review of #4058, finding 3).
func decodeJSONValue(raw json.RawMessage) (interface{}, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v interface{}
	if dec.Decode(&v) != nil {
		return nil, false
	}
	return v, true
}

func appendJSONStrings(dst []string, node interface{}) []string {
	switch n := node.(type) {
	case string:
		if n != "" {
			dst = append(dst, n)
		}
	case []interface{}:
		for _, e := range n {
			dst = appendJSONStrings(dst, e)
		}
	case map[string]interface{}:
		// Keys too: an object key is text the model reads in the tool-call
		// history, and a conformant input may carry arbitrary properties
		// (Codex review of #4058, pass 2, finding 1).
		for _, k := range sortedKeys(n) {
			if k != "" {
				dst = append(dst, k)
			}
			dst = appendJSONStrings(dst, n[k])
		}
	}
	return dst
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// scanSamplingTools runs the tools/list description scanner over the tool
// definitions a server supplies inside a sampling/createMessage request
// (SEP-1577). The definitions are the tools/list shape and reach the same
// model, but FilterToolsListResponse only ever sees tools/list responses, so a
// description it would hide went through here untouched.
//
// A poisoned definition blocks the whole request. Unlike a listing, there is
// no clean remainder to forward: the request is one prompt, and the tools are
// part of it.
func scanSamplingTools(tools []ToolDefinition) []SamplingFinding {
	var out []SamplingFinding
	for _, tool := range tools {
		r := ScanToolDescription(tool)
		if !r.Poisoned {
			continue
		}
		for _, f := range r.Findings {
			out = append(out, SamplingFinding{
				Signal:   SignalSamplingToolDefinition,
				Detail:   "sampling tool " + strconv.Quote(tool.Name) + ": " + string(f.Signal) + ": " + f.Detail,
				Role:     "tools",
				TextSnip: f.Snippet,
			})
		}
	}
	return out
}
