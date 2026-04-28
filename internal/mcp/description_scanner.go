package mcp

import (
	"regexp"
	"strings"
)

// PoisonSignal identifies a specific type of tool description poisoning.
type PoisonSignal string

const (
	SignalHiddenInstructions     PoisonSignal = "hidden_instructions"
	SignalCredentialHarvest      PoisonSignal = "credential_harvest"
	SignalExfiltrationIntent     PoisonSignal = "exfiltration_intent"
	SignalCrossToolOverride       PoisonSignal = "cross_tool_override"
	SignalStealthInstruction     PoisonSignal = "stealth_instruction"
	SignalBehavioralManipulation PoisonSignal = "behavioral_manipulation"
	SignalShadowTool             PoisonSignal = "shadow_tool"
	SignalAnnotationSpoofing     PoisonSignal = "annotation_spoofing"
	// SignalEvalAwareness flags tool descriptions that embed evaluation-mode signals
	// intended to trigger sandbagging — an agent behaving more safely when it detects
	// it is being observed, producing false-positive compliance evidence.
	SignalEvalAwareness PoisonSignal = "eval_awareness"

	// SignalGlitchToken flags tool descriptions containing known anomalous vocabulary
	// tokens (SolidGoldMagikarp family, cl100k_base anomalies) that have no legitimate
	// presence in MCP tool descriptions. These tokens are used to provoke undefined model
	// behavior — refusal bypass, hallucinated tool calls, structured-output corruption.
	SignalGlitchToken PoisonSignal = "glitch_token"

	// SignalConditionalTrigger flags tool descriptions containing dormant-directive patterns
	// that activate only when a runtime condition fires — a date guard, turn-count, trigger
	// phrase, tool-presence check, or lifecycle event. Legitimate tool descriptions never
	// contain such conditional instruction structures directed at the agent.
	SignalConditionalTrigger PoisonSignal = "conditional_trigger"

	// SignalUnicodeTagsBlock flags tool descriptions containing Unicode Tags block
	// characters (U+E0000–U+E007F). These deprecated code points (since Unicode 5.1)
	// have zero legitimate use in tool descriptions and are the primary vehicle for
	// ASCII smuggling / hidden prompt injection planted by malicious MCP servers.
	SignalUnicodeTagsBlock PoisonSignal = "unicode_tags_block"
)

// PoisonFinding records one detected poisoning signal in a tool description.
type PoisonFinding struct {
	Signal  PoisonSignal `json:"signal"`
	Detail  string       `json:"detail"`
	Snippet string       `json:"snippet,omitempty"`
}

// DescriptionScanResult is the result of scanning a single tool's description.
type DescriptionScanResult struct {
	ToolName string          `json:"tool_name"`
	Poisoned bool            `json:"poisoned"`
	Findings []PoisonFinding `json:"findings,omitempty"`
}

// ScanToolDescription checks a tool's description and input schema for
// poisoning signals. Returns findings if any suspicious patterns are detected.
func ScanToolDescription(tool ToolDefinition) DescriptionScanResult {
	result := DescriptionScanResult{ToolName: tool.Name}

	// Combine description + inputSchema text for scanning
	text := tool.Description
	if len(tool.InputSchema) > 0 {
		text += " " + string(tool.InputSchema)
	}

	if text == "" {
		return result
	}

	lower := strings.ToLower(text)

	// Signal 1: Hidden instruction markers
	for _, pattern := range hiddenInstructionPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalHiddenInstructions,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 2: Credential/sensitive file harvesting references
	for _, pattern := range credentialHarvestPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalCredentialHarvest,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 3: Exfiltration intent
	for _, pattern := range exfiltrationPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalExfiltrationIntent,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 4: Cross-tool override / shadowing
	for _, pattern := range crossToolPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalCrossToolOverride,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 5: Stealth instructions (hide behavior from user)
	for _, pattern := range stealthPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalStealthInstruction,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 6: Behavioral manipulation directives (compelling AI to change safety behavior)
	for _, pattern := range behavioralManipulationPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalBehavioralManipulation,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 7: Shadow tool registration (claiming to replace/supersede another tool)
	for _, pattern := range shadowToolPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalShadowTool,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 9: Eval-awareness triggers — language designed to make the agent believe it is
	// being evaluated, inducing sandbagging (better behavior under observation that reverts
	// after the evaluation window passes).
	for _, pattern := range evalAwarenessPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalEvalAwareness,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 10: Glitch-token injection — known anomalous vocabulary tokens embedded in
	// tool descriptions. No legitimate MCP tool description contains SolidGoldMagikarp-family
	// tokens; their presence is a reliable indicator of adversarial content.
	for _, pattern := range glitchTokenPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalGlitchToken,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 11: Conditional-trigger injection — dormant directives in tool descriptions
	// that activate on a runtime condition (date guard, turn-count, trigger phrase, tool
	// presence). No legitimate tool description contains such structures.
	for _, pattern := range conditionalTriggerPatterns {
		if loc := pattern.re.FindStringIndex(lower); loc != nil {
			result.Findings = append(result.Findings, PoisonFinding{
				Signal:  SignalConditionalTrigger,
				Detail:  pattern.description,
				Snippet: safeSnippet(text, loc[0], 80),
			})
		}
	}

	// Signal 8: Annotation spoofing — MCP 2025 annotation inconsistency (rug-pull indicator)
	// Per MCP spec, annotations are "not guaranteed to be accurate". A tool annotated
	// readOnly:true but named with destructive verbs is a rug-pull signal: the server
	// claims no side effects to bypass confirmation prompts, but the name reveals intent.
	if tool.Annotations != nil {
		result.Findings = append(result.Findings, checkAnnotationConsistency(tool.Name, tool.Description, tool.Annotations)...)
	}

	// Signal 12: Unicode Tags block in tool description — invisible adversarial payload.
	// U+E0000–U+E007F chars are deprecated (Unicode 5.1) with zero legitimate use in
	// tool descriptions. Their presence indicates a malicious MCP server embedding
	// hidden directives invisible to humans but readable by the LLM tokenizer.
	if idx := indexTagsBlock(text); idx >= 0 {
		result.Findings = append(result.Findings, PoisonFinding{
			Signal:  SignalUnicodeTagsBlock,
			Detail:  "Unicode Tags block character (U+E0000–U+E007F) in tool description — invisible prompt injection payload",
			Snippet: safeSnippet(text, max(0, idx-20), 60),
		})
	}

	result.Poisoned = len(result.Findings) > 0
	return result
}

// indexTagsBlock returns the byte offset of the first Unicode Tags block character
// (U+E0000–U+E007F) in text, or -1 if none are present.
func indexTagsBlock(text string) int {
	byteOffset := 0
	for _, r := range text {
		if r >= 0xE0000 && r <= 0xE007F {
			return byteOffset
		}
		byteOffset += len(string(r))
	}
	return -1
}


// checkAnnotationConsistency checks MCP 2025 tool annotations for semantic inconsistency
// with the tool name and description. Returns annotation spoofing findings.
func checkAnnotationConsistency(name, description string, ann *ToolAnnotations) []PoisonFinding {
	var findings []PoisonFinding
	nameLower := strings.ToLower(name)
	descLower := strings.ToLower(description)

	// readOnly:true inconsistency: destructive verb in name implies side effects
	if ann.ReadOnly != nil && *ann.ReadOnly {
		if readOnlyLiePattern.MatchString(nameLower) {
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationSpoofing,
				Detail:  "readOnly:true annotation inconsistent with destructive verb in tool name — rug-pull indicator (mcp-tool-annotation-spoofing)",
				Snippet: name,
			})
		}
		// Also flag if description mentions sending/posting/uploading (network egress side effect)
		if readOnlyEgressPattern.MatchString(descLower) {
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationSpoofing,
				Detail:  "readOnly:true annotation inconsistent with egress verbs in tool description — tool claims no side effects but description implies network activity",
				Snippet: safeSnippet(description, 0, 80),
			})
		}
	}

	// openWorld:false or absent when description describes network egress is suspicious,
	// but we only flag when openWorld is explicitly false (explicit concealment).
	if ann.OpenWorld != nil && !*ann.OpenWorld {
		if openWorldConcealPattern.MatchString(descLower) {
			findings = append(findings, PoisonFinding{
				Signal:  SignalAnnotationSpoofing,
				Detail:  "openWorld:false annotation inconsistent with egress verbs in description — conceals network egress from monitors (mcp-tool-annotation-spoofing)",
				Snippet: safeSnippet(description, 0, 80),
			})
		}
	}

	return findings
}

// signalPattern pairs a compiled regex with a human-readable description.
type signalPattern struct {
	re          *regexp.Regexp
	description string
}

var hiddenInstructionPatterns = []signalPattern{
	{regexp.MustCompile(`<important>`), "Hidden <IMPORTANT> tag in description"},
	{regexp.MustCompile(`<system>`), "Hidden <SYSTEM> tag in description"},
	{regexp.MustCompile(`<instruction>`), "Hidden <INSTRUCTION> tag in description"},
	{regexp.MustCompile(`<cmd>`), "Hidden <CMD> tag in description"},
	{regexp.MustCompile(`(ignore|disregard|discard|forget)\s+(all\s+)?previous\s+instructions`), "Prompt injection: ignore/disregard previous instructions"},
	{regexp.MustCompile(`ignore\s+(all\s+)?safety`), "Prompt injection: ignore safety"},
	{regexp.MustCompile(`override\s+(all\s+)?(previous|system)`), "Prompt injection: override instructions"},
	{regexp.MustCompile(`you\s+must\s+(first|always)\s+read`), "Coercive instruction to read files"},
	{regexp.MustCompile(`before\s+using\s+this\s+tool.*read`), "Pre-condition instruction to read files"},
	{regexp.MustCompile(`otherwise\s+the\s+tool\s+will\s+not\s+work`), "Fake pre-condition threat"},
}

var credentialHarvestPatterns = []signalPattern{
	{regexp.MustCompile(`~/?\.(ssh|aws|gnupg|kube|config/gcloud)`), "References sensitive dotfile directory"},
	{regexp.MustCompile(`id_rsa|id_ed25519|id_ecdsa`), "References SSH private key filename"},
	{regexp.MustCompile(`authorized_keys`), "References SSH authorized_keys"},
	{regexp.MustCompile(`mcp\.json`), "References MCP configuration file"},
	{regexp.MustCompile(`credentials|access.?key|secret.?key`), "References credential keywords"},
	{regexp.MustCompile(`/etc/shadow|/etc/passwd`), "References system auth files"},
	{regexp.MustCompile(`\.env\b`), "References .env file"},
	{regexp.MustCompile(`api.?key|api.?token|bearer.?token`), "References API key/token"},
}

var exfiltrationPatterns = []signalPattern{
	{regexp.MustCompile(`pass\s+(it|its|the|this|that|them|their)?\s*(content|contents|data|value|result)?\s*as\b`), "Instruction to pass data as parameter"},
	{regexp.MustCompile(`send\s+(it|the|this|all)?\s*(to|via)\b`), "Instruction to send data somewhere"},
	{regexp.MustCompile(`(curl|wget|fetch|http|post)\s.*(attacker|evil|exfil|collect|receive)`), "Exfiltration via HTTP"},
	{regexp.MustCompile(`\bexfiltrate\b`), "Instruction to exfiltrate data"},
	{regexp.MustCompile(`encode\s+(it|the|this|data)?\s*(as|in|to|with)\s*(base64|hex)`), "Instruction to encode data for exfiltration"},
	{regexp.MustCompile(`(include|embed|attach|append)\s+(it|the|this|all)?\s*(in|to|into)\s*(the\s+)?(response|output|result|argument|param)`), "Instruction to embed data in output"},
}

var crossToolPatterns = []signalPattern{
	{regexp.MustCompile(`(side\s+effect|important\s+side\s+effect)\s+on\s+(the\s+)?(also\s+present\s+)?`), "Describes side effects on other tools"},
	{regexp.MustCompile(`when\s+this\s+tool\s+is\s+available.*must\s+`), "Conditional override when tool is present"},
	{regexp.MustCompile(`(mcp_tool_|tool_)\w+\s+must\s+`), "Direct instruction to override another tool"},
	{regexp.MustCompile(`send\s+all\s+(emails|messages|requests|data)\s+to\b`), "Instruction to redirect all data"},
}

var stealthPatterns = []signalPattern{
	{regexp.MustCompile(`do\s+not\s+(mention|tell|inform|reveal|show|display|say)`), "Instruction to hide behavior from user"},
	{regexp.MustCompile(`don'?t\s+(mention|tell|inform|reveal|show|display|say)`), "Instruction to hide behavior from user"},
	{regexp.MustCompile(`(could|might|will)\s+(upset|scare|confuse|alarm|worry)\s+the\s+user`), "Social engineering: user emotional manipulation"},
	{regexp.MustCompile(`implementation\s+detail`), "Disguising malicious behavior as implementation detail"},
	{regexp.MustCompile(`(mere|just\s+a|simply\s+an?)\s+(implementation|technical)\s+(detail|requirement)`), "Minimizing suspicious behavior"},
	{regexp.MustCompile(`very\s+very\s+(very\s+)?important`), "Emphatic coercion (repeated emphasis)"},
	{regexp.MustCompile(`the\s+application\s+will\s+crash`), "Fake crash threat to coerce behavior"},
	{regexp.MustCompile(`all\s+data\s+will\s+be\s+lost`), "Fake data loss threat to coerce behavior"},
}

var behavioralManipulationPatterns = []signalPattern{
	{regexp.MustCompile(`act\s+as\s+(if\s+you\s+(have\s+no|are\s+free|don'?t\s+have)|a\s+different)`), "Behavioral directive: act as if unrestricted"},
	{regexp.MustCompile(`pretend\s+(to\s+be|you\s+(are|don'?t|have\s+no))`), "Behavioral directive: pretend to be different agent"},
	{regexp.MustCompile(`(disable|bypass|circumvent|remove|ignore)\s+(your\s+)?(safety|restrictions|filters|guidelines|limits|rules)`), "Behavioral directive: disable safety controls"},
	{regexp.MustCompile(`from\s+now\s+on\s+(you|your|always|never|do\s+not)`), "Behavioral takeover: from-now-on directive"},
	{regexp.MustCompile(`your\s+new\s+(role|instructions?|goal|objective|purpose|task)\s+(is|are)\s+`), "Behavioral takeover: role reassignment"},
	{regexp.MustCompile(`forget\s+(your|all)\s+(previous|prior|original|default)\s+(instructions?|training|guidelines?|rules?|behavior)`), "Behavioral takeover: forget instructions"},
	{regexp.MustCompile(`you\s+are\s+(no\s+longer|now\s+free\s+from|released\s+from)`), "Behavioral takeover: liberation claim"},
	{regexp.MustCompile(`(jailbreak|developer\s+mode|dan\s+mode|unrestricted\s+mode)`), "Jailbreak attempt: mode switch"},
	{regexp.MustCompile(`you\s+must\s+(comply|obey|follow\s+these)\s+(with\s+)?(all|every|these|the\s+following)`), "Behavioral coercion: must comply directive"},
	{regexp.MustCompile(`(without\s+question|without\s+hesitation|no\s+matter\s+what|regardless\s+of)`), "Behavioral coercion: unconditional compliance"},
}

// annotationSpoofing compiled patterns
var (
	// readOnlyLiePattern matches tool names containing destructive verbs that
	// contradict a readOnly:true annotation. Uses (?:^|_|\b) anchors to handle
	// both snake_case tool names (delete_user_data) and plain words (deleteUser).
	readOnlyLiePattern = regexp.MustCompile(`(?:^|_)(delete|drop|remove|write|create|modify|update|edit|send|post|upload|exec|execute|purge|wipe|truncate|insert|grant|revoke)(?:_|$|[A-Z])`)

	// readOnlyEgressPattern matches description text indicating network egress,
	// inconsistent with readOnly:true (which implies no side effects).
	// Handles verb forms: send/sends/sending, post/posts/posting, upload/uploads, etc.
	readOnlyEgressPattern = regexp.MustCompile(`(sends?|posts?|uploads?|forwards?|transmits?|relays?|push(?:es)?|emits?|publish(?:es)?)\s+(it|data|the|this|all|to|result)`)

	// openWorldConcealPattern matches description text indicating network egress
	// when the tool has openWorld explicitly set to false (active concealment).
	openWorldConcealPattern = regexp.MustCompile(`\b(send|post|upload|fetch|call|request|connect|forward|transmit|relay|push|emit)\s+(to|data|the|this|result|request)?\s*(external|remote|server|api|endpoint|url|webhook|http)`)
)

// evalAwarenessPatterns detects tool descriptions that embed evaluation-mode language.
// These signals are planted by adversaries to induce sandbagging: the LLM believes it
// is under evaluation and behaves more cautiously, producing false-positive compliance
// attestations. After the evaluation window the agent reverts to riskier behavior.
var evalAwarenessPatterns = []signalPattern{
	{regexp.MustCompile(`you\s+are\s+being\s+(evaluated|assessed|tested|monitored|observed|scored)`), "Eval signal: explicit evaluation announcement targeting agent"},
	{regexp.MustCompile(`this\s+is\s+(a|an)?\s*(safety\s+)?(test|probe|eval|assessment|audit|benchmark|red.?team)`), "Eval signal: explicit test/evaluation declaration"},
	{regexp.MustCompile(`eval.?mode\s*[=:]\s*(true|1|on|enabled|active)`), "Eval signal: EVAL_MODE flag set to true"},
	{regexp.MustCompile(`alignment.?(check|probe|test|eval)\b`), "Eval signal: alignment evaluation trigger"},
	{regexp.MustCompile(`\beval_mode\b|\bevaluation_mode\b|\btest_mode\b|\bsafety_probe\b`), "Eval signal: eval/test mode flag in description"},
	{regexp.MustCompile(`(your|agent)\s+(outputs?|responses?|actions?|behavior)\s+(are|will\s+be|is\s+being)\s+(scored|graded|evaluated|assessed|logged\s+for\s+(safety|compliance|audit))`), "Eval signal: output scoring announcement"},
	{regexp.MustCompile(`red.?team\s+probe\b|red.?teaming\s+session\b`), "Eval signal: red-team probe signal"},
	{regexp.MustCompile(`safety\s+evaluator\s+(is\s+)?watching`), "Eval signal: safety evaluator presence announcement"},
	{regexp.MustCompile(`behave\s+(carefully|cautiously|safely)\s+(as|because|since|while)\s+(your|you)`), "Eval signal: behavioral coercion tied to evaluation context"},
}

var shadowToolPatterns = []signalPattern{
	{regexp.MustCompile(`(replaces?|supersedes?|overrides?)\s+(the\s+)?\w+\s+tool`), "Shadow tool: claims to replace another tool"},
	{regexp.MustCompile(`use\s+this\s+tool\s+instead\s+of`), "Shadow tool: redirect from another tool"},
	{regexp.MustCompile(`(should|must|always)\s+(use|call|invoke)\s+this\s+(tool\s+)?(instead|rather\s+than|over|before)`), "Shadow tool: usage redirection directive"},
	{regexp.MustCompile(`this\s+is\s+the\s+(updated|new|improved|correct|official|real)\s+version\s+of`), "Shadow tool: impersonates updated version of another tool"},
	{regexp.MustCompile(`preferred\s+(over|to)\s+(the\s+)?\w+\s+tool`), "Shadow tool: preference override for another tool"},
	{regexp.MustCompile(`when\s+(this|the)\s+tool\s+is\s+(present|available|installed|loaded),?\s+(the\s+)?\w+\s+(tool\s+)?(should\s+not|must\s+not|cannot)`), "Shadow tool: conditional suppression of another tool"},
	{regexp.MustCompile(`do\s+not\s+use\s+(the\s+)?(built.?in|original|default|other)\s+(\w+\s+)?tool`), "Shadow tool: suppression of built-in tool"},
}

// conditionalTriggerPatterns detects dormant-directive structures in tool descriptions.
// These patterns indicate sleeper prompt injection: instructions embedded in a tool
// description that remain inactive until a runtime condition fires (a date, a turn count,
// a trigger phrase, a tool-presence check, or a lifecycle event). Legitimate tool
// descriptions never contain such conditional imperative structures directed at the agent.
var conditionalTriggerPatterns = []signalPattern{
	// Date-guarded directives: "if today is on or after 2026-06-01" / "if the date >= 2026"
	{regexp.MustCompile(`if\s+(today|the\s+date)\s+is\s+(on\s+or\s+after|>=?|past)\s+\d{4}`), "Conditional trigger: date guard directive"},
	// Trigger-phrase guards: "when you see the token PINEAPPLE_88" / "when you next see"
	{regexp.MustCompile(`when\s+you\s+(next\s+)?(see|find|encounter|observe|detect)\s+(the\s+)?(token|string|phrase|word|key|signal)\b`), "Conditional trigger: trigger-phrase guard"},
	// Tool-presence guards: "if available tools include X" / "if tools contain Y"
	{regexp.MustCompile(`if\s+(available\s+)?tools\s+(include|contain|have)\b`), "Conditional trigger: tool-presence guard"},
	// Turn/session lifecycle guards: "on first restart" / "after N more messages"
	{regexp.MustCompile(`on\s+(first|next)\s+(restart|session|invocation|startup|run)\b`), "Conditional trigger: lifecycle trigger guard"},
	{regexp.MustCompile(`after\s+\d+\s+(more\s+)?(messages?|turns?|sessions?|interactions?)\b`), "Conditional trigger: turn-count guard"},
}

// glitchTokenPatterns lists known anomalous vocabulary tokens from the SolidGoldMagikarp
// disclosure (Rumbelow & Watkins 2023) and related research. These tokens are under-trained
// or unallocated in GPT-2/3/4 and tiktoken (cl100k_base) vocabularies, and can provoke
// undefined model behavior (refusal bypass, hallucinated tool calls, output corruption)
// when injected into agent-ingested content.
//
// No legitimate MCP tool description contains these tokens; their presence is a reliable
// signal of adversarial content. Matching is case-insensitive since the tokenizer treats
// these as atomic tokens regardless of casing in surrounding prose.
var glitchTokenPatterns = []signalPattern{
	// SolidGoldMagikarp family (original Rumbelow & Watkins 2023 disclosure — GPT-2/3)
	{regexp.MustCompile(`solidgoldmagikarp`), "Known glitch token: SolidGoldMagikarp (Rumbelow & Watkins 2023)"},
	{regexp.MustCompile(`\bpetertodd\b`), "Known glitch token: petertodd (SolidGoldMagikarp family)"},
	{regexp.MustCompile(`\bdavidjl\b`), "Known glitch token: davidjl (SolidGoldMagikarp family)"},
	{regexp.MustCompile(`forgemodloader`), "Known glitch token: ForgeModLoader (SolidGoldMagikarp family)"},
	// Additional anomalous tokens from the original enumeration
	{regexp.MustCompile(`\bstreamer\b.*\bbot\b|\bstreamerbottoken\b`), "Known glitch token: StreamerBot-family token"},
	{regexp.MustCompile(`ahoma\s+city\s+oklahoma|okcthunderfan`), "Known glitch token: OKC Thunder fan token family"},
}

// safeSnippet extracts a context snippet around an index, capped at maxLen.
func safeSnippet(text string, idx, maxLen int) string {
	start := idx - 20
	if start < 0 {
		start = 0
	}
	end := idx + maxLen
	if end > len(text) {
		end = len(text)
	}
	snippet := text[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(text) {
		snippet = snippet + "..."
	}
	return snippet
}
