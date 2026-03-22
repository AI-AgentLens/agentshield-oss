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

	result.Poisoned = len(result.Findings) > 0
	return result
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

var shadowToolPatterns = []signalPattern{
	{regexp.MustCompile(`(replaces?|supersedes?|overrides?)\s+(the\s+)?\w+\s+tool`), "Shadow tool: claims to replace another tool"},
	{regexp.MustCompile(`use\s+this\s+tool\s+instead\s+of`), "Shadow tool: redirect from another tool"},
	{regexp.MustCompile(`(should|must|always)\s+(use|call|invoke)\s+this\s+(tool\s+)?(instead|rather\s+than|over|before)`), "Shadow tool: usage redirection directive"},
	{regexp.MustCompile(`this\s+is\s+the\s+(updated|new|improved|correct|official|real)\s+version\s+of`), "Shadow tool: impersonates updated version of another tool"},
	{regexp.MustCompile(`preferred\s+(over|to)\s+(the\s+)?\w+\s+tool`), "Shadow tool: preference override for another tool"},
	{regexp.MustCompile(`when\s+(this|the)\s+tool\s+is\s+(present|available|installed|loaded),?\s+(the\s+)?\w+\s+(tool\s+)?(should\s+not|must\s+not|cannot)`), "Shadow tool: conditional suppression of another tool"},
	{regexp.MustCompile(`do\s+not\s+use\s+(the\s+)?(built.?in|original|default|other)\s+(\w+\s+)?tool`), "Shadow tool: suppression of built-in tool"},
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
