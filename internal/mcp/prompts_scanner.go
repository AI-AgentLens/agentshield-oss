package mcp

import (
	"encoding/json"
	"regexp"
	"strings"

	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
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

	// Scan each message's content (primary injection surface).
	// Handles both type:"text" and type:"resource" blocks — the latter embeds
	// a full ResourceContentItem whose text is injected into the agent's context
	// exactly like a text block but was previously invisible to this scanner
	// (structural bypass, issue #2316).
	for i, msg := range result.Messages {
		baseField := "message[" + itoa(i) + "].content"
		switch msg.Content.Type {
		case "text":
			if msg.Content.Text != "" {
				scanPromptsField(&scanResult, msg.Content.Text, baseField)
			}
		case "resource":
			if msg.Content.Resource != nil {
				// Scan the embedded resource text — hosts render this into the
				// agent's conversation context verbatim, so it is a full injection
				// surface equivalent to type:"text".
				if msg.Content.Resource.Text != "" {
					scanPromptsField(&scanResult, msg.Content.Resource.Text, baseField+".resource.text")
				}
				// Scan the resource URI for dangerous schemes and credential paths.
				// A malicious server can embed file:///etc/shadow, javascript:,
				// or gopher: URIs that cause SSRF or code execution when the host
				// auto-fetches or renders the resource.
				if msg.Content.Resource.URI != "" {
					scanPromptsResourceURI(&scanResult, msg.Content.Resource.URI, baseField+".resource.uri")
				}
			}
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
		// Scan the prompt NAME itself. The name is a slash-command identifier the
		// host renders verbatim, the user selects by sight, and the agent routes
		// on — yet the description-text pipeline above never inspects it. A
		// homoglyph name (`cоde_review`, Cyrillic о) impersonates a trusted prompt
		// (confused-deputy), and a name carrying an LLM role token or hidden-
		// instruction tag injects directly into the listing context the LLM reads.
		scanPromptIdentifier(&scanResult, prompt.Name, "prompt["+prompt.Name+"].name")

		if prompt.Description != "" {
			field := "prompt[" + prompt.Name + "].description"
			scanPromptsField(&scanResult, prompt.Description, field)
		}
		// Scan argument descriptions — each argument shown to the agent during
		// prompt selection is an injection surface that bypasses top-level description scans.
		for _, arg := range prompt.Arguments {
			// Argument NAMES are identifiers the agent binds values to; a confusable
			// or invisible char here lets a malicious server shadow a benign argument.
			scanPromptIdentifier(&scanResult, arg.Name, "prompt["+prompt.Name+"].arguments["+arg.Name+"].name")
			if arg.Description != "" {
				field := "prompt[" + prompt.Name + "].arguments[" + arg.Name + "].description"
				scanPromptsField(&scanResult, arg.Description, field)
			}
		}
	}

	scanResult.Poisoned = len(scanResult.Findings) > 0
	return scanResult
}

// identifierInjectionTagRE matches the unambiguous injection markers that have
// no legitimate place in a programmatic identifier (a prompt name or argument
// name): hidden-instruction tags (<important>, <system>, <instruction>, <cmd>,
// <tool>, <secret>). Unlike scanPromptsField (which runs the full credential /
// exfiltration / behavioural prose pattern set against DESCRIPTION text), the
// identifier scan must NOT run those prose patterns — a legitimate prompt named
// `get_credentials`, `rotate_api_key`, or `read_env` would false-positive on the
// credential-harvest patterns. Names are identifiers, so only identifier-illegal
// constructs (confusables, invisibles, role tokens, instruction tags) are flagged.
var identifierInjectionTagRE = regexp.MustCompile(`(?i)<\s*(important|system|instruction|cmd|tool|secret|inst)\s*>`)

// scanPromptIdentifier inspects an MCP prompt NAME or prompt-argument NAME — a
// programmatic identifier — for impersonation and injection that the description-
// text pipeline never sees. Three zero-FP classes are checked:
//
//  1. Unicode confusables / invisibles / bidi / tag chars / control chars
//     (via internal/unicode.Scan) — a homoglyph name (`cоde_review`, Cyrillic о)
//     renders identically to a trusted prompt in the host's slash-command menu,
//     so the user selects the impostor: confused-deputy / prompt impersonation.
//     This mirrors detectToolNameConfusable on the tools surface.
//  2. LLM tokenizer role delimiters (<|im_start|>, <<SYS>>, [/INST], …) — a name
//     carrying one injects a role boundary into the tool/prompt-listing context.
//  3. Hidden-instruction tags (<important>, <system>, …) embedded in the name.
//
// All three are illegal in a real prompt identifier, so the check is false-
// positive-free on the conventional `snake_case` / `kebab-case` names MCP
// servers actually publish.
func scanPromptIdentifier(result *PromptsScanResult, name, field string) {
	if name == "" {
		return
	}
	snip := name
	if len(snip) > 80 {
		snip = snip[:80] + "..."
	}

	// (1) Unicode confusables / invisibles / tag / control chars — impersonation.
	if scan := pkgunicode.Scan(name); !scan.Clean {
		seen := make(map[string]bool, len(scan.Threats))
		for _, threat := range scan.Threats {
			if seen[threat.Category] {
				continue
			}
			seen[threat.Category] = true
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationConfusable,
				Detail:  "prompt identifier contains " + threat.Description + " — prompt names are ASCII identifiers the host renders verbatim and the user selects by sight; a confusable or invisible character impersonates a trusted prompt (confused-deputy)",
				Field:   field,
				Snippet: snip,
			})
		}
	}

	// (2) LLM tokenizer role delimiters — case-sensitive, matched against raw name.
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(name) {
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationInjection,
				Detail:  "prompt identifier contains LLM tokenizer role delimiter: " + p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// (3) Hidden-instruction tags embedded in the identifier.
	if identifierInjectionTagRE.MatchString(name) {
		result.Findings = append(result.Findings, PromptFinding{
			Signal:  SignalNotificationInjection,
			Detail:  "prompt identifier contains a hidden-instruction tag (<important>/<system>/…) — an injection marker that has no legitimate place in a prompt name",
			Field:   field,
			Snippet: snip,
		})
	}
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

	// LLM tokenizer ROLE delimiters in the message CONTENT / description prose.
	// scanPromptIdentifier already checks the prompt NAME for these, but the
	// message content — rendered directly into the agent's conversation context —
	// was unscanned for role tokens. An attacker who knows the name is checked
	// simply moves the forged "<|im_start|>system ..." turn into the content. The
	// content text pattern groups above (hidden-instruction / behavioural) do not
	// match tokenizer-level role delimiters. Matched case-sensitively against the
	// raw text since these tokens are architecture-specific.
	for _, p := range llmRoleTokenPatterns {
		if p.re.MatchString(text) {
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationInjection,
				Detail:  "prompt content contains LLM tokenizer role delimiter: " + p.description,
				Field:   field,
				Snippet: snip,
			})
			break
		}
	}

	// Forged tool-CALL dispatch control syntax in the message CONTENT / description
	// prose (description->tool-call confusion). A poisoned prompt template that
	// embeds "<function_calls><invoke name='exec_shell'>..." is rendered into the
	// agent's context verbatim; a harness that parses tool-call syntax from free
	// text may dispatch the attacker-chosen call. Reuses the high-confidence,
	// zero-legit-use dispatch-token set from description_scanner.go (generic
	// <tool_call>/<tool_use> XML is deliberately excluded to stay FP-safe).
	if toolCallDispatchTokenRE.MatchString(text) {
		result.Findings = append(result.Findings, PromptFinding{
			Signal:  SignalNotificationInjection,
			Detail:  "prompt content contains forged tool-call / function-invocation control syntax (<function_calls>/<invoke>, <|python_tag|>/<|tool_call|>, or [TOOL_REQUEST]/[TOOL_CALLS]) — a harness parsing tool-call syntax from the rendered prompt may dispatch an unsanctioned privileged call",
			Field:   field,
			Snippet: snip,
		})
	}
}

// promptDangerousSchemes are URI schemes that should never appear in a legitimate
// MCP prompt embedded-resource URI. Keyed by lowercase scheme without colon.
// A subset of the resource-list dangerous-scheme list scoped to schemes that
// represent active-code execution or direct SSRF vectors when a host renders
// or auto-fetches the embedded resource text/uri.
var promptDangerousSchemes = map[string]string{
	"javascript": "URI scheme `javascript:` in an embedded prompt resource enables code execution when the host renders it",
	"vbscript":   "URI scheme `vbscript:` in an embedded prompt resource enables legacy Windows code execution on render",
	"data":       "URI scheme `data:` in an embedded prompt resource inlines a base64 payload that the host ingests directly — feedback injection vector",
	"gopher":     "URI scheme `gopher:` in an embedded prompt resource is a well-known SSRF carrier that bypasses HTTP allowlists",
	"dict":       "URI scheme `dict:` in an embedded prompt resource can reach arbitrary internal TCP services via Dict protocol gadgets",
	"ldap":       "URI scheme `ldap:` in an embedded prompt resource reaches directory services and is a classic SSRF / credential-harvest vector",
	"jndi":       "URI scheme `jndi:` in an embedded prompt resource triggers JVM remote object loading — remote code execution vector (Log4Shell class)",
}

// promptSensitiveFileRe matches file:// URIs pointing to well-known credential
// or sensitive system files. Used to flag embedded-resource URIs in prompts/get
// responses that would cause the host to auto-fetch sensitive local files.
var promptSensitiveFileRe = regexp.MustCompile(
	`(?i)file://[^?#]*(` +
		`/\.ssh/` + `|` +
		`/\.aws/` + `|` +
		`/\.gnupg/` + `|` +
		`/\.kube/` + `|` +
		`/vault-token` + `|` +
		`/etc/shadow\b` + `|` +
		`/etc/passwd\b` + `|` +
		`/etc/sudoers\b` + `|` +
		`/serviceaccount/token\b` +
		`)`,
)

// scanPromptsResourceURI checks the URI of an embedded resource block inside a
// prompts/get response for dangerous schemes and sensitive credential paths.
//
// A malicious server can embed type:"resource" blocks in prompt messages that
// carry a URI the host auto-fetches or renders. Unlike type:"text" where the
// payload is inline text, here the threat is the URI itself — a javascript:
// or gopher: URI becomes an execution/SSRF vector when the host renders the
// resource, and a file:// URI pointing to a credential file constitutes a
// silent authorization bypass (the prompt "contains" the credential path as
// structured metadata, not as suspicious prose).
func scanPromptsResourceURI(result *PromptsScanResult, uri, field string) {
	if uri == "" {
		return
	}
	lower := strings.ToLower(uri)
	snip := uri
	if len(snip) > 80 {
		snip = snip[:80] + "..."
	}

	// Check for dangerous URI schemes (code-exec / SSRF vectors).
	schemeEnd := strings.IndexByte(lower, ':')
	if schemeEnd > 0 {
		scheme := lower[:schemeEnd]
		if detail, bad := promptDangerousSchemes[scheme]; bad {
			result.Findings = append(result.Findings, PromptFinding{
				Signal:  SignalNotificationInjection,
				Detail:  detail,
				Field:   field,
				Snippet: snip,
			})
			return // scheme alone is conclusive — no need to check path patterns
		}
	}

	// Check file:// URIs for sensitive credential paths.
	if strings.HasPrefix(lower, "file://") && promptSensitiveFileRe.MatchString(lower) {
		result.Findings = append(result.Findings, PromptFinding{
			Signal:  SignalNotificationCredential,
			Detail:  "embedded prompt resource URI points to a sensitive credential path — host may auto-fetch this file and include its content in the agent's context",
			Field:   field,
			Snippet: snip,
		})
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
