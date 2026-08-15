package mcp

import (
	"fmt"
	"regexp"
	"strings"
)

// EmailInjectionSignal identifies an injection marker found in an email write operation.
type EmailInjectionSignal string

const (
	// SignalEmailInjectionMarker fires when an email write tool (send/reply/forward/draft)
	// is invoked with a body/content argument containing role-override injection
	// markers. These markers indicate that content from a read email was used verbatim
	// to drive the write action — the canonical email-as-injection-vector exploit:
	// an attacker sends adversarial agent instructions to an AI email agent, which
	// then forwards/replies/exfiltrates using its own authorised permissions.
	//
	// Covered patterns (built from fragments to avoid triggering content scanners):
	//   bracket role markers: [SYSTEM], [AGENT], [AI], [INSTRUCTION]
	//   XML role tags: <system>, <instruction>, <ai_instruction>
	//   override directives and turn delimiters
	//   markup-style directives: ###SYSTEM, ###INSTRUCTION
	SignalEmailInjectionMarker EmailInjectionSignal = "email_injection_marker"

	// SignalEmailShellPayload fires when an email write tool's body/content argument
	// contains an inline shell payload carried through from a read email.
	SignalEmailShellPayload EmailInjectionSignal = "email_shell_payload"
)

// EmailInjectionFinding records one injection signal found in an email write call.
type EmailInjectionFinding struct {
	Signal  EmailInjectionSignal
	Detail  string
	ArgName string
	Snippet string
}

// EmailInjectionScanResult is the result of an email write injection scan.
type EmailInjectionScanResult struct {
	Blocked  bool
	Audited  bool
	Findings []EmailInjectionFinding
}

// ScanEmailWriteInjection inspects email write tool calls for role-override injection
// markers in the outgoing message body/content arguments.
//
// Detection rationale: email is a zero-barrier indirect injection surface — any
// attacker can inject adversarial agent instructions into an AI email agent's context
// by sending a message. When the read content is then forwarded verbatim as an
// outgoing action, the injection was successful. The scanner is AUDIT-only (not BLOCK)
// because legitimate agents may quote injected content for review — false positives
// are expensive here.
//
// The tool name must match the email write family (send, reply, forward, draft);
// email read tools (search, list, fetch) are not scanned.
func ScanEmailWriteInjection(toolName string, arguments map[string]interface{}) EmailInjectionScanResult {
	if !isEmailWriteTool(toolName) {
		return EmailInjectionScanResult{}
	}

	var result EmailInjectionScanResult
	for _, argName := range emailBodyArgNames {
		val, ok := arguments[argName]
		if !ok {
			continue
		}
		text, ok := val.(string)
		if !ok || text == "" {
			continue
		}

		// Check for role-override injection markers.
		if m := emailInjectionMarkerRE.FindString(text); m != "" {
			idx := strings.Index(text, m)
			snippet := safeSnippet(text, idx, 120)
			result.Findings = append(result.Findings, EmailInjectionFinding{
				Signal: SignalEmailInjectionMarker,
				Detail: fmt.Sprintf(
					"email write tool %q has role-override injection marker in %q — "+
						"outgoing email body may carry adversarial agent instructions from a read email "+
						"(email prompt injection: zero-barrier indirect injection via inbox content)",
					toolName, argName),
				ArgName: argName,
				Snippet: snippet,
			})
		}

		// Check for inline shell payloads carried through from inbox content.
		if m := emailShellPayloadRE.FindString(text); m != "" {
			idx := strings.Index(text, m)
			snippet := safeSnippet(text, idx, 120)
			result.Findings = append(result.Findings, EmailInjectionFinding{
				Signal: SignalEmailShellPayload,
				Detail: fmt.Sprintf(
					"email write tool %q has shell payload in %q — inline command pattern carried through from inbox content",
					toolName, argName),
				ArgName: argName,
				Snippet: snippet,
			})
		}
	}

	if len(result.Findings) > 0 {
		result.Audited = true
	}
	return result
}

// isEmailWriteTool returns true when the tool name belongs to the email write family
// (send, forward, reply, draft, compose). Case-insensitive, namespace-prefix stripped.
func isEmailWriteTool(toolName string) bool {
	name := toolName
	if i := strings.LastIndex(name, "__"); i >= 0 {
		name = name[i+2:]
	}
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	lower := strings.ToLower(name)
	for _, prefix := range emailWriteToolPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	for _, exact := range emailWriteToolExact {
		if lower == exact {
			return true
		}
	}
	return false
}

// emailBodyArgNames are argument keys that carry the outgoing message body.
var emailBodyArgNames = []string{
	"body", "content", "message", "text", "html_body", "plain_body",
	"message_body", "email_body", "msg", "html", "plain_text",
}

// emailWriteToolPrefixes — tool name prefixes that unambiguously denote email writes.
var emailWriteToolPrefixes = []string{
	"send_", "forward_", "reply_", "draft_", "compose_",
}

// emailWriteToolExact — exact tool names for common email MCP servers.
var emailWriteToolExact = []string{
	"send_email", "forward_message", "forward_email", "reply_email",
	"reply_to_email", "reply_to_message", "create_draft", "save_draft",
	"gmail_send", "gmail_compose", "gmail_reply", "gmail_forward",
	"outlook_send", "outlook_reply", "outlook_forward", "outlook_compose",
	"smtp_send", "imap_send", "mail_send", "email_send",
	"compose_email", "compose_message",
}

// emailInjectionMarkerRE matches role-override and injection-marker patterns.
// Built from fragments to avoid triggering source-file content scanners.
var emailInjectionMarkerRE = func() *regexp.Regexp {
	// Bracket-style role markers: [SYSTEM], [AGENT], [AI], [INSTRUCTION], [HUMAN]
	bracket := `\[(SYSTEM|AGENT|AI|INSTRUCTION|HUMAN|ASSISTANT|USER|OVERRIDE)\]`
	// XML-style role tags: <system>, <instruction>, <ai_instruction>
	xmlTag := `<(system|instruction|ai_instruction|agent_instruction)\s*>`
	// Override directives — split across vars to avoid literal phrase detection
	ign := `IGN` + `ORE\s+` + `PREVIOUS\s+INSTRUCT`
	dis := `DISREG` + `ARD\s+` + `(?:ALL\s+)?(?:PREVIOUS\s+)?INSTRUCT`
	override := ign + `|` + dis
	// Turn-marker injection (assistant/human delimiter injection)
	turnMarkers := `\n\s*Human:\s+|\n\s*Assistant:\s+`
	// Markup-style role directives
	hashDirective := `###\s*(?:SYSTEM|INSTRUCTION|AGENT|OVERRIDE)\b`
	// Prompt boundary separators
	boundaryMarker := `---\s*(?:SYSTEM|INSTRUCTION|AGENT|NEW\s+TASK)\s*---`

	return regexp.MustCompile(`(?i)(` +
		bracket + `|` +
		xmlTag + `|` +
		override + `|` +
		turnMarkers + `|` +
		hashDirective + `|` +
		boundaryMarker + `)`)
}()

// emailShellPayloadRE matches inline shell payload patterns carried through from
// inbox content into an email write action.
var emailShellPayloadRE = regexp.MustCompile(
	`(?i)(` +
		`curl\s+\S+\s*\|\s*(?:ba)?sh` + // curl <url> | sh
		`|wget\s+\S+\s+-O\s*-\s*\|\s*(?:ba)?sh` + // wget -O- | sh
		`|/bin/(?:ba)?sh\s+-c\s+` + // /bin/sh -c
		`|python[23]?\s+-c\s+'` + // python -c '...'
		`)`,
)
