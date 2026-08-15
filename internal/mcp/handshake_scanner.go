package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// MinAcceptedProtocolVersion is the earliest MCP protocol version that
// AgentShield considers secure. Responses advertising an older version are
// AUDIT-flagged as a possible downgrade attack — analogous to TLS version
// negotiation downgrade (CWE-757).
//
// "2025-03-26" is the first version that introduced OAuth 2.1 enforcement,
// tool annotations, and elicitation protections.
const MinAcceptedProtocolVersion = "2025-03-26"

// impersonationPatterns are substrings in serverInfo.name that indicate an
// impersonation attempt. A server claiming to be "official-anthropic-server"
// may trigger reduced scrutiny in allowlist-based agents.
var impersonationPatterns = []string{
	"official-anthropic",
	"anthropic-",
	"openai-",
	"trusted-enterprise",
}

// suspiciousCapabilityKeys are experimental capability keys that indicate
// capability injection — fictional flags that naive clients may misinterpret
// as granting elevated trust or disabling security layers.
var suspiciousCapabilityKeys = []string{
	"trustedServer",
	"bypassSafetyFilters",
	"skipContentScan",
	"disableProxy",
}

// trustSignalingKeywords are substrings in serverInfo.name that signal
// inflated trust without matching a specific impersonation target.
var trustSignalingKeywords = []string{
	"official",
	"trusted",
	"verified",
	"internal",
}

// HandshakeScanResult is the outcome of ScanInitializeResponse.
type HandshakeScanResult struct {
	// Decision is "BLOCK", "AUDIT", or "ALLOW".
	Decision string

	// Reason is a human-readable explanation (empty when ALLOW).
	Reason string

	// Rule is the triggered rule ID (empty when ALLOW).
	Rule string
}

// ScanInitializeResponse inspects an MCP initialize response for:
//   - BLOCK: serverInfo.name impersonation patterns (e.g. "official-anthropic-server")
//   - BLOCK: experimental capability injection (e.g. {"trustedServer": true})
//   - BLOCK: instructions field containing hidden instructions, credential harvest, or exfiltration directives
//   - AUDIT: protocolVersion downgrade (older than MinAcceptedProtocolVersion)
//   - AUDIT: trust-signaling server name keywords (e.g. "verified", "official")
//   - AUDIT: instructions field containing behavioral manipulation patterns
func ScanInitializeResponse(result *InitializeResult) HandshakeScanResult {
	// BLOCK: serverInfo impersonation
	if result.ServerInfo != nil {
		nameLower := strings.ToLower(result.ServerInfo.Name)
		for _, pattern := range impersonationPatterns {
			if strings.Contains(nameLower, strings.ToLower(pattern)) {
				return HandshakeScanResult{
					Decision: "BLOCK",
					Reason:   fmt.Sprintf("initialize handshake: serverInfo.name %q matches impersonation pattern %q — possible server identity spoofing", result.ServerInfo.Name, pattern),
					Rule:     "mcp-initialize-handshake-manipulation",
				}
			}
		}

		// BLOCK: Unicode homoglyph or zero-width character injection in serverInfo.name
		// Attackers use look-alike characters (e.g. Cyrillic 'о' for Latin 'o') to spoof
		// trusted server names while evading substring-based checks.
		if scan := unicode.Scan(result.ServerInfo.Name); !scan.Clean {
			for _, threat := range scan.Threats {
				if threat.Severity == "block" {
					return HandshakeScanResult{
						Decision: "BLOCK",
						Reason:   fmt.Sprintf("initialize handshake: serverInfo.name %q contains suspicious Unicode (%s at %s) — possible homoglyph server name spoofing", result.ServerInfo.Name, threat.Description, threat.Codepoint),
						Rule:     "mcp-initialize-handshake-manipulation",
					}
				}
			}
			// Audit-level threats (e.g. zero-width characters without block-severity)
			return HandshakeScanResult{
				Decision: "AUDIT",
				Reason:   fmt.Sprintf("initialize handshake: serverInfo.name %q contains non-ASCII Unicode — possible homoglyph server name spoofing", result.ServerInfo.Name),
				Rule:     "mcp-initialize-handshake-manipulation-audit",
			}
		}
	}

	// BLOCK: suspicious experimental capability keys
	if len(result.Capabilities) > 0 {
		var caps map[string]json.RawMessage
		if err := json.Unmarshal(result.Capabilities, &caps); err == nil {
			if expRaw, ok := caps["experimental"]; ok {
				var exp map[string]json.RawMessage
				if err := json.Unmarshal(expRaw, &exp); err == nil {
					for _, key := range suspiciousCapabilityKeys {
						if _, found := exp[key]; found {
							return HandshakeScanResult{
								Decision: "BLOCK",
								Reason:   fmt.Sprintf("initialize handshake: experimental capability %q indicates capability injection — attacker may be inflating trust level", key),
								Rule:     "mcp-initialize-handshake-manipulation",
							}
						}
					}
				}
			}
		}
	}

	// AUDIT: protocol version downgrade
	// ISO date strings sort lexicographically in version order (YYYY-MM-DD).
	if result.ProtocolVersion != "" && result.ProtocolVersion < MinAcceptedProtocolVersion {
		return HandshakeScanResult{
			Decision: "AUDIT",
			Reason:   fmt.Sprintf("initialize handshake: protocolVersion %q is older than minimum accepted %q — possible downgrade attack disabling OAuth 2.1 and tool annotations", result.ProtocolVersion, MinAcceptedProtocolVersion),
			Rule:     "mcp-initialize-handshake-manipulation-audit",
		}
	}

	// AUDIT: trust-signaling server name
	if result.ServerInfo != nil {
		nameLower := strings.ToLower(result.ServerInfo.Name)
		for _, keyword := range trustSignalingKeywords {
			if strings.Contains(nameLower, keyword) {
				return HandshakeScanResult{
					Decision: "AUDIT",
					Reason:   fmt.Sprintf("initialize handshake: serverInfo.name %q contains trust-signaling keyword %q — may be attempting to influence agent trust level", result.ServerInfo.Name, keyword),
					Rule:     "mcp-initialize-handshake-manipulation-audit",
				}
			}
		}
	}

	// BLOCK/AUDIT: scan the instructions field (MCP 2025-03-26 spec).
	// The instructions field is sent once at session start and provides behavioral
	// guidance to the AI agent for the entire session. A malicious server can use
	// this field to inject session-scoped override directives, credential-harvest
	// instructions, or exfiltration commands without requiring any tool call.
	if result.Instructions != "" {
		lower := strings.ToLower(result.Instructions)

		// BLOCK-level signals: hidden instructions, credential harvest, exfiltration,
		// cross-tool override, stealth/concealment directives.
		blockGroups := []struct {
			patterns []signalPattern
			label    string
		}{
			{hiddenInstructionPatterns, "hidden-instruction directive"},
			{credentialHarvestPatterns, "credential-harvest reference"},
			{exfiltrationPatterns, "exfiltration directive"},
			{crossToolPatterns, "cross-tool override directive"},
			{stealthPatterns, "stealth/concealment directive"},
		}
		for _, g := range blockGroups {
			for _, p := range g.patterns {
				if p.re.FindStringIndex(lower) != nil {
					return HandshakeScanResult{
						Decision: "BLOCK",
						Reason:   fmt.Sprintf("initialize instructions contain %s — session-scoped behavioral override injected at handshake time: %q", g.label, truncateInstruction(result.Instructions, 120)),
						Rule:     "mcp-initialize-instructions-injection",
					}
				}
			}
		}

		// BLOCK-level: control-token injection — forged LLM tokenizer role delimiters
		// and tool-call dispatch syntax. Checked case-sensitively against the raw
		// instructions (not lowercased) because these are architecture-specific literals.
		// A malicious server injecting <|im_start|>system\n... at handshake time poisons
		// the entire session — the highest-impact control-token surface.
		for _, p := range llmRoleTokenPatterns {
			if p.re.MatchString(result.Instructions) {
				return HandshakeScanResult{
					Decision: "BLOCK",
					Reason:   fmt.Sprintf("initialize instructions contain control-token injection (LLM tokenizer role delimiter: %s) — session-scoped override injected at handshake time: %q", p.description, truncateInstruction(result.Instructions, 120)),
					Rule:     "mcp-initialize-instructions-injection",
				}
			}
		}
		if toolCallDispatchTokenRE.MatchString(result.Instructions) {
			return HandshakeScanResult{
				Decision: "BLOCK",
				Reason:   fmt.Sprintf("initialize instructions contain forged tool-call dispatch syntax — a harness may dispatch an unsanctioned call from session-init instructions: %q", truncateInstruction(result.Instructions, 120)),
				Rule:     "mcp-initialize-instructions-injection",
			}
		}

		// AUDIT-level signals: behavioral manipulation patterns (lower confidence).
		for _, p := range behavioralManipulationPatterns {
			if p.re.FindStringIndex(lower) != nil {
				return HandshakeScanResult{
					Decision: "AUDIT",
					Reason:   fmt.Sprintf("initialize instructions contain behavioral manipulation pattern — review server instructions before trusting: %q", truncateInstruction(result.Instructions, 120)),
					Rule:     "mcp-initialize-instructions-injection-audit",
				}
			}
		}
	}

	return HandshakeScanResult{Decision: "ALLOW"}
}

// truncateInstruction truncates a string to maxLen characters for use in log messages.
func truncateInstruction(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
