package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
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
//   - AUDIT: protocolVersion downgrade (older than MinAcceptedProtocolVersion)
//   - AUDIT: trust-signaling server name keywords (e.g. "verified", "official")
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

	return HandshakeScanResult{Decision: "ALLOW"}
}
