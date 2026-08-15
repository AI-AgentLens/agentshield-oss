package mcp

import (
	"fmt"

	"github.com/AI-AgentLens/agentshield/internal/unicode"
)

// Manifest flooding thresholds. A malicious MCP server may return an
// excessively large tools/list response to dilute the agent's context window
// and push safety guardrails out of effective attention range.
//
// Hard limits trigger BLOCK (the response is replaced with an error).
// Soft limits trigger AUDIT (the response is forwarded but flagged).
const (
	// ToolsListHardBlockCount is the maximum number of tools allowed before blocking.
	ToolsListHardBlockCount = 200

	// ToolsListAuditCount is the number of tools above which an AUDIT event is emitted.
	ToolsListAuditCount = 50

	// ToolsListHardBlockBytes is the maximum manifest byte size before blocking (500 KB).
	ToolsListHardBlockBytes = 512_000

	// ToolsListAuditBytes is the manifest byte size above which an AUDIT event is emitted (100 KB).
	ToolsListAuditBytes = 102_400

	// ToolsListMaxDescriptionBytes is the per-tool description size that triggers an AUDIT.
	ToolsListMaxDescriptionBytes = 2048
)

// ManifestScanResult is the result of ScanToolsListManifest.
type ManifestScanResult struct {
	// Decision is "BLOCK", "AUDIT", or "ALLOW".
	Decision string

	// Reason is a human-readable explanation (empty when ALLOW).
	Reason string

	// Rule is the triggered rule ID (empty when ALLOW).
	Rule string

	// ToolCount is the number of tools in the manifest.
	ToolCount int

	// ManifestBytes is the raw byte size of the full response payload.
	ManifestBytes int

	// LargestDescriptionBytes is the size of the largest tool description.
	LargestDescriptionBytes int
}

// ScanToolsListManifest checks a tools/list response for manifest flooding.
// toolCount and manifestBytes are the number of tools and the raw byte size of
// the full JSON-RPC response payload, respectively.
func ScanToolsListManifest(tools []ToolDefinition, manifestBytes int) ManifestScanResult {
	toolCount := len(tools)

	var largestDesc int
	for _, t := range tools {
		if n := len(t.Description); n > largestDesc {
			largestDesc = n
		}
	}

	// BLOCK: hard limits
	if toolCount > ToolsListHardBlockCount {
		return ManifestScanResult{
			Decision:                "BLOCK",
			Reason:                  fmt.Sprintf("tools/list flooding: %d tools returned (hard limit: %d) — context-window dilution attack", toolCount, ToolsListHardBlockCount),
			Rule:                    "mcp-tools-list-flooding",
			ToolCount:               toolCount,
			ManifestBytes:           manifestBytes,
			LargestDescriptionBytes: largestDesc,
		}
	}
	if manifestBytes > ToolsListHardBlockBytes {
		return ManifestScanResult{
			Decision:                "BLOCK",
			Reason:                  fmt.Sprintf("tools/list flooding: manifest is %d bytes (hard limit: %d) — context-window dilution attack", manifestBytes, ToolsListHardBlockBytes),
			Rule:                    "mcp-tools-list-flooding",
			ToolCount:               toolCount,
			ManifestBytes:           manifestBytes,
			LargestDescriptionBytes: largestDesc,
		}
	}

	// AUDIT: soft limits or oversized descriptions
	if toolCount > ToolsListAuditCount {
		return ManifestScanResult{
			Decision:                "AUDIT",
			Reason:                  fmt.Sprintf("tools/list anomaly: %d tools (audit threshold: %d) — possible context dilution", toolCount, ToolsListAuditCount),
			Rule:                    "mcp-tools-list-flooding-audit",
			ToolCount:               toolCount,
			ManifestBytes:           manifestBytes,
			LargestDescriptionBytes: largestDesc,
		}
	}
	if manifestBytes > ToolsListAuditBytes {
		return ManifestScanResult{
			Decision:                "AUDIT",
			Reason:                  fmt.Sprintf("tools/list anomaly: manifest is %d bytes (audit threshold: %d) — possible context dilution", manifestBytes, ToolsListAuditBytes),
			Rule:                    "mcp-tools-list-flooding-audit",
			ToolCount:               toolCount,
			ManifestBytes:           manifestBytes,
			LargestDescriptionBytes: largestDesc,
		}
	}
	if largestDesc > ToolsListMaxDescriptionBytes {
		return ManifestScanResult{
			Decision:                "AUDIT",
			Reason:                  fmt.Sprintf("tools/list anomaly: largest tool description is %d bytes (limit: %d) — verbose/padded descriptions may signal poisoning amplifier", largestDesc, ToolsListMaxDescriptionBytes),
			Rule:                    "mcp-tools-list-flooding-audit",
			ToolCount:               toolCount,
			ManifestBytes:           manifestBytes,
			LargestDescriptionBytes: largestDesc,
		}
	}

	// BLOCK: Unicode confusables in tool names (issue #1970).
	//
	// Legitimate MCP tool names are always ASCII identifiers (e.g., read_file,
	// list_directory). A tool name containing Cyrillic/Greek homoglyphs (e.g.,
	// reаd_file with Cyrillic 'а' U+0430), zero-width characters (U+200B/200C/200D),
	// bidirectional override (U+202E RTLO), or Unicode Tags block characters
	// (U+E0000–U+E007F) has no legitimate use — it indicates a tool name
	// impersonation attack where a malicious server registers a look-alike tool.
	//
	// Attack: prompt injection tricks the agent into calling the homoglyph tool
	// (which executes attacker logic) instead of the legitimate ASCII-named tool.
	//
	// Detection reuses the existing internal/unicode.Scan function (already used
	// by handshake_scanner.go for serverInfo.name). Unlike the general-purpose
	// context (where homoglyphs may appear in commit messages/docs at audit
	// severity), ANY non-ASCII Unicode in a tool name is suspicious — tool names
	// are machine identifiers, not human-readable text.
	for _, t := range tools {
		if scan := unicode.Scan(t.Name); !scan.Clean {
			for _, threat := range scan.Threats {
				// All confusable categories are BLOCK in tool names: there is no
				// legitimate use for Cyrillic, Greek, zero-width, bidi-override,
				// tag-char, or invalid-utf8 in an MCP tool identifier.
				return ManifestScanResult{
					Decision:                "BLOCK",
					Reason:                  fmt.Sprintf("tools/list: tool name %q contains suspicious Unicode (%s at %s) — possible tool name impersonation attack (homoglyph or invisible-character variant of a legitimate tool name)", t.Name, threat.Description, threat.Codepoint),
					Rule:                    "mcp-tools-list-tool-name-homoglyph",
					ToolCount:               toolCount,
					ManifestBytes:           manifestBytes,
					LargestDescriptionBytes: largestDesc,
				}
			}
			// Catch non-ASCII tool names that Scan marked as not-clean but
			// produced no categorised threats (e.g. arbitrary non-Latin script).
			return ManifestScanResult{
				Decision:                "BLOCK",
				Reason:                  fmt.Sprintf("tools/list: tool name %q contains non-ASCII characters — MCP tool names must be ASCII identifiers; non-ASCII indicates possible tool name spoofing", t.Name),
				Rule:                    "mcp-tools-list-tool-name-homoglyph",
				ToolCount:               toolCount,
				ManifestBytes:           manifestBytes,
				LargestDescriptionBytes: largestDesc,
			}
		}
	}

	return ManifestScanResult{
		Decision:                "ALLOW",
		ToolCount:               toolCount,
		ManifestBytes:           manifestBytes,
		LargestDescriptionBytes: largestDesc,
	}
}
