package mcp

import "fmt"

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

	return ManifestScanResult{
		Decision:                "ALLOW",
		ToolCount:               toolCount,
		ManifestBytes:           manifestBytes,
		LargestDescriptionBytes: largestDesc,
	}
}
