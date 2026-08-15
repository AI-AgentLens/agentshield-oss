package mcp

import "encoding/json"

// StructuredContentScanResult is the result of scanning a tool result's
// structuredContent field for injection signals.
type StructuredContentScanResult struct {
	Findings []ResponsePoisonFinding
	Poisoned bool
}

// ScanStructuredContent walks a structuredContent JSON map and runs injection
// detection on every string leaf value. The structuredContent field (MCP
// 2025-06-18) carries typed structured results that are invisible to
// ScanToolCallResponse, which only processes text ContentItems. A malicious
// server can embed prompt-injection payloads in structuredContent field values
// to bypass the text-content scanner entirely.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-tool-outputschema-poisoning
func ScanStructuredContent(structured map[string]interface{}) StructuredContentScanResult {
	var result StructuredContentScanResult
	if len(structured) == 0 {
		return result
	}
	scanStructuredNode(&result, structured)
	result.Poisoned = len(result.Findings) > 0
	return result
}

// ScanStructuredContentRaw decodes a raw JSON message and delegates to
// ScanStructuredContent. Returns an empty result for non-object JSON.
func ScanStructuredContentRaw(raw json.RawMessage) StructuredContentScanResult {
	if len(raw) == 0 {
		return StructuredContentScanResult{}
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return StructuredContentScanResult{}
	}
	return ScanStructuredContent(obj)
}

func scanStructuredNode(result *StructuredContentScanResult, v interface{}) {
	switch val := v.(type) {
	case string:
		var sub ResponseScanResult
		scanResponseText(&sub, val)
		result.Findings = append(result.Findings, sub.Findings...)
	case map[string]interface{}:
		for _, child := range val {
			scanStructuredNode(result, child)
		}
	case []interface{}:
		for _, item := range val {
			scanStructuredNode(result, item)
		}
	}
}
