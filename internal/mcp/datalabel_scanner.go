package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// DataLabelScanner scans MCP tool call arguments for customer-defined
// sensitive data patterns. A nil scanner is safe — callers nil-check before use.
type DataLabelScanner struct {
	engine *datalabel.Engine
}

// NewDataLabelScanner creates an MCP data label scanner wrapping the given engine.
func NewDataLabelScanner(engine *datalabel.Engine) *DataLabelScanner {
	return &DataLabelScanner{engine: engine}
}

// DataLabelScanResult holds the outcome of scanning a tool call's arguments.
type DataLabelScanResult struct {
	Blocked  bool
	Findings []DataLabelFinding
}

// DataLabelFinding describes a single data label match in a tool argument.
type DataLabelFinding struct {
	LabelID   string
	LabelName string
	Detail    string
	ArgName   string
	Decision  string
}

// ScanToolCallContent scans all arguments of an MCP tool call for data label
// matches. Outbound direction (agent → tool).
func (s *DataLabelScanner) ScanToolCallContent(toolName string, arguments map[string]interface{}) DataLabelScanResult {
	var result DataLabelScanResult
	if s == nil || s.engine == nil {
		return result
	}

	for argName, argValue := range arguments {
		text := argToString(argValue)
		if text == "" {
			continue
		}

		matches := s.engine.ScanText(text, toolName, "outbound")
		for _, m := range matches {
			finding := DataLabelFinding{
				LabelID:   m.LabelID,
				LabelName: m.LabelName,
				Detail:    fmt.Sprintf("%s: matched %q", m.Reason, m.MatchText),
				ArgName:   argName,
				Decision:  m.Decision,
			}
			result.Findings = append(result.Findings, finding)

			if m.Decision == "BLOCK" {
				result.Blocked = true
			}
		}
	}

	return result
}

// ScanToolResponseContent scans text content from an MCP tool response for
// data label matches. Inbound direction (tool → agent). Used to catch
// sensitive data flowing back from downstream servers (e.g. a database
// query tool returning a row containing an SSN).
//
// Because the response path does not carry the originating tool name,
// toolName is empty — scope.tools filters will not apply to response scans.
// Customers that want to scan responses should use `directions: ["inbound"]`
// (plus `shell: false` if the label should only fire in MCP contexts).
// This is the BUG-DL-006 fix: previously the engine was hardcoded to
// "outbound" and inbound labels were silently ineffective.
func (s *DataLabelScanner) ScanToolResponseContent(textContent string) DataLabelScanResult {
	var result DataLabelScanResult
	if s == nil || s.engine == nil || textContent == "" {
		return result
	}

	matches := s.engine.ScanText(textContent, "", "inbound")
	for _, m := range matches {
		finding := DataLabelFinding{
			LabelID:   m.LabelID,
			LabelName: m.LabelName,
			Detail:    fmt.Sprintf("%s: matched %q", m.Reason, m.MatchText),
			ArgName:   "response.content",
			Decision:  m.Decision,
		}
		result.Findings = append(result.Findings, finding)

		if m.Decision == "BLOCK" {
			result.Blocked = true
		}
	}

	return result
}

// argToString converts an argument value to a string for scanning.
// Handles strings, nested maps, and arrays by JSON-encoding non-strings.
func argToString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case nil:
		return ""
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Sprintf("%v", val)
		}
		return string(b)
	}
}
