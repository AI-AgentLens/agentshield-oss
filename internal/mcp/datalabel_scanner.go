package mcp

import (
	"encoding/json"
	"fmt"

	"github.com/security-researcher-ca/agentshield/internal/datalabel"
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

// ScanToolCallContent scans all arguments of an MCP tool call for data label matches.
func (s *DataLabelScanner) ScanToolCallContent(toolName string, arguments map[string]interface{}) DataLabelScanResult {
	var result DataLabelScanResult

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
