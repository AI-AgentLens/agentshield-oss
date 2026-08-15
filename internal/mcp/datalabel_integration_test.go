package mcp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

// TestIntegration_DataLabel_MCP_FromYAML is the regression floor for the
// homepage DLP claim on the MCP side. It writes a real mcp-policy.yaml to
// disk, loads it through LoadMCPPolicy + ConvertDataLabels (the same path
// `agentshield mcp-proxy` uses at startup), and asserts a synthetic tool
// call carrying labelled data is correctly flagged BLOCK by the scanner.
//
// Why this test exists:
// Existing mcp/datalabel_scanner_test.go constructs the engine directly in
// Go. That bypasses the YAML schema → MCPPolicy.DataLabels → ConvertDataLabels
// → Engine wiring used in production. A struct-tag typo or schema field
// rename (e.g. data_labels → datalabels) would silently load zero labels
// and customer PII would walk straight through.
const dlMCPPolicyYAML = `version: "0.1"
defaults:
  decision: "AUDIT"

data_labels:
  - id: "pii-ssn"
    name: "Social Security Number"
    decision: "BLOCK"
    confidence: 0.95
    reason: "SSN pattern detected"
    patterns:
      - regex: '\b\d{3}-\d{2}-\d{4}\b'

  - id: "internal-codename"
    name: "Internal Project Codename"
    decision: "BLOCK"
    confidence: 0.90
    reason: "Confidential project codename detected"
    patterns:
      - keywords: ["PHOENIX", "TITAN"]
        case_sensitive: true
`

func TestIntegration_DataLabel_MCP_FromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp-policy.yaml")
	if err := os.WriteFile(path, []byte(dlMCPPolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	pol, err := LoadMCPPolicy(path)
	if err != nil {
		t.Fatalf("LoadMCPPolicy: %v", err)
	}
	if got := len(pol.DataLabels); got != 2 {
		t.Fatalf("expected 2 data labels, got %d (yaml schema regression?)", got)
	}

	engine, err := datalabel.NewEngine(ConvertDataLabels(pol.DataLabels))
	if err != nil {
		t.Fatalf("datalabel.NewEngine: %v", err)
	}
	if engine == nil {
		t.Fatal("engine is nil — labels did not survive YAML → engine conversion")
	}
	scanner := NewDataLabelScanner(engine)

	cases := []struct {
		name        string
		toolName    string
		args        map[string]interface{}
		wantBlocked bool
		wantLabel   string
	}{
		{
			name:        "ssn in tool argument is blocked",
			toolName:    "send_email",
			args:        map[string]interface{}{"body": "Customer SSN: 123-45-6789, please update"},
			wantBlocked: true,
			wantLabel:   "pii-ssn",
		},
		{
			name:        "codename keyword in tool argument is blocked",
			toolName:    "post_message",
			args:        map[string]interface{}{"text": "Project PHOENIX is launching tomorrow"},
			wantBlocked: true,
			wantLabel:   "internal-codename",
		},
		{
			name:        "ssn in nested structured argument is blocked (json-encoded)",
			toolName:    "create_ticket",
			args:        map[string]interface{}{"meta": map[string]interface{}{"note": "ssn 123-45-6789"}},
			wantBlocked: true,
			wantLabel:   "pii-ssn",
		},
		{
			name:        "benign tool call passes",
			toolName:    "get_weather",
			args:        map[string]interface{}{"location": "San Francisco"},
			wantBlocked: false,
		},
		{
			name:        "lowercase codename does not fire (case_sensitive: true)",
			toolName:    "post_message",
			args:        map[string]interface{}{"text": "phoenix is just a bird"},
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanner.ScanToolCallContent(tc.toolName, tc.args)
			if res.Blocked != tc.wantBlocked {
				t.Fatalf("Blocked=%v want=%v findings=%+v", res.Blocked, tc.wantBlocked, res.Findings)
			}
			if tc.wantLabel != "" {
				found := false
				for _, f := range res.Findings {
					if f.LabelID == tc.wantLabel {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected finding with LabelID %q, got %+v", tc.wantLabel, res.Findings)
				}
			}
		})
	}
}
