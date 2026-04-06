package mcp

import (
	"testing"

	"github.com/security-researcher-ca/agentshield/internal/datalabel"
)

func newTestDataLabelScanner(t *testing.T) *DataLabelScanner {
	t.Helper()
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:         "pii-ssn",
			Name:       "Social Security Number",
			Decision:   "BLOCK",
			Confidence: 0.90,
			Reason:     "SSN detected",
			Patterns:   []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
		{
			ID:         "pii-email",
			Name:       "Email Address",
			Decision:   "AUDIT",
			Confidence: 0.70,
			Reason:     "Email detected",
			Patterns:   []datalabel.PatternConfig{{Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	return NewDataLabelScanner(engine)
}

func TestDataLabelScanner_BlockOnSSN(t *testing.T) {
	scanner := newTestDataLabelScanner(t)
	result := scanner.ScanToolCallContent("write_file", map[string]interface{}{
		"path":    "/tmp/data.txt",
		"content": "Employee SSN: 123-45-6789",
	})

	if !result.Blocked {
		t.Fatal("expected BLOCK for SSN in content")
	}
	if len(result.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if result.Findings[0].LabelID != "pii-ssn" {
		t.Errorf("wrong label: %s", result.Findings[0].LabelID)
	}
	if result.Findings[0].ArgName != "content" {
		t.Errorf("wrong arg name: %s", result.Findings[0].ArgName)
	}
}

func TestDataLabelScanner_AuditOnEmail(t *testing.T) {
	scanner := newTestDataLabelScanner(t)
	result := scanner.ScanToolCallContent("send_message", map[string]interface{}{
		"body": "Contact us at support@example.com",
	})

	if result.Blocked {
		t.Fatal("expected AUDIT (not BLOCK) for email")
	}
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	if result.Findings[0].LabelID != "pii-email" {
		t.Errorf("wrong label: %s", result.Findings[0].LabelID)
	}
}

func TestDataLabelScanner_NoMatch(t *testing.T) {
	scanner := newTestDataLabelScanner(t)
	result := scanner.ScanToolCallContent("read_file", map[string]interface{}{
		"path": "/workspace/README.md",
	})

	if result.Blocked {
		t.Fatal("expected no block for benign content")
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestDataLabelScanner_NilArguments(t *testing.T) {
	scanner := newTestDataLabelScanner(t)
	result := scanner.ScanToolCallContent("test_tool", nil)

	if result.Blocked {
		t.Fatal("expected no block for nil arguments")
	}
}

func TestDataLabelScanner_NestedArguments(t *testing.T) {
	scanner := newTestDataLabelScanner(t)
	result := scanner.ScanToolCallContent("api_call", map[string]interface{}{
		"data": map[string]interface{}{
			"ssn": "123-45-6789",
		},
	})

	if !result.Blocked {
		t.Fatal("expected BLOCK for SSN in nested argument")
	}
}

func TestArgToString(t *testing.T) {
	tests := []struct {
		name string
		val  interface{}
		want string
	}{
		{name: "string", val: "hello", want: "hello"},
		{name: "nil", val: nil, want: ""},
		{name: "number", val: 42.0, want: "42"},
		{name: "bool", val: true, want: "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := argToString(tt.val)
			if got != tt.want {
				t.Errorf("argToString(%v) = %q, want %q", tt.val, got, tt.want)
			}
		})
	}
}
