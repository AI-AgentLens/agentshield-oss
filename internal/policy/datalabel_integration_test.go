package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIntegration_DataLabel_Shell_FromYAML is the regression floor for the
// homepage DLP claim on the shell side. It writes a real policy.yaml to disk,
// loads it through the same code path used by `agentshield run` / hooks, and
// asserts that customer-defined data labels actually fire through the full
// Layer-7 pipeline.
//
// Why this test exists:
// Every other datalabel test constructs the engine directly in Go
// (datalabel.NewEngine([]DataLabelConfig{...})). That leaves the YAML schema
// → policy.Policy → datalabel.Engine wiring path uncovered, so a typo in a
// yaml struct tag (e.g. `case_sensitive` → `casesensitive`) would silently
// load zero labels and every unit test would still pass. This test fails
// closed on that scenario.
const dlTestPolicyYAML = `version: "0.1"
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

func TestIntegration_DataLabel_Shell_FromYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte(dlTestPolicyYAML), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}

	pol, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(pol.DataLabels); got != 2 {
		t.Fatalf("expected 2 data labels, got %d (yaml schema regression?)", got)
	}

	engine, err := NewEngineWithAnalyzers(pol, 0)
	if err != nil {
		t.Fatalf("NewEngineWithAnalyzers: %v", err)
	}

	cases := []struct {
		name        string
		command     string
		wantBlocked bool
		wantRule    string // expected substring in TriggeredRules
	}{
		{
			name:        "ssn regex fires and blocks",
			command:     `echo "SSN: 123-45-6789"`,
			wantBlocked: true,
			wantRule:    "dl-pii-ssn",
		},
		{
			name:        "case-sensitive codename keyword fires and blocks",
			command:     `echo "Project PHOENIX shipping next quarter"`,
			wantBlocked: true,
			wantRule:    "dl-internal-codename",
		},
		{
			name:        "lowercase codename does not fire (case_sensitive: true)",
			command:     `echo "phoenix is just a bird"`,
			wantBlocked: false,
		},
		{
			name:        "benign command does not block",
			command:     `echo hello world`,
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := engine.Evaluate(tc.command, nil)
			gotBlocked := res.Decision == DecisionBlock
			if gotBlocked != tc.wantBlocked {
				t.Fatalf("Decision=%s blocked=%v, want blocked=%v (rules=%v reasons=%v)",
					res.Decision, gotBlocked, tc.wantBlocked, res.TriggeredRules, res.Reasons)
			}
			if tc.wantRule != "" && !containsRule(res.TriggeredRules, tc.wantRule) {
				t.Errorf("expected TriggeredRules to contain %q, got %v", tc.wantRule, res.TriggeredRules)
			}
		})
	}
}

func containsRule(rules []string, want string) bool {
	for _, r := range rules {
		if strings.Contains(r, want) {
			return true
		}
	}
	return false
}
