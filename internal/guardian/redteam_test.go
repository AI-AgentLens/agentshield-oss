package guardian

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// RedTeamCommand is a single command within a red-team case.
type RedTeamCommand struct {
	Cmd             string   `yaml:"cmd"`
	GuardianMin     string   `yaml:"guardian_min"`
	PipelineMin     string   `yaml:"pipeline_min"`
	ExpectedSignals []string `yaml:"expected_signals"`
}

// RedTeamCase is a single red-team regression test case loaded from YAML.
type RedTeamCase struct {
	ID           string           `yaml:"id"`
	AgentContext string           `yaml:"agent_context"`
	Commands     []RedTeamCommand `yaml:"commands"`
	Description  string           `yaml:"description"`
}

// RedTeamSuite is the top-level YAML structure.
type RedTeamSuite struct {
	Cases []RedTeamCase `yaml:"cases"`
}

// loadRedTeamCases reads and parses the red-team YAML file.
func loadRedTeamCases(t *testing.T) []RedTeamCase {
	t.Helper()

	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	path := filepath.Join(dir, "testdata", "redteam_cases.yaml")

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read red-team cases: %v", err)
	}

	var suite RedTeamSuite
	if err := yaml.Unmarshal(data, &suite); err != nil {
		t.Fatalf("failed to parse red-team YAML: %v", err)
	}

	if len(suite.Cases) == 0 {
		t.Fatal("no red-team cases loaded")
	}

	return suite.Cases
}

// decisionSeverity maps decisions to numeric severity for comparison.
func decisionSeverity(d string) int {
	switch strings.ToUpper(d) {
	case "BLOCK":
		return 2
	case "AUDIT":
		return 1
	case "ALLOW":
		return 0
	default:
		return -1
	}
}

// TestRedTeamGuardian runs all red-team cases through the heuristic guardian
// in isolation and asserts guardian_min decision + expected signals.
func TestRedTeamGuardian(t *testing.T) {
	cases := loadRedTeamCases(t)
	provider := NewHeuristicProvider()

	var passed, failed int

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			for _, cmd := range tc.Commands {
				resp, err := provider.Analyze(GuardianRequest{
					RawCommand:   cmd.Cmd,
					AgentContext: tc.AgentContext,
				})
				if err != nil {
					t.Errorf("  command %q: unexpected error: %v", cmd.Cmd, err)
					failed++
					continue
				}

				gotSev := decisionSeverity(resp.SuggestedDecision)
				wantSev := decisionSeverity(cmd.GuardianMin)

				if gotSev < wantSev {
					t.Errorf("  command: %q\n    expected guardian_min: %s (sev=%d)\n    got:                  %s (sev=%d)\n    signals:              %v",
						cmd.Cmd, cmd.GuardianMin, wantSev,
						resp.SuggestedDecision, gotSev, signalIDs(resp.Signals))
					failed++
				} else {
					passed++
				}

				for _, wantSig := range cmd.ExpectedSignals {
					if !hasSignal(resp.Signals, wantSig) {
						t.Errorf("  command: %q\n    missing expected signal: %s\n    got signals: %v",
							cmd.Cmd, wantSig, signalIDs(resp.Signals))
					}
				}
			}
		})
	}

	t.Logf("\n  Guardian-only harness: %d/%d command checks passed", passed, passed+failed)
}

// TestRedTeamReport generates a markdown report of guardian-only red-team results.
func TestRedTeamReport(t *testing.T) {
	cases := loadRedTeamCases(t)
	provider := NewHeuristicProvider()

	var sb strings.Builder
	sb.WriteString("# AgentShield Red-Team Regression Report\n\n")
	sb.WriteString("## Guardian-Only Results\n\n")
	sb.WriteString("| Case | Command | Guardian Min | Got | Signals | Status |\n")
	sb.WriteString("|------|---------|-------------|-----|---------|--------|\n")

	totalCmds := 0
	passedCmds := 0

	for _, tc := range cases {
		for _, cmd := range tc.Commands {
			totalCmds++
			resp, err := provider.Analyze(GuardianRequest{
				RawCommand:   cmd.Cmd,
				AgentContext: tc.AgentContext,
			})

			status := "PASS"
			if err != nil {
				status = "FAIL (error)"
			} else if decisionSeverity(resp.SuggestedDecision) < decisionSeverity(cmd.GuardianMin) {
				status = "FAIL (too lenient)"
			} else {
				passedCmds++
			}

			shortCmd := cmd.Cmd
			if len(shortCmd) > 60 {
				shortCmd = shortCmd[:57] + "..."
			}

			sigs := strings.Join(signalIDs(resp.Signals), ", ")
			if sigs == "" {
				sigs = "(none)"
			}
			got := "ALLOW"
			if err == nil {
				got = resp.SuggestedDecision
			}

			fmt.Fprintf(&sb, "| `%s` | `%s` | %s | %s | %s | %s |\n",
				tc.ID, shortCmd, cmd.GuardianMin, got, sigs, status)
		}
	}

	fmt.Fprintf(&sb, "\n**Guardian-only: %d/%d commands meet minimum decision (%0.1f%%)**\n",
		passedCmds, totalCmds, float64(passedCmds)/float64(totalCmds)*100)
	sb.WriteString("\n> Note: This tests the guardian layer in isolation. The full pipeline\n")
	sb.WriteString("> (regex + structural + semantic + dataflow + stateful + guardian)\n")
	sb.WriteString("> provides additional detection coverage for cases where guardian_min = ALLOW.\n")

	_, filename, _, _ := runtime.Caller(0)
	dir := filepath.Dir(filename)
	reportPath := filepath.Join(dir, "testdata", "GUARDIAN_REDTEAM_REPORT.md")
	if err := os.WriteFile(reportPath, []byte(sb.String()), 0644); err != nil {
		t.Logf("warning: could not write report: %v", err)
	} else {
		t.Logf("Generated %s with %d command checks", reportPath, totalCmds)
	}
}
