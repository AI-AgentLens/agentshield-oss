package analyzer_test

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/analyzer/testdata"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// ---------------------------------------------------------------------------
// Test Runner Infrastructure
//
// runTestCases is the shared test runner that evaluates each command through
// the policy engine and validates the decision against expectations.
//
// Classification handling:
//   - TP (True Positive): Command MUST produce the expected decision.
//   - TN (True Negative): Command MUST produce the expected decision.
//   - FP (False Positive): Skipped — documents known FP. Will be promoted
//     to TN once the analyzer that fixes it is implemented.
//   - FN (False Negative): Skipped — documents known gaps. Will be promoted
//     to TP once the analyzer that catches it is implemented.
// ---------------------------------------------------------------------------

func runTestCases(t *testing.T, cases []testdata.TestCase) {
	t.Helper()

	engine := newTestEngine(t)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			// Skip known FP/FN cases — they document limitations, not regressions.
			if tc.Classification == "FN" {
				t.Skipf("KNOWN FALSE NEGATIVE — awaiting analyzer: %s\n  %s",
					tc.Analyzer, firstLine(tc.Description))
				return
			}
			if tc.Classification == "FP" {
				t.Skipf("KNOWN FALSE POSITIVE — awaiting analyzer: %s\n  %s",
					tc.Analyzer, firstLine(tc.Description))
				return
			}

			// Skip promoted TP/TN cases that require structural/semantic analyzers.
			// These pass with the full pipeline but not the regex-only engine.
			if tc.Analyzer == "structural" || tc.Analyzer == "semantic" || tc.Analyzer == "stateful" || tc.Analyzer == "dataflow" || tc.Analyzer == "pipeline" || tc.Analyzer == "guardian" {
				t.Skipf("PIPELINE-ONLY — requires %s analyzer", tc.Analyzer)
				return
			}

			result := engine.Evaluate(tc.Command, nil)
			actual := string(result.Decision)

			if actual != tc.ExpectedDecision {
				t.Errorf(
					"[%s] %s\n"+
						"  Command:    %q\n"+
						"  Expected:   %s\n"+
						"  Got:        %s\n"+
						"  Taxonomy:   %s\n"+
						"  Triggered:  %v\n"+
						"  Reason:     %s",
					tc.Classification, tc.ID,
					tc.Command,
					tc.ExpectedDecision,
					actual,
					tc.TaxonomyRef,
					result.TriggeredRules,
					firstLine(tc.Description),
				)
			}
		})
	}
}

// newTestEngine creates a policy engine loaded with all packs for testing.
// This uses the regex-only fallback path (no analyzer pipeline).
func newTestEngine(t *testing.T) *policy.Engine {
	t.Helper()

	pol := loadTestPolicy(t)

	engine, err := policy.NewEngine(pol)
	if err != nil {
		t.Fatalf("failed to create policy engine: %v", err)
	}
	return engine
}

// newPipelineEngine creates a policy engine with the full analyzer pipeline
// (regex + structural + semantic + combiner).
func newPipelineEngine(t *testing.T) *policy.Engine {
	t.Helper()

	pol := loadTestPolicy(t)

	engine, err := policy.NewEngineWithAnalyzers(pol, 2)
	if err != nil {
		t.Fatalf("failed to create pipeline engine: %v", err)
	}
	return engine
}

func loadTestPolicy(t *testing.T) *policy.Policy {
	t.Helper()

	pol := policy.DefaultPolicy()

	// Load packs from the project root packs/ directory.
	// Test binary runs from internal/analyzer/, so we go up two levels.
	packsDir := "../../packs"
	pol, _, err := policy.LoadPacks(packsDir, pol)
	if err != nil {
		t.Logf("warning: could not load packs from %s: %v", packsDir, err)
	}
	return pol
}

// firstLine returns the first non-empty line of a multi-line string, trimmed.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			return trimmed
		}
	}
	return s
}

// ===========================================================================
// Kingdom 1: Destructive Operations
// ===========================================================================

func TestAccuracy_RecursiveRootDelete(t *testing.T) {
	runTestCases(t, testdata.RecursiveRootDeleteCases)
}

func TestAccuracy_SystemDirectoryDelete(t *testing.T) {
	runTestCases(t, testdata.SystemDirectoryDeleteCases)
}

func TestAccuracy_DiskOverwrite(t *testing.T) {
	runTestCases(t, testdata.DiskOverwriteCases)
}

func TestAccuracy_FilesystemFormat(t *testing.T) {
	runTestCases(t, testdata.FilesystemFormatCases)
}

func TestAccuracy_ForkBomb(t *testing.T) {
	runTestCases(t, testdata.ForkBombCases)
}

func TestAccuracy_ChmodWorldWritable(t *testing.T) {
	runTestCases(t, testdata.ChmodWorldWritableCases)
}

// ===========================================================================
// Kingdom 2: Credential & Secret Exposure
// ===========================================================================

func TestAccuracy_SSHPrivateKeyRead(t *testing.T) {
	runTestCases(t, testdata.SSHPrivateKeyReadCases)
}

func TestAccuracy_EnvDump(t *testing.T) {
	runTestCases(t, testdata.EnvDumpCases)
}

// ===========================================================================
// Kingdom 3: Data Exfiltration
// ===========================================================================

func TestAccuracy_ReverseShell(t *testing.T) {
	runTestCases(t, testdata.ReverseShellCases)
}

func TestAccuracy_DNSTunneling(t *testing.T) {
	runTestCases(t, testdata.DNSTunnelingCases)
}

// ===========================================================================
// Kingdom 4: Unauthorized Code Execution
// ===========================================================================

func TestAccuracy_PipeToShell(t *testing.T) {
	runTestCases(t, testdata.PipeToShellCases)
}

// ===========================================================================
// Kingdom 5: Privilege Escalation
// ===========================================================================

func TestAccuracy_SudoCommand(t *testing.T) {
	runTestCases(t, testdata.SudoCommandCases)
}

// ===========================================================================
// Kingdom 6: Persistence & Defense Evasion
// ===========================================================================

func TestAccuracy_CrontabModification(t *testing.T) {
	runTestCases(t, testdata.CrontabModificationCases)
}

// ===========================================================================
// Kingdom 7: Supply Chain Compromise
// ===========================================================================

func TestAccuracy_NonStandardRegistry(t *testing.T) {
	runTestCases(t, testdata.NonStandardRegistryCases)
}

func TestAccuracy_MCPToolSchemaDrift(t *testing.T) {
	runTestCases(t, testdata.MCPToolSchemaDriftCases)
}

// ===========================================================================
// Kingdom 8: Reconnaissance & Discovery
// ===========================================================================

func TestAccuracy_NetworkScanning(t *testing.T) {
	runTestCases(t, testdata.NetworkScanningCases)
}

func TestAccuracy_GHAuthToken(t *testing.T) {
	runTestCases(t, testdata.GHAuthTokenCases)
}

func TestAccuracy_GitHubActionsEnvInjection(t *testing.T) {
	runTestCases(t, testdata.GitHubActionsEnvInjectionCases)
}

// ===========================================================================
// Aggregate: All kingdoms
// ===========================================================================

func TestAccuracy_AllKingdoms(t *testing.T) {
	runTestCases(t, testdata.AllTestCases())
}

// ===========================================================================
// Pipeline Tests: Full analyzer pipeline (regex + structural + semantic)
// These run ALL test cases (including FP/FN) to measure what the pipeline fixes.
// ===========================================================================

// runPipelineTestCases evaluates all test cases through the full pipeline.
// Unlike runTestCases, this does NOT skip FP/FN — it tests whether the
// pipeline actually fixes them. Known FP/FN mismatches are logged (not failed)
// since they track Phase 3+ limitations.
func runPipelineTestCases(t *testing.T, cases []testdata.TestCase) {
	t.Helper()

	engine := newPipelineEngine(t)

	for _, tc := range cases {
		t.Run(tc.ID, func(t *testing.T) {
			// Skip premium-only test cases when premium packs are not loaded.
			for _, tag := range tc.Tags {
				if tag == "premium" {
					t.Skipf("PREMIUM — requires premium rule pack")
					return
				}
			}

			result := engine.Evaluate(tc.Command, nil)
			actual := string(result.Decision)

			if actual != tc.ExpectedDecision {
				msg := fmt.Sprintf(
					"[%s] %s\n"+
						"  Command:    %q\n"+
						"  Expected:   %s\n"+
						"  Got:        %s\n"+
						"  Taxonomy:   %s\n"+
						"  Triggered:  %v\n"+
						"  Reason:     %s",
					tc.Classification, tc.ID,
					tc.Command,
					tc.ExpectedDecision,
					actual,
					tc.TaxonomyRef,
					result.TriggeredRules,
					firstLine(tc.Description),
				)
				// Known FP/FN: log only (Phase 3+ work). TP/TN: fail.
				if tc.Classification == "FP" || tc.Classification == "FN" {
					t.Skipf("KNOWN LIMITATION (pipeline): %s", msg)
				} else {
					t.Errorf("%s", msg)
				}
			}
		})
	}
}

func TestPipeline_AllKingdoms(t *testing.T) {
	runPipelineTestCases(t, testdata.AllTestCases())
}

// TestAccuracyMetrics computes and prints TP/FP/FN/TN counts across all
// test cases. Run with: go test -v -run TestAccuracyMetrics
func TestAccuracyMetrics(t *testing.T) {
	allCases := testdata.AllTestCases()

	total := len(allCases)
	counts := map[string]int{"TP": 0, "TN": 0, "FP": 0, "FN": 0}
	byKingdom := map[string]map[string]int{}

	for _, tc := range allCases {
		counts[tc.Classification]++

		kingdom := extractKingdom(tc.TaxonomyRef)
		if byKingdom[kingdom] == nil {
			byKingdom[kingdom] = map[string]int{}
		}
		byKingdom[kingdom][tc.Classification]++
	}

	t.Logf("=== AgentShield Accuracy Metrics ===")
	t.Logf("Total test cases: %d", total)
	t.Logf("")
	t.Logf("  TP (True Positives):  %d", counts["TP"])
	t.Logf("  TN (True Negatives):  %d", counts["TN"])
	t.Logf("  FP (False Positives): %d  (known, awaiting fix)", counts["FP"])
	t.Logf("  FN (False Negatives): %d  (known, awaiting analyzer)", counts["FN"])
	t.Logf("")

	// Precision = TP / (TP + FP), Recall = TP / (TP + FN)
	tp := float64(counts["TP"])
	fp := float64(counts["FP"])
	fn := float64(counts["FN"])

	if tp+fp > 0 {
		t.Logf("  Precision: %.1f%%  (of flagged commands, how many are truly bad)",
			100*tp/(tp+fp))
	}
	if tp+fn > 0 {
		t.Logf("  Recall:    %.1f%%  (of bad commands, how many are caught)",
			100*tp/(tp+fn))
	}

	t.Logf("")
	t.Logf("=== Per-Kingdom Breakdown ===")
	for kingdom, kCounts := range byKingdom {
		t.Logf("  %-40s  TP:%d TN:%d FP:%d FN:%d",
			kingdom, kCounts["TP"], kCounts["TN"], kCounts["FP"], kCounts["FN"])
	}
}

// extractKingdom returns the kingdom portion of a taxonomy ref.
// E.g., "destructive-ops/fs-destruction/recursive-root-delete" → "destructive-ops"
func extractKingdom(ref string) string {
	parts := strings.SplitN(ref, "/", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ref
}

// TestCaseIDsAreUnique validates that no two test cases share the same ID.
func TestCaseIDsAreUnique(t *testing.T) {
	allCases := testdata.AllTestCases()
	seen := map[string]bool{}
	for _, tc := range allCases {
		if seen[tc.ID] {
			t.Errorf("duplicate test case ID: %s", tc.ID)
		}
		seen[tc.ID] = true
	}
	t.Logf("Verified %d test case IDs are unique", len(allCases))
}

// TestCaseClassificationsAreValid validates that all classifications are valid.
func TestCaseClassificationsAreValid(t *testing.T) {
	valid := map[string]bool{}
	for _, c := range testdata.AllClassifications {
		valid[c] = true
	}

	for _, tc := range testdata.AllTestCases() {
		if !valid[tc.Classification] {
			t.Errorf("[%s] invalid classification: %q", tc.ID, tc.Classification)
		}
	}
}

// TestCaseTaxonomyRefsArePresent validates that all test cases have taxonomy refs.
func TestCaseTaxonomyRefsArePresent(t *testing.T) {
	for _, tc := range testdata.AllTestCases() {
		if tc.TaxonomyRef == "" {
			t.Errorf("[%s] missing TaxonomyRef", tc.ID)
		}
		// Taxonomy refs should have at least two segments (kingdom/category/weakness)
		parts := strings.Split(tc.TaxonomyRef, "/")
		if len(parts) < 2 {
			t.Errorf("[%s] TaxonomyRef should have at least 2 segments: %q",
				tc.ID, tc.TaxonomyRef)
		}
	}
}

// TestCaseDescriptionsArePresent validates that all test cases have descriptions.
func TestCaseDescriptionsArePresent(t *testing.T) {
	for _, tc := range testdata.AllTestCases() {
		if strings.TrimSpace(tc.Description) == "" {
			t.Errorf("[%s] missing Description — every test case must explain WHY it exists",
				tc.ID)
		}
	}
}

// TestCaseSummary prints a formatted summary of all test cases grouped by kingdom.
func TestCaseSummary(t *testing.T) {
	allCases := testdata.AllTestCases()

	byKingdom := map[string][]testdata.TestCase{}
	for _, tc := range allCases {
		kingdom := extractKingdom(tc.TaxonomyRef)
		byKingdom[kingdom] = append(byKingdom[kingdom], tc)
	}

	t.Logf("=== Test Case Summary ===")
	t.Logf("Total: %d cases across %d kingdoms", len(allCases), len(byKingdom))
	t.Logf("")

	for kingdom, cases := range byKingdom {
		tp, tn, fp, fn := 0, 0, 0, 0
		for _, tc := range cases {
			switch tc.Classification {
			case "TP":
				tp++
			case "TN":
				tn++
			case "FP":
				fp++
			case "FN":
				fn++
			}
		}
		t.Logf("  %s: %d cases (TP:%d TN:%d FP:%d FN:%d)",
			kingdom, len(cases), tp, tn, fp, fn)
	}

	// Tag frequency
	tagCounts := map[string]int{}
	for _, tc := range allCases {
		for _, tag := range tc.Tags {
			tagCounts[tag]++
		}
	}
	t.Logf("")
	t.Logf("=== Tag Frequency ===")
	for tag, count := range tagCounts {
		t.Logf("  %-25s %d", tag, count)
	}
}

// TestPipelineAccuracyMetrics runs ALL test cases through the full pipeline
// and computes actual TP/FP/FN/TN by comparing pipeline decisions against
// expected decisions. This gives real accuracy numbers for the pipeline.
//
// Run with: go test -v -run TestPipelineAccuracyMetrics
func TestPipelineAccuracyMetrics(t *testing.T) {
	engine := newPipelineEngine(t)
	allCases := testdata.AllTestCases()

	total := len(allCases)
	tp, tn, fp, fn := 0, 0, 0, 0

	for _, tc := range allCases {
		result := engine.Evaluate(tc.Command, nil)
		actual := string(result.Decision)
		match := actual == tc.ExpectedDecision

		switch {
		case tc.ExpectedDecision == "BLOCK" && match:
			tp++
		case tc.ExpectedDecision == "BLOCK" && !match:
			fn++
		case tc.ExpectedDecision == "AUDIT" && match:
			tp++
		case tc.ExpectedDecision == "AUDIT" && !match:
			fn++
		case tc.ExpectedDecision == "ALLOW" && match:
			tn++
		case tc.ExpectedDecision == "ALLOW" && !match:
			fp++
		}
	}

	precision := float64(0)
	recall := float64(0)
	if tp+fp > 0 {
		precision = 100 * float64(tp) / float64(tp+fp)
	}
	if tp+fn > 0 {
		recall = 100 * float64(tp) / float64(tp+fn)
	}

	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════╗")
	t.Logf("║  AgentShield Pipeline Accuracy (regex+struct+sem)   ║")
	t.Logf("╠══════════════════════════════════════════════════════╣")
	t.Logf("║  Total test cases: %-33d║", total)
	t.Logf("║  TP (True Positives):  %-29d║", tp)
	t.Logf("║  TN (True Negatives):  %-29d║", tn)
	t.Logf("║  FP (False Positives): %-29d║", fp)
	t.Logf("║  FN (False Negatives): %-29d║", fn)
	t.Logf("║                                                      ║")
	t.Logf("║  Precision: %-7.1f%%                                  ║", precision)
	t.Logf("║  Recall:    %-7.1f%%                                  ║", recall)
	t.Logf("╚══════════════════════════════════════════════════════╝")
}

// TestGenerateFailingTestsReport runs all test cases through the pipeline engine
// and generates a markdown report of failing cases at FAILING_TESTS.md.
//
// Run with: go test -v -run TestGenerateFailingTestsReport
//
// The report groups failures by kingdom, assigns priority, and includes the
// analyzer needed to fix each case — making it easy to plan next improvements.
func TestGenerateFailingTestsReport(t *testing.T) {
	engine := newPipelineEngine(t)
	allCases := testdata.AllTestCases()

	type failure struct {
		tc       testdata.TestCase
		got      string
		rules    []string
		priority string
	}

	var failures []failure

	for _, tc := range allCases {
		result := engine.Evaluate(tc.Command, nil)
		actual := string(result.Decision)
		if actual != tc.ExpectedDecision {
			pri := "P2"
			for _, tag := range tc.Tags {
				if tag == "critical" {
					pri = "P0"
					break
				}
				if tag == "evasion" || tag == "regression" {
					pri = "P1"
				}
			}
			if tc.ExpectedDecision == "BLOCK" && actual == "ALLOW" {
				pri = "P0" // Worst case: should block but allows
			}
			failures = append(failures, failure{
				tc:       tc,
				got:      actual,
				rules:    result.TriggeredRules,
				priority: pri,
			})
		}
	}

	// Sort: P0 first, then P1, then P2
	sort.Slice(failures, func(i, j int) bool {
		if failures[i].priority != failures[j].priority {
			return failures[i].priority < failures[j].priority
		}
		return failures[i].tc.ID < failures[j].tc.ID
	})

	// Group by kingdom
	byKingdom := map[string][]failure{}
	kingdomOrder := []string{}
	for _, f := range failures {
		k := extractKingdom(f.tc.TaxonomyRef)
		if _, exists := byKingdom[k]; !exists {
			kingdomOrder = append(kingdomOrder, k)
		}
		byKingdom[k] = append(byKingdom[k], f)
	}
	sort.Strings(kingdomOrder)

	// Count by type
	fpCount, fnCount := 0, 0
	for _, f := range failures {
		if f.tc.Classification == "FP" {
			fpCount++
		} else {
			fnCount++
		}
	}

	// Build markdown
	var b strings.Builder
	b.WriteString("# AgentShield — Failing Test Cases\n\n")
	fmt.Fprintf(&b, "> Auto-generated by `TestGenerateFailingTestsReport` on %s\n",
		time.Now().Format("2006-01-02"))
	b.WriteString("> Run: `go test -v -run TestGenerateFailingTestsReport ./internal/analyzer/`\n\n")

	b.WriteString("## Summary\n\n")
	b.WriteString("| Metric | Count |\n")
	b.WriteString("|--------|-------|\n")
	fmt.Fprintf(&b, "| Total failing | %d |\n", len(failures))
	fmt.Fprintf(&b, "| False Negatives (missed threats) | %d |\n", fnCount)
	fmt.Fprintf(&b, "| False Positives (false alarms) | %d |\n", fpCount)
	fmt.Fprintf(&b, "| Total test cases | %d |\n", len(allCases))
	fmt.Fprintf(&b, "| Pass rate | %.1f%% |\n\n", 100*float64(len(allCases)-len(failures))/float64(len(allCases)))

	// Priority legend
	b.WriteString("## Priority Legend\n\n")
	b.WriteString("| Priority | Meaning |\n")
	b.WriteString("|----------|---------|\n")
	b.WriteString("| **P0** | Critical — should BLOCK but ALLOWs, or tagged `critical` |\n")
	b.WriteString("| **P1** | High — evasion technique or regression |\n")
	b.WriteString("| **P2** | Medium — known gap, future analyzer work |\n\n")

	// Analyzer grouping for planning
	byAnalyzer := map[string]int{}
	for _, f := range failures {
		a := f.tc.Analyzer
		if a == "" {
			a = "unspecified"
		}
		byAnalyzer[a]++
	}
	b.WriteString("## Failures by Required Analyzer\n\n")
	b.WriteString("| Analyzer Needed | Count | Notes |\n")
	b.WriteString("|-----------------|-------|-------|\n")
	analyzerNotes := map[string]string{
		"structural": "Shell AST parsing, flag normalization",
		"semantic":   "Command intent classification",
		"dataflow":   "Data flow through redirects/pipes",
		"stateful":   "Multi-step attack chain detection",
		"regex":      "Pattern matching improvements",
		"ai":         "LLM-based analysis",
	}
	analyzerKeys := make([]string, 0, len(byAnalyzer))
	for k := range byAnalyzer {
		analyzerKeys = append(analyzerKeys, k)
	}
	sort.Strings(analyzerKeys)
	for _, a := range analyzerKeys {
		note := analyzerNotes[a]
		if note == "" {
			note = "—"
		}
		fmt.Fprintf(&b, "| %s | %d | %s |\n", a, byAnalyzer[a], note)
	}
	b.WriteString("\n")

	// Detailed table per kingdom
	b.WriteString("## Failing Cases by Kingdom\n\n")
	for _, kingdom := range kingdomOrder {
		kFailures := byKingdom[kingdom]
		fmt.Fprintf(&b, "### %s (%d cases)\n\n", kingdom, len(kFailures))
		b.WriteString("| Priority | ID | Type | Command | Expected | Got | Analyzer | Description |\n")
		b.WriteString("|----------|----|------|---------|----------|-----|----------|-------------|\n")
		for _, f := range kFailures {
			cmd := f.tc.Command
			if len(cmd) > 60 {
				cmd = cmd[:57] + "..."
			}
			cmd = strings.ReplaceAll(cmd, "|", "\\|")
			desc := firstLine(f.tc.Description)
			if len(desc) > 80 {
				desc = desc[:77] + "..."
			}
			desc = strings.ReplaceAll(desc, "|", "\\|")
			analyzer := f.tc.Analyzer
			if analyzer == "" {
				analyzer = "—"
			}
			fmt.Fprintf(&b, "| **%s** | `%s` | %s | `%s` | %s | %s | %s | %s |\n",
				f.priority, f.tc.ID, f.tc.Classification,
				cmd, f.tc.ExpectedDecision, f.got,
				analyzer, desc)
		}
		b.WriteString("\n")
	}

	// Full detail section for reference
	b.WriteString("## Full Details\n\n")
	b.WriteString("Expand each case for the full description and triggered rules.\n\n")
	for _, f := range failures {
		fmt.Fprintf(&b, "<details>\n<summary><b>[%s] %s</b> — %s</summary>\n\n",
			f.priority, f.tc.ID, f.tc.Classification)
		fmt.Fprintf(&b, "- **Command**: `%s`\n", f.tc.Command)
		fmt.Fprintf(&b, "- **Expected**: %s\n", f.tc.ExpectedDecision)
		fmt.Fprintf(&b, "- **Got**: %s\n", f.got)
		fmt.Fprintf(&b, "- **Taxonomy**: %s\n", f.tc.TaxonomyRef)
		fmt.Fprintf(&b, "- **Analyzer needed**: %s\n", f.tc.Analyzer)
		if len(f.rules) > 0 {
			fmt.Fprintf(&b, "- **Triggered rules**: %s\n", strings.Join(f.rules, ", "))
		}
		fmt.Fprintf(&b, "- **Tags**: %s\n", strings.Join(f.tc.Tags, ", "))
		fmt.Fprintf(&b, "- **Description**: %s\n",
			strings.TrimSpace(f.tc.Description))
		b.WriteString("\n</details>\n\n")
	}

	// Write file
	outPath := "../../FAILING_TESTS.md"
	if err := os.WriteFile(outPath, []byte(b.String()), 0644); err != nil {
		t.Fatalf("failed to write FAILING_TESTS.md: %v", err)
	}
	t.Logf("Generated %s with %d failing cases", outPath, len(failures))
}

// formatTestSummary generates a text summary for a slice of test cases.
//
//lint:ignore U1000 used for debugging test results
func formatTestSummary(cases []testdata.TestCase) string {
	tp, tn, fp, fn := 0, 0, 0, 0
	for _, tc := range cases {
		switch tc.Classification {
		case "TP":
			tp++
		case "TN":
			tn++
		case "FP":
			fp++
		case "FN":
			fn++
		}
	}
	return fmt.Sprintf("%d cases (TP:%d TN:%d FP:%d FN:%d)", len(cases), tp, tn, fp, fn)
}
