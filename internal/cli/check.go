package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/normalize"
	"github.com/AI-AgentLens/agentshield/internal/policy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// agentshield check evaluates a shell command (or a fixture file of cases)
// against the policy engine WITHOUT executing anything. It is the developer
// loop for rule writers — fast feedback, no Go test boilerplate, and a
// fixture format that doubles as the integration-test artifact for custom
// rules.
//
// Why a new command instead of reviving `run`: the deleted-but-still-checked-in
// `run` command actually executed shell commands. We deliberately keep this
// surface evaluation-only — no os/exec from this file or any helper it calls.

var (
	checkShell      string
	checkPolicyPath string
	checkFixture    string
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Evaluate a shell command or fixture against the policy (no execution)",
	Long: `Evaluate a shell command or a fixture file of cases against the policy.

The command is parsed and analyzed but NEVER executed. Use this to test
rules during development without round-tripping through Go tests.

Examples:
  # Evaluate one shell command against deployed policy
  agentshield check --shell "rm -rf /"

  # Evaluate against a custom rule file
  agentshield check --shell "psql prod.db" --policy ./my-rule.yaml

  # Run a fixture of TP/TN cases (for CI and local iteration)
  agentshield check --fixture ./packs/destructive_ops.test.yaml`,
	RunE: checkRun,
}

func init() {
	checkCmd.Flags().StringVar(&checkShell, "shell", "", "Shell command string to evaluate (NOT executed)")
	checkCmd.Flags().StringVar(&checkPolicyPath, "policy", "", "Policy YAML to use instead of ~/.agentshield/policy.yaml")
	checkCmd.Flags().StringVar(&checkFixture, "fixture", "", "Fixture YAML file containing test cases")
	rootCmd.AddCommand(checkCmd)
}

func checkRun(cmd *cobra.Command, args []string) error {
	switch {
	case checkShell != "" && checkFixture != "":
		return fmt.Errorf("--shell and --fixture are mutually exclusive")
	case checkShell != "":
		result, err := evaluateShellCommand(checkShell, checkPolicyPath)
		if err != nil {
			return err
		}
		printShellResult(cmd.OutOrStdout(), result)
		if result.Decision == policy.DecisionBlock {
			os.Exit(2)
		}
		return nil
	case checkFixture != "":
		report, err := runFixtureFile(checkFixture, checkPolicyPath)
		if err != nil {
			return err
		}
		printFixtureReport(cmd.OutOrStdout(), report)
		if report.failed > 0 {
			os.Exit(1)
		}
		return nil
	default:
		return fmt.Errorf("must provide --shell or --fixture")
	}
}

// evaluateShellCommand loads the policy and evaluates a single command. Pure
// computation — no os.Exit, no stdout — so tests can call it directly.
func evaluateShellCommand(command, policyFileOverride string) (policy.EvalResult, error) {
	pol, _, err := loadCheckPolicy(policyFileOverride)
	if err != nil {
		return policy.EvalResult{}, err
	}

	engine, err := policy.NewEngineWithAnalyzers(pol, defaultMaxParseDepth())
	if err != nil {
		return policy.EvalResult{}, fmt.Errorf("failed to create policy engine: %w", err)
	}

	// Treat the whole flag value as one shell command string. The normalizer
	// handles the join + path extraction.
	normalized := normalize.Normalize([]string{command}, "")
	return engine.Evaluate(command, normalized.Paths), nil
}

func printShellResult(w io.Writer, r policy.EvalResult) {
	_, _ = fmt.Fprintf(w, "%s\n", r.Decision)
	if len(r.TriggeredRules) > 0 {
		_, _ = fmt.Fprintf(w, "  Rules: %s\n", strings.Join(r.TriggeredRules, ", "))
	}
	for _, reason := range r.Reasons {
		_, _ = fmt.Fprintf(w, "  Reason: %s\n", reason)
	}
}

// loadCheckPolicy returns the merged policy used for `check`. It mirrors the
// runtime hook's loading order so check results match what users would see
// from the IDE hook:
//
//   1. Base policy: --policy override OR ~/.agentshield/policy.yaml.
//   2. Embedded community shell packs (always available).
//   3. Disk packs from ~/.agentshield/packs (premium, user custom) — best-effort.
//
// Returns the merged policy and the resolved base policy path (for diagnostics).
func loadCheckPolicy(policyFileOverride string) (*policy.Policy, string, error) {
	cfg, cfgErr := config.Load(policyPath, logPath, mode)
	basePath := policyFileOverride
	if basePath == "" {
		if cfg == nil {
			return nil, "", fmt.Errorf("failed to load config: %w", cfgErr)
		}
		basePath = cfg.PolicyPath
	} else {
		// Explicit --policy: a missing file is a UX bug, not a fall-back. The
		// stdlib loader returns DefaultPolicy() on os.IsNotExist (sensible at
		// the runtime hook site, where the user may not have created
		// ~/.agentshield/policy.yaml yet). Here, the user named the file
		// themselves, so honor the intent and surface the typo.
		if _, err := os.Stat(basePath); err != nil {
			return nil, basePath, fmt.Errorf("policy file %s not found: %w", basePath, err)
		}
	}

	pol, err := policy.Load(basePath)
	if err != nil {
		return nil, basePath, fmt.Errorf("failed to load policy from %s: %w", basePath, err)
	}

	pol, _, _ = policy.LoadEmbeddedShellPacks(pol)

	if cfg != nil {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		if merged, _, err := policy.LoadPacks(packsDir, pol); err == nil && merged != nil {
			pol = merged
		}
	}

	return pol, basePath, nil
}

func defaultMaxParseDepth() int {
	if cfg, _ := config.Load(policyPath, logPath, mode); cfg != nil {
		return cfg.Analyzer.MaxParseDepth
	}
	return 2
}

// --- Fixture support -------------------------------------------------------

// fixtureFile is the on-disk format. Designed to layer on top of (not replace)
// the existing Go testdata: a rule writer can colocate `<rule>.test.yaml`
// next to a `<rule>.yaml` and iterate without touching Go.
type fixtureFile struct {
	// Optional override of the policy file. Resolved relative to the fixture
	// file's directory, so a rule and its tests can ship as a self-contained
	// pair.
	Policy string        `yaml:"policy,omitempty"`
	Cases  []fixtureCase `yaml:"cases"`
}

type fixtureCase struct {
	Name   string `yaml:"name"`
	Shell  string `yaml:"shell"`
	Expect string `yaml:"expect"`
}

type fixtureReport struct {
	path    string
	results []fixtureCaseResult
	passed  int
	failed  int
}

type fixtureCaseResult struct {
	name     string
	line     int
	expect   policy.Decision
	actual   policy.Decision
	pass     bool
	err      error // parse/eval-time error
	rules    []string
	reasons  []string
}

func runFixtureFile(fixturePath, policyFileOverride string) (fixtureReport, error) {
	report := fixtureReport{path: fixturePath}

	data, err := os.ReadFile(fixturePath)
	if err != nil {
		return report, fmt.Errorf("read fixture %s: %w", fixturePath, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return report, fmt.Errorf("parse fixture %s: %w", fixturePath, err)
	}

	var fix fixtureFile
	if err := root.Decode(&fix); err != nil {
		return report, fmt.Errorf("decode fixture %s: %w", fixturePath, err)
	}

	// Walk the YAML node tree to recover line numbers for each case so failure
	// messages can be reported as "path:line: FAIL ..." for VS Code's
	// problemMatcher to pick up. yaml.v3 preserves source positions on Nodes.
	caseLines := extractCaseLines(&root)

	// Resolve --policy precedence: CLI override > fixture's policy field.
	policyPathToUse := policyFileOverride
	if policyPathToUse == "" && fix.Policy != "" {
		policyPathToUse = fix.Policy
		if !filepath.IsAbs(policyPathToUse) {
			policyPathToUse = filepath.Join(filepath.Dir(fixturePath), policyPathToUse)
		}
	}

	for i, c := range fix.Cases {
		line := 0
		if i < len(caseLines) {
			line = caseLines[i]
		}
		expectedDecision, parseErr := parseExpectedDecision(c.Expect)
		if parseErr != nil {
			report.results = append(report.results, fixtureCaseResult{
				name: c.Name, line: line, err: parseErr,
			})
			report.failed++
			continue
		}

		evalResult, err := evaluateShellCommand(c.Shell, policyPathToUse)
		if err != nil {
			report.results = append(report.results, fixtureCaseResult{
				name: c.Name, line: line, expect: expectedDecision, err: err,
			})
			report.failed++
			continue
		}

		res := fixtureCaseResult{
			name:    c.Name,
			line:    line,
			expect:  expectedDecision,
			actual:  evalResult.Decision,
			pass:    evalResult.Decision == expectedDecision,
			rules:   evalResult.TriggeredRules,
			reasons: evalResult.Reasons,
		}
		if res.pass {
			report.passed++
		} else {
			report.failed++
		}
		report.results = append(report.results, res)
	}

	return report, nil
}

// extractCaseLines walks the parsed YAML to find the source line of each entry
// under `cases:`. Returns lines in document order, aligned with fixtureFile.Cases.
func extractCaseLines(root *yaml.Node) []int {
	var lines []int
	if root == nil || len(root.Content) == 0 {
		return lines
	}
	doc := root.Content[0] // root.Kind=DocumentNode, single child = mapping
	if doc.Kind != yaml.MappingNode {
		return lines
	}
	for i := 0; i < len(doc.Content); i += 2 {
		key := doc.Content[i]
		if key.Value != "cases" {
			continue
		}
		seq := doc.Content[i+1]
		if seq.Kind != yaml.SequenceNode {
			return lines
		}
		for _, item := range seq.Content {
			lines = append(lines, item.Line)
		}
		return lines
	}
	return lines
}

func parseExpectedDecision(s string) (policy.Decision, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "BLOCK":
		return policy.DecisionBlock, nil
	case "AUDIT":
		return policy.DecisionAudit, nil
	case "ALLOW":
		return policy.DecisionAllow, nil
	default:
		return "", fmt.Errorf("invalid expect %q (must be BLOCK, AUDIT, or ALLOW)", s)
	}
}

func printFixtureReport(w io.Writer, r fixtureReport) {
	total := r.passed + r.failed
	_, _ = fmt.Fprintf(w, "%s: %d cases\n", r.path, total)

	for _, res := range r.results {
		switch {
		case res.err != nil:
			// Errors are always failures — print in the path:line: form too.
			_, _ = fmt.Fprintf(w, "%s:%d: FAIL %s — %v\n", r.path, res.line, res.name, res.err)
		case res.pass:
			_, _ = fmt.Fprintf(w, "  PASS  %s (%s)\n", res.name, res.actual)
		default:
			_, _ = fmt.Fprintf(w, "%s:%d: FAIL %s — expected %s, got %s\n",
				r.path, res.line, res.name, res.expect, res.actual)
			if len(res.rules) > 0 {
				_, _ = fmt.Fprintf(w, "        rules: %s\n", strings.Join(res.rules, ", "))
			}
		}
	}

	_, _ = fmt.Fprintf(w, "\n%d passed, %d failed\n", r.passed, r.failed)
}
