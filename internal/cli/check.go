package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/config"
	"github.com/AI-AgentLens/agentshield/internal/execenv"
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
	checkFormat     string
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

  # Evaluate against a custom rule file. --policy also skips the deployed
  # packs in ~/.agentshield/packs, so a stale installed copy of a rule
  # cannot shadow the file you named (#3030). Embedded packs still apply.
  agentshield check --shell "psql prod.db" --policy ./my-rule.yaml

  # Run a fixture of TP/TN cases (for CI and local iteration)
  agentshield check --fixture ./packs/destructive_ops.test.yaml`,
	RunE: checkRun,
}

func init() {
	checkCmd.Flags().StringVar(&checkShell, "shell", "", "Shell command string to evaluate (NOT executed)")
	checkCmd.Flags().StringVar(&checkPolicyPath, "policy", "", "Policy YAML to use instead of ~/.agentshield/policy.yaml (also skips deployed ~/.agentshield/packs, so the named file is not shadowed)")
	checkCmd.Flags().StringVar(&checkFixture, "fixture", "", "Fixture YAML file containing test cases")
	checkCmd.Flags().StringVar(&checkFormat, "format", "text", "Output format: text or json (only with --shell)")
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
		switch strings.ToLower(checkFormat) {
		case "json":
			if err := printShellResultJSON(cmd.OutOrStdout(), result); err != nil {
				return err
			}
		case "", "text":
			printShellResult(cmd.OutOrStdout(), result)
		default:
			return fmt.Errorf("invalid --format %q (must be text or json)", checkFormat)
		}
		if len(checkFailedPacks) > 0 {
			os.Exit(3) // degraded ruleset — distinct from 1 (fixture failures) and 2 (BLOCK)
		}
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
		if len(checkFailedPacks) > 0 {
			os.Exit(3) // degraded ruleset — every result is suspect, not just the failures
		}
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

	// Resolve enforcement mode the same way hook.go does so `check` is a
	// faithful predictor of production behavior under audit-only mode
	// (issue #1952). Without this, a developer testing their policy with
	// `check` sees BLOCK on a rule that audit-only would actually downgrade
	// to AUDIT — exactly the wrong direction for a dev-loop tool. The CLI
	// flag (--mode) and ~/.agentshield/agentshield.yaml win as usual; if
	// neither is set, the SaaS-pushed policy.yaml's enforcement_mode field
	// (resolution rung 3) flows through here.
	cfg, _ := config.Load(policyPath, logPath, mode)

	engine, err := policy.NewEngineWithAnalyzers(pol, defaultMaxParseDepth())
	if err != nil {
		return policy.EvalResult{}, fmt.Errorf("failed to create policy engine: %w", err)
	}
	if cfg != nil {
		engine.SetMode(cfg.Mode)
	}
	// Issue #3291: mirror the hook's CI-context detection so `agentshield check`
	// is a faithful predictor of production behaviour — running it inside a CI
	// job (or with CI=true/GITHUB_ACTIONS=true set) exercises the same
	// context-scoped tightening the live hook would apply there.
	engine.SetExecContext(execenv.Detect(os.Getenv))

	// Mirror the IDE hook's evaluation path exactly so `check` is a faithful
	// dev-loop predictor of production behavior:
	//   1. Use NormalizeCommand, which tokenizes internally (strings.Fields) so
	//      the path-extraction state machine sees real argv tokens, not one
	//      mega-arg, but parses the AST from the original `command` string —
	//      not a whitespace-collapsed reconstruction (issue #2831).
	//   2. Pass the parsed AST into EvaluateWithParsed so the structural and
	//      downstream analyzers operate on the same input the hook provides.
	// See hook.go's evaluateCommand — keep these two call sites in lock-step.
	// The parity test in check_test.go (TestEvaluateShellCommand_HookParityFitnessFunction)
	// enforces the invariant.
	normalized := normalize.NormalizeCommand(command, "")
	return engine.EvaluateWithParsed(command, normalized.Paths, normalized.Parsed), nil
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

func printShellResultJSON(w io.Writer, r policy.EvalResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// loadCheckPolicy returns the merged policy used for `check`. It mirrors the
// runtime hook's loading order so check results match what users would see
// from the IDE hook:
//
//  1. Base policy: --policy override OR ~/.agentshield/policy.yaml.
//  2. Embedded community shell packs (always available).
//  3. Disk packs from ~/.agentshield/packs (premium, user custom) — best-effort,
//     and ONLY when no explicit --policy was given (#3030). Naming a file means
//     "evaluate against this", so machine-local deployed packs must not shadow it.
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

	pol, embeddedInfos, _ := policy.LoadEmbeddedShellPacks(pol)

	// Issue #3030: when the user names a policy file explicitly, do NOT merge the
	// machine-local deployed packs over it. Previously this merge was
	// unconditional, so ~/.agentshield/packs shadowed both the --policy file and
	// the binary's embedded packs: a rule author would fix a regex, rebuild, run
	// `check --policy ./packs/community/terminal-safety.yaml`, and watch the OLD
	// behaviour persist with no indication that a different copy of the same rule
	// supplied the verdict. This box carried FOUR copies of terminal-safety.yaml
	// under ~/.agentshield/, which is why it was so easy to trip over.
	//
	// Same reasoning as the explicit-path branch above: the user named the file,
	// so honour the intent. Deployed packs are machine-local state that varies per
	// install; skipping them makes `check --policy` reproducible across machines.
	//
	// Embedded packs are deliberately still merged — they ship inside the binary
	// under test, so they are deterministic and are the baseline coverage a rule
	// author actually wants their rule evaluated against.
	var diskInfos []policy.PackInfo
	if cfg != nil && policyFileOverride == "" {
		packsDir := filepath.Join(cfg.ConfigDir, "packs")
		if merged, infos, err := policy.LoadPacks(packsDir, pol); err == nil && merged != nil {
			pol = merged
			diskInfos = infos
		}
	}

	// Issue #2188 recorded LoadError so every surface could warn; the hook and
	// scan do, but check discarded the PackInfo slices — so a pack that failed
	// to parse silently dropped ALL of its rules and every command degraded to
	// the default AUDIT with no signal at all. That is the worst place to be
	// quiet: check is the rule-development tool, so the author's whole mental
	// model of "did my rule fire?" is formed here. A single `: ` in an unquoted
	// YAML scalar drops the entire pack, and the only visible symptom is
	// unrelated cases mysteriously returning AUDIT (#3035).
	noteFailedPacks(append(policy.FailedPacks(embeddedInfos), policy.FailedPacks(diskInfos)...))

	return pol, basePath, nil
}

var (
	// checkFailedPacks records packs that failed to parse during this process.
	// A --fixture run re-resolves the policy once per case, so the warning is
	// emitted once (warnOnce) rather than repeated for every case, while the
	// count stays available for the exit code.
	checkFailedPacks []policy.PackInfo
	checkWarnOnce    sync.Once
)

func noteFailedPacks(failed []policy.PackInfo) {
	if len(failed) == 0 {
		return
	}
	checkWarnOnce.Do(func() {
		checkFailedPacks = failed
		warnFailedPacks(os.Stderr, failed)
	})
}

// warnFailedPacks prints a loud, actionable warning for each pack that failed to
// parse. Mirrors the hook and scan surfaces so all three agree.
func warnFailedPacks(w io.Writer, failed []policy.PackInfo) {
	for _, fp := range failed {
		_, _ = fmt.Fprintf(w, "[AgentShield] CRITICAL: pack %q failed to parse — its rules are NOT loaded, enforcement degraded: %v\n", fp.Path, fp.LoadError)
	}
	_, _ = fmt.Fprintf(w, "[AgentShield] %d pack(s) failed to load — results below are evaluated against a DEGRADED ruleset and are NOT trustworthy.\n", len(failed))
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
	name    string
	line    int
	expect  policy.Decision
	actual  policy.Decision
	pass    bool
	err     error // parse/eval-time error
	rules   []string
	reasons []string
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
