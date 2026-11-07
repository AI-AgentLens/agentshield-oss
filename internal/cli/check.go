package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/assembly"
	"github.com/AI-AgentLens/agentshield/internal/config"
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
	checkShellFile  string
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
  agentshield check --fixture ./packs/destructive_ops.test.yaml

  # A case can name the rule it tests: "fires: co-block-prod-db" passes only
  # when that rule triggers, "silent: co-block-prod-db" only when it does not.
  # Use these for custom rules: built-in packs still apply, so a decision
  # alone can pass without your rule ever firing. A pack's protected_paths
  # are tested as the built-in rule: "fires: protected-path".

  # Diagnose a command the IDE hook just blocked. --shell puts the command in
  # argv, where the hook sees it and blocks the diagnosis too (#3302); reading
  # it from a file keeps the flagged text out of argv entirely.
  agentshield check --shell-file ./blocked.txt`,
	RunE: checkRun,
}

func init() {
	checkCmd.Flags().StringVar(&checkShell, "shell", "", "Shell command string to evaluate (NOT executed)")
	checkCmd.Flags().StringVar(&checkShellFile, "shell-file", "", "File containing the shell command to evaluate (NOT executed); keeps the command text out of argv so the IDE hook cannot block the diagnosis itself")
	checkCmd.Flags().StringVar(&checkPolicyPath, "policy", "", "Policy YAML to use instead of ~/.agentshield/policy.yaml (also skips deployed ~/.agentshield/packs, so the named file is not shadowed)")
	checkCmd.Flags().StringVar(&checkFixture, "fixture", "", "Fixture YAML file containing test cases")
	checkCmd.Flags().StringVar(&checkFormat, "format", "text", "Output format: text or json (with --shell or --shell-file)")
	rootCmd.AddCommand(checkCmd)
}

func checkRun(cmd *cobra.Command, args []string) error {
	// Flags parsed; a policy that will not load is not a usage error (#4739).
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true // main prints the returned error
	if err := resolveShellFile(); err != nil {
		return err
	}
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

// resolveShellFile folds --shell-file into checkShell so the rest of the
// command sees exactly one input path.
//
// It exists because `--shell` cannot diagnose the blocks that most need
// diagnosing (#3302). The hook evaluates the whole outer command string, so
// `agentshield check --shell "<blocked>"` carries the flagged text in argv and
// gets blocked in turn — the "to see why this triggered" hint was the one
// command you could not run. A file keeps the text out of argv.
//
// Only the trailing newline is stripped, and only one: editors add it, and
// nothing about a shell command changes when it is removed. Leading and
// interior whitespace is preserved verbatim, because `command_position_exclude`
// and the per-statement anchored-regex retry both key on where text sits in the
// command — silently trimming would make this path a less faithful predictor of
// the hook than --shell, which would defeat the point of having it.
func resolveShellFile() error {
	if checkShellFile == "" {
		return nil
	}
	if checkShell != "" {
		return fmt.Errorf("--shell and --shell-file are mutually exclusive")
	}
	if checkFixture != "" {
		return fmt.Errorf("--shell-file and --fixture are mutually exclusive")
	}
	data, err := os.ReadFile(checkShellFile)
	if err != nil {
		return fmt.Errorf("reading --shell-file %s: %w", checkShellFile, err)
	}
	cmdStr := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if strings.TrimSpace(cmdStr) == "" {
		return fmt.Errorf("--shell-file %s contains no command", checkShellFile)
	}
	checkShell = cmdStr
	return nil
}

// evaluateShellCommand loads the policy and evaluates a single command. Pure
// computation — no os.Exit, no stdout — so tests can call it directly.
// checkEngine is a loaded policy engine that `check` evaluates commands
// against. Building one costs a config load, a policy + pack load and an
// engine construction — about 150 ms, the same as a whole hook call — while
// one evaluation on a built engine costs a few milliseconds. The engine holds
// no per-evaluation state (the stateful analyzer runs compound-only here, as in
// the hook), so fixture mode builds one engine and reuses it: a fixture of N
// cases used to pay the load N times (400 real-traffic cases took 93 s in the
// #3995 replay), which is what made replaying an audit log too slow to gate a
// deploy on. TestRunFixtureFile_ReusedEngineMatchesFreshEngine pins the reuse
// against a fresh build per command.
type checkEngine struct {
	engine *policy.Engine
	// probe answers a fixture case's fires/silent. It loads the named policy
	// file with every one of its rules raised to BLOCK, so a stricter rule
	// elsewhere (an embedded pack, a built-in analyzer) cannot drop a match
	// from the triggered rules: the combiner keeps only the winning decision's
	// rules. A rule's decision does not change what it matches. Nil when no
	// policy file was named.
	probe *policy.Engine
	// probeIDs holds the named policy file's rule ids. A fires or silent
	// naming any other id is an error: silent on a misspelled id would pass
	// forever, testing nothing.
	probeIDs map[string]bool
	mode     string
}

func evaluateShellCommand(command, policyFileOverride string) (policy.EvalResult, error) {
	ce, err := newCheckEngine(policyFileOverride)
	if err != nil {
		return policy.EvalResult{}, err
	}
	return ce.evaluate(command), nil
}

func newCheckEngine(policyFileOverride string) (*checkEngine, error) {
	pol, _, err := loadCheckPolicy(policyFileOverride)
	if err != nil {
		return nil, err
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

	checkMode := ""
	if cfg != nil {
		checkMode = cfg.Mode
	}
	// assembly.ShellEngine is what the hook uses, so `agentshield check` is a
	// faithful predictor of production behaviour, including the CI-context
	// tightening (#3291) when run inside a CI job or with CI=true set.
	engine, err := assembly.ShellEngine(pol, defaultMaxParseDepth(), checkMode)
	if err != nil {
		return nil, fmt.Errorf("failed to create policy engine: %w", err)
	}
	return &checkEngine{engine: engine, mode: checkMode}, nil
}

// protectedPathRuleID is the rule id a protected_paths match reports.
const protectedPathRuleID = "protected-path"

// addProbe builds the probe engine from the named policy file. Fixture mode
// calls it only when a case uses fires or silent.
func (ce *checkEngine) addProbe(policyFile string) error {
	pol, err := policy.Load(policyFile)
	if err != nil {
		return fmt.Errorf("failed to load policy from %s: %w", policyFile, err)
	}
	ce.probeIDs = make(map[string]bool, len(pol.Rules)+1)
	for i := range pol.Rules {
		pol.Rules[i].Decision = policy.DecisionBlock
		ce.probeIDs[pol.Rules[i].ID] = true
	}
	// A pack's defaults.protected_paths fire as the built-in "protected-path"
	// rule, so a test of a protected path names that id.
	ce.probeIDs[protectedPathRuleID] = true
	pol, _, _ = policy.LoadEmbeddedShellPacks(pol)
	ce.probe, err = assembly.ShellEngine(pol, defaultMaxParseDepth(), ce.mode)
	if err != nil {
		return fmt.Errorf("failed to create probe engine: %w", err)
	}
	return nil
}

// evaluate runs one command through the loaded engine.
func (ce *checkEngine) evaluate(command string) policy.EvalResult {
	return evaluateWith(ce.engine, command)
}

// namedRules returns the rules a fires/silent case is judged on: the probe's
// when a policy file was named, else the engine's.
func (ce *checkEngine) namedRules(command string, full policy.EvalResult) []string {
	if ce.probe == nil {
		return full.TriggeredRules
	}
	return evaluateWith(ce.probe, command).TriggeredRules
}

func evaluateWith(engine *policy.Engine, command string) policy.EvalResult {
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
	//
	// Use the process cwd, matching the hook (#4020). This used to pass ""
	// deliberately: giving check a cwd resolves relative paths to absolute
	// before protected_paths matching, which used to drop every relative
	// protected_paths match. That gap is now closed in the engine itself
	// (checkProtectedPaths also matches a path under cwd, made cwd-relative,
	// against a relative pattern), so check and the hook agree either way —
	// see TestEvaluateShellCommand_CwdParity.
	//
	// A command past the chain bound, or a text a reading derived from it, is
	// decided as the hook decides it, without parsing (#4778, chain_bound.go).
	cwd, _ := os.Getwd()
	r, chain := readPOSIXText(engine, command, cwd)
	if chain != nil {
		return pastChainBoundResult(chain, nil)
	}
	return r
}

func printShellResult(w io.Writer, r policy.EvalResult) {
	_, _ = fmt.Fprintf(w, "%s\n", r.Decision)
	if r.OriginalDecision != "" {
		// Audit-only mode (#1952), the default for new installs (#4337):
		// without this line a would-be block reads as a plain AUDIT.
		_, _ = fmt.Fprintf(w, "  Enforce mode: %s (this machine runs in audit-only mode)\n", r.OriginalDecision)
	}
	if len(r.TriggeredRules) > 0 {
		_, _ = fmt.Fprintf(w, "  Rules: %s\n", strings.Join(r.TriggeredRules, ", "))
	}
	for _, reason := range r.Reasons {
		_, _ = fmt.Fprintf(w, "  Reason: %s\n", reason)
	}
	for _, n := range r.Notes {
		_, _ = fmt.Fprintf(w, "  Note: %s%s%s\n", n.Kind, optField(" rule=", n.Rule), optField(" ", n.Detail))
	}
	if len(r.TriggeredRules) > 0 && len(r.TaxonomyRefs) == 0 {
		_, _ = fmt.Fprintln(w, "  Note: no rule here names a taxonomy node, so this decision's record maps to no compliance control. If it's your rule, add `taxonomy:`.")
	}
}

func optField(prefix, v string) string {
	if v == "" {
		return ""
	}
	return prefix + v
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
		return nil, basePath, unreadablePolicyError(basePath, err)
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
	// Fires and Silent name the rule a case is about. Embedded packs still
	// apply under --policy, so an expected decision can be met by a built-in
	// rule while the rule under test never fires; naming the rule closes that
	// gap. When either is set, Expect is optional.
	Fires  string `yaml:"fires,omitempty"`
	Silent string `yaml:"silent,omitempty"`
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
	expect  policy.Decision // empty when the case only names a rule
	actual  policy.Decision
	pass    bool
	err     error // parse/eval-time error
	rules   []string
	reasons []string
	fires   string
	silent  string
	named   []string // rules that matched, for fires/silent (see checkEngine.probe)
}

// failures lists why a case failed, in the order expect, fires, silent.
func (r fixtureCaseResult) failures() []string {
	var why []string
	if r.expect != "" && r.actual != r.expect {
		why = append(why, fmt.Sprintf("expected %s, got %s", r.expect, r.actual))
	}
	if r.fires != "" && !slices.Contains(r.named, r.fires) {
		why = append(why, fmt.Sprintf("expected rule %s to fire", r.fires))
	}
	if r.silent != "" && slices.Contains(r.named, r.silent) {
		why = append(why, fmt.Sprintf("expected rule %s to stay silent", r.silent))
	}
	return why
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

	// One engine for the whole fixture (see checkEngine). A build failure is
	// recorded on every case, exactly as the per-case build used to report it,
	// so the report shape and the exit code are unchanged.
	ce, engineErr := newCheckEngine(policyPathToUse)
	if engineErr == nil && policyPathToUse != "" && slices.ContainsFunc(fix.Cases, func(c fixtureCase) bool {
		return c.Fires != "" || c.Silent != ""
	}) {
		engineErr = ce.addProbe(policyPathToUse)
	}

	for i, c := range fix.Cases {
		line := 0
		if i < len(caseLines) {
			line = caseLines[i]
		}
		var expectedDecision policy.Decision
		if c.Expect != "" || (c.Fires == "" && c.Silent == "") {
			d, parseErr := parseExpectedDecision(c.Expect)
			if parseErr != nil {
				report.results = append(report.results, fixtureCaseResult{
					name: c.Name, line: line, err: parseErr,
				})
				report.failed++
				continue
			}
			expectedDecision = d
		}
		if engineErr == nil && ce.probeIDs != nil {
			var unknown string
			for _, id := range []string{c.Fires, c.Silent} {
				if id != "" && !ce.probeIDs[id] {
					unknown = id
				}
			}
			if unknown != "" {
				report.results = append(report.results, fixtureCaseResult{
					name: c.Name, line: line,
					err: fmt.Errorf("rule %q is not in %s", unknown, policyPathToUse),
				})
				report.failed++
				continue
			}
		}

		if engineErr != nil {
			report.results = append(report.results, fixtureCaseResult{
				name: c.Name, line: line, expect: expectedDecision, err: engineErr,
			})
			report.failed++
			continue
		}
		evalResult := ce.evaluate(c.Shell)

		res := fixtureCaseResult{
			name:    c.Name,
			line:    line,
			expect:  expectedDecision,
			actual:  evalResult.Decision,
			rules:   evalResult.TriggeredRules,
			reasons: evalResult.Reasons,
			fires:   c.Fires,
			silent:  c.Silent,
		}
		if c.Fires != "" || c.Silent != "" {
			res.named = ce.namedRules(c.Shell, evalResult)
		}
		res.pass = len(res.failures()) == 0
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
			_, _ = fmt.Fprintf(w, "%s:%d: FAIL %s — %s\n",
				r.path, res.line, res.name, strings.Join(res.failures(), "; "))
			if len(res.rules) > 0 {
				_, _ = fmt.Fprintf(w, "        rules: %s\n", strings.Join(res.rules, ", "))
			}
		}
	}

	_, _ = fmt.Fprintf(w, "\n%d passed, %d failed\n", r.passed, r.failed)
}
