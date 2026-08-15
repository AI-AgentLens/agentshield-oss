package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/execenv"
	"github.com/AI-AgentLens/agentshield/internal/regexlit"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	unicheck "github.com/AI-AgentLens/agentshield/internal/unicode"
)

type Engine struct {
	policy   *Policy
	homeDir  string
	registry *analyzer.Registry // optional: when set, uses full analyzer pipeline
	// regexCache holds required-literal-prefiltered matchers (internal/regexlit),
	// not bare regexps — the fallback path scans the whole rule corpus per
	// command just as the analyzer pipeline does.
	regexCache       map[string]*regexlit.Matcher
	intentClassifier *analyzer.IntentClassifier // honored by matchRule's regex-fallback path
	// mode controls whether interrupting decisions (BLOCK / REQUIRE_APPROVAL)
	// actually fire or get downgraded to AUDIT. Empty or "enforce" preserves
	// the historical behavior. "audit-only" downgrades — see issue #1952.
	// Set via SetMode; never read directly outside applyModeDowngrade.
	mode string
	// execContext is the runtime execution environment (CI/CD-ness) used to
	// gate context-scoped rules (issue #3291). Zero-value (CI:false) is the
	// trusted-developer baseline, under which no CI-only rule fires. Set via
	// SetExecContext by the hook/check CLI from execenv.Detect; left zero by
	// the accuracy suite so its verdicts are deterministic regardless of
	// whether the tests themselves happen to run inside CI.
	execContext execenv.Context
}

func NewEngine(p *Policy) (*Engine, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	e := &Engine{
		policy:           p,
		homeDir:          homeDir,
		regexCache:       make(map[string]*regexlit.Matcher),
		intentClassifier: analyzer.NewIntentClassifier(),
	}
	// Pre-compile all rule regexes at initialization
	for _, rule := range p.Rules {
		for _, pat := range [...]string{rule.Match.CommandRegex, rule.Match.CommandRegexExclude} {
			if pat == "" {
				continue
			}
			if m, err := regexlit.Compile(pat); err == nil {
				e.regexCache[pat] = m
			}
		}
	}
	return e, nil
}

// SetRegistry attaches an analyzer pipeline to the engine.
// When set, Evaluate() uses the full pipeline (regex+structural+semantic+combiner)
// instead of the built-in regex-only matching.
func (e *Engine) SetRegistry(r *analyzer.Registry) {
	e.registry = r
}

// SetMode configures the enforcement mode. Recognized values:
//   - ""          — same as "enforce" (default; no downgrade)
//   - "enforce"   — BLOCK / REQUIRE_APPROVAL fire as authored
//   - "audit-only" — BLOCK / REQUIRE_APPROVAL get downgraded to AUDIT, with the
//     pre-downgrade decision recorded on EvalResult.OriginalDecision
//
// Unrecognized values are treated as "enforce" — fail-safe. The caller (config
// layer) is expected to validate and warn; this is the last line of defense.
// Introduced for issue #1952 to let a pilot deployment observe telemetry
// without interrupting users.
func (e *Engine) SetMode(mode string) {
	e.mode = mode
}

// SetExecContext configures the runtime execution environment used to gate
// context-scoped rules (issue #3291). The hook and `agentshield check` call
// this with execenv.Detect(os.Getenv) so that CI-context rules tighten posture
// when — and only when — the process is running inside a CI/CD runner. Left
// unset (zero-value), the engine applies the trusted-developer baseline and no
// `match.context.ci: true` rule fires. Read at evaluation time by both the
// analyzer-pipeline path (via ctx.ExecContext) and the regex-fallback path, so
// it takes effect without rebuilding the engine.
func (e *Engine) SetExecContext(ec execenv.Context) {
	e.execContext = ec
}

// applyModeDowngrade collapses interrupting decisions to AUDIT when the
// engine is in audit-only mode. Returns the (possibly modified) result.
// Pure function over the result + mode — easy to unit-test, no engine state
// mutation. The original decision is captured on OriginalDecision so the
// audit emitter can reconstruct the "would have happened" event.
//
// Why audit-only matters for issue #1952: a 6-user rollout needs to ship rules
// in shadow mode for a week, watch the dashboard, then flip enforce on. If we
// downgraded silently (no OriginalDecision), the dashboard would just see a
// flood of AUDIT events and the team couldn't tell which would've actually
// interrupted users.
func applyModeDowngrade(result EvalResult, mode string) EvalResult {
	if mode != "audit-only" {
		return result
	}
	switch result.Decision {
	case DecisionBlock, DecisionRequireApproval:
		result.OriginalDecision = result.Decision
		result.Decision = DecisionAudit
	}
	// ALLOW, AUDIT, and any unknown decision (e.g. an internal ERROR) pass
	// through unchanged — we only downgrade what the spec names.
	return result
}

// Policy returns the engine's policy (for inspection/testing).
func (e *Engine) Policy() *Policy {
	return e.policy
}

func (e *Engine) Evaluate(command string, paths []string) EvalResult {
	return e.EvaluateWithParsed(command, paths, nil)
}

// EvaluateWithParsed is like Evaluate but accepts a pre-parsed command AST
// from the normalizer, avoiding redundant parsing in the structural analyzer.
func (e *Engine) EvaluateWithParsed(command string, paths []string, parsed *analyzer.ParsedCommand) EvalResult {
	return e.EvaluateWithParsedCwd(command, paths, parsed, "")
}

// EvaluateWithParsedCwd is EvaluateWithParsed plus the working directory, so
// analyzers that resolve relative filesystem paths (e.g. the artifact-hash
// verifier) can locate the on-disk file. Callers without a cwd (scan/check)
// use EvaluateWithParsed, which passes "" — those analyzers then no-op.
func (e *Engine) EvaluateWithParsedCwd(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string) EvalResult {
	// Every return path goes through finish() so the issue #1952 mode
	// downgrade and the explanation-building are applied uniformly. Doing
	// this inside the function (rather than at each return site) is what
	// makes the protected-path early-exit and the registry/fallback branches
	// audit-only-safe without duplicating logic.
	result := EvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
		TaxonomyRefs:   []string{},
	}
	finish := func(r EvalResult) EvalResult {
		r = applyModeDowngrade(r, e.mode)
		r.Explanation = buildExplanation(r)
		return r
	}

	// Built-in: Unicode smuggling detection (runs before all rules)
	uniScan := unicheck.Scan(command)
	if !uniScan.Clean {
		hasBlockLevel := false
		for _, threat := range uniScan.Threats {
			result.TriggeredRules = append(result.TriggeredRules, "unicode-"+threat.Category)
			result.Reasons = append(result.Reasons, threat.Description)
			if threat.Severity == "block" {
				hasBlockLevel = true
			}
		}
		if hasBlockLevel {
			result.Decision = DecisionBlock
		} else {
			result.Decision = DecisionAudit
		}
		return finish(result)
	}

	if blocked, rule := e.checkProtectedPaths(paths); blocked {
		result.Decision = DecisionBlock
		result.TriggeredRules = append(result.TriggeredRules, "protected-path")
		result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied: %s", rule))
		return finish(result)
	}

	// If an analyzer registry is set, use the full pipeline.
	// Otherwise, fall back to built-in regex-only matching.
	if e.registry != nil {
		ctx := &analyzer.AnalysisContext{
			RawCommand:  command,
			Paths:       paths,
			Parsed:      parsed,
			Cwd:         cwd,
			ExecContext: e.execContext,
		}
		combined := e.registry.RunAll(ctx, string(e.policy.Defaults.Decision))
		result.Decision = Decision(combined.Decision)
		result.TriggeredRules = combined.TriggeredRules
		result.Reasons = combined.Reasons
		// Issue #3111: carry the taxonomy refs of the winning findings out to
		// the audit event. The protected-path post-pass below can add a rule
		// with no taxonomy — that's fine, it just contributes no ref.
		result.TaxonomyRefs = combined.TaxonomyRefs

		// Layer 2.5 post-pass: re-run protected-path matching against any
		// paths the substitution analyzer reconstructed from `Name=value`
		// assignments. The early check at the top of this method only sees
		// paths the normalizer extracted from raw argv tokens; split-concat
		// bypasses (P1=~/.ssh; P2=id_rsa; cat $P1/$P2) only become concrete
		// after the AST walk. We override to BLOCK on a hit because
		// protected paths are non-negotiable — combiner severity doesn't
		// apply when the policy explicitly named the path off-limits.
		if blocked, rule := e.checkProtectedPaths(ctx.MaterializedPaths); blocked {
			result.Decision = DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "protected-path-via-substitution")
			result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied (resolved via variable substitution): %s", rule))
		}

		return finish(result)
	}

	// Fallback: built-in regex-only matching (backward compatible).
	// Evaluate ALL matching rules and pick the highest severity.
	var bestDecision Decision
	var bestRules []string
	var bestReasons []string
	var bestTaxonomy []string
	matched := false

	// dequotedCommand mirrors RegexAnalyzer's fix for issue #2854: a
	// quote-spliced token (`~/.ss'h'/id_r'sa'`) resolves to the real,
	// unmodified path at runtime but evades a rule matching the raw
	// pre-quote-removal text. "" (the no-op sentinel) when there's nothing
	// to strip or parsing failed, in which case only command is checked.
	dequotedCommand := shellparse.DequoteCommand(command)

	// foldedCommand is the same idea for unset-parameter expansion: an unset
	// variable expands to nothing, so `r${zqx}m -rf /` runs `rm -rf /` while
	// no raw-text rule matches. This is the regex-only fallback path (the
	// pipeline path gets it via shellparse.Parse and RegexAnalyzer), so it
	// needs its own candidate or disabling the pipeline reopens the bypass.
	foldedCommand := shellparse.NormalizeUnsetParamExp(command)

	// materializedCommand folds constant `Name=value` assignments into their
	// read sites — "P1=/root/.ssh; P2=id_rsa; cat $P1/$P2" reads exactly the
	// file sec-block-ssh-private blocks, but the literal never appears in raw
	// text (issue #3249). Same reasoning as foldedCommand just above: this is
	// the regex-only fallback path, so it needs its own candidate or disabling
	// the pipeline reopens the bypass.
	materializedCommand := shellparse.MaterializeAssignments(command)

	for _, rule := range e.policy.Rules {
		if e.policy.IsRuleDisabled(rule.ID) {
			continue
		}
		// CI-context gate (issue #3291), mirroring RegexAnalyzer.Analyze on the
		// pipeline path: a rule carrying match.context only applies when the
		// runtime execution context matches. Checked before any matching so a
		// gated-out rule costs nothing.
		if !ruleContextActive(rule, e.execContext) {
			continue
		}
		matchedCmd := ""
		switch {
		case e.matchRule(command, rule):
			matchedCmd = command
		case dequotedCommand != "" && e.matchRule(dequotedCommand, rule):
			matchedCmd = dequotedCommand
		case foldedCommand != "" && e.matchRule(foldedCommand, rule):
			matchedCmd = foldedCommand
		case materializedCommand != "" && e.matchRule(materializedCommand, rule):
			matchedCmd = materializedCommand
		}
		if matchedCmd == "" {
			continue
		}
		// Context-aware downgrade (#2843), mirroring RegexAnalyzer.Analyze on
		// the pipeline path: a BLOCK/REQUIRE_APPROVAL match that fires only
		// inside doc-text/heredoc statements (a sensitive literal in a gh/git
		// --body/--message argument, a heredoc body) is documenting a pattern,
		// not executing an access — downgrade to AUDIT so it stays LOGGED
		// (attested) rather than being silently suppressed by exclude. Computed
		// on the command that actually matched so the per-statement scoping is
		// non-vacuous (a chained real access keeps its BLOCK).
		dec := rule.Decision
		reason := rule.Reason
		if eff := e.effectiveDecision(matchedCmd, rule); eff != rule.Decision {
			dec = eff
			reason = reason + " [downgraded BLOCK→AUDIT: the sensitive pattern appears inside a documentation/message argument (gh/git --body/--message), not an executed access]"
		}
		if !matched || decisionSeverity(dec) > decisionSeverity(bestDecision) {
			bestDecision = dec
			bestRules = []string{rule.ID}
			bestReasons = []string{reason}
			bestTaxonomy = nil
			if rule.Taxonomy != "" {
				bestTaxonomy = append(bestTaxonomy, rule.Taxonomy)
			}
			matched = true
		} else if decisionSeverity(dec) == decisionSeverity(bestDecision) {
			bestRules = append(bestRules, rule.ID)
			bestReasons = append(bestReasons, reason)
			if rule.Taxonomy != "" {
				bestTaxonomy = append(bestTaxonomy, rule.Taxonomy)
			}
		}
	}

	if matched {
		result.Decision = bestDecision
		result.TriggeredRules = bestRules
		result.Reasons = bestReasons
		result.TaxonomyRefs = analyzer.NormalizeTaxonomyRefs(bestTaxonomy)
	}

	return finish(result)
}

// decisionSeverity returns a numeric severity for priority comparison.
// Higher number = more restrictive decision. REQUIRE_APPROVAL sits between
// AUDIT and BLOCK — louder than a silent audit, gentler than an outright
// block. See issue #1952 for why REQUIRE_APPROVAL exists at all in this
// codebase (it's the second decision audit-only mode downgrades).
func decisionSeverity(d Decision) int {
	switch d {
	case DecisionBlock:
		return 4
	case DecisionRequireApproval:
		return 3
	case DecisionAudit:
		return 2
	case DecisionAllow:
		return 1
	default:
		return 0
	}
}

// ruleContextActive reports whether a rule's CI-context gate (issue #3291) is
// satisfied by the engine's execution context. A rule with no `match.context`
// (or no `ci:` field) is unconditionally active. A `ci: true` rule is active
// only inside CI; a `ci: false` rule only outside CI. This is the single
// definition of the gate for the regex-fallback path; the analyzer-pipeline
// path applies the equivalent test inside RegexAnalyzer via RegexRule.RequireCI.
func ruleContextActive(rule Rule, ec execenv.Context) bool {
	if rule.Match.Context == nil || rule.Match.Context.CI == nil {
		return true
	}
	return *rule.Match.Context.CI == ec.CI
}

// matchCommandPrefix reports whether rule's command_prefix list fires on
// command. The semantics — including the ALLOW-side narrowing from #3199 and
// why output redirects are out of scope — live on shellparse.PrefixRuleMatches,
// which is the single implementation shared with the analyzer's regex path.
func matchCommandPrefix(command string, rule Rule) bool {
	return shellparse.PrefixRuleMatches(command, rule.Match.CommandPrefix, rule.Decision == DecisionAllow)
}

// regexExcluded reports whether command_regex_exclude suppresses this match.
//
// Split out because the exclude used to be applied ONLY inside the
// command_regex branch, so a rule combining command_prefix (or command_exact)
// with command_regex_exclude had an exclude that parsed, validated, and did
// nothing — on this path AND in analyzer.RegexAnalyzer (#3232). No shipped rule
// had that combination, which is exactly why it survived: the field was a
// latent trap, not a live bug, and the first rule to reach for it would have
// silently got no exclusion at all.
func (e *Engine) regexExcluded(command, excl string) bool {
	if excl == "" {
		return false
	}
	re := e.compiledRegex(excl)
	return re != nil && re.MatchString(command)
}

// matchRule reports whether rule fires on command: its raw pattern (exact,
// prefix, or regex + command_regex_exclude, via matchRulePattern) must match,
// AND the match must not be suppressed by command_intent_exclude.
func (e *Engine) matchRule(command string, rule Rule) bool {
	if !e.matchRulePattern(command, rule) {
		return false
	}
	return !e.intentExcluded(command, rule)
}

// intentExcluded reports whether command_intent_exclude suppresses a match
// matchRulePattern already confirmed, mirroring regexExcluded's role for
// command_regex_exclude (#3232) — split out for the identical reason: the
// check used to live ONLY inside matchRule's command_regex branch, so a rule
// combining command_prefix or command_exact with command_intent_exclude had
// an exclude that parsed, passed load-time label validation, and did nothing
// on this path (#3234, sibling of #3232). No shipped rule used that
// combination, which is exactly why it survived: a latent trap, not a live
// bug, and the first rule to reach for it would silently have got no
// exclusion at all.
//
// Scoped per top-level shell statement (see
// analyzer.IntentExcludedForStatements) so a chained, unrelated dangerous
// statement can't be excused by an adjacent doc-text/heredoc/self-mgmt-shaped
// one. The per-statement re-test reuses matchRulePattern — the same "raw
// pattern, any match kind" predicate effectiveDecision's #2843 downgrade
// already uses this way — so exact/prefix/regex are all covered uniformly,
// mirroring how the analyzer pipeline's RegexAnalyzer.Analyze wraps
// matchRegexRule in IntentExcludedForStatements regardless of which match
// kind fired. Computed lazily — only rules opting into
// command_intent_exclude pay the classification/parse cost.
func (e *Engine) intentExcluded(command string, rule Rule) bool {
	if len(rule.Match.CommandIntentExclude) == 0 || e.intentClassifier == nil {
		return false
	}
	statements := shellparse.SplitTopLevelStatements(command)
	return analyzer.IntentExcludedForStatements(e.intentClassifier, command, statements, rule.Match.CommandIntentExclude, func(stmt string) bool {
		return e.matchRulePattern(stmt, rule)
	})
}

// matchRulePattern reports whether the rule's raw match predicate (exact,
// prefix, or regex + command_regex_exclude) fires on command, WITHOUT applying
// command_intent_exclude. effectiveDecision uses this as the per-statement
// predicate for the #2843 downgrade so the downgrade's statement scoping
// mirrors the pipeline's (analyzer.RegexAnalyzer.matchRegexRule is likewise
// exclude-free) rather than being confounded by the rule's own exclude labels.
func (e *Engine) matchRulePattern(command string, rule Rule) bool {
	if rule.Match.CommandExact != "" && command == rule.Match.CommandExact {
		return !e.regexExcluded(command, rule.Match.CommandRegexExclude)
	}
	if matchCommandPrefix(command, rule) {
		return !e.regexExcluded(command, rule.Match.CommandRegexExclude)
	}
	if rule.Match.CommandRegex != "" {
		re := e.compiledRegex(rule.Match.CommandRegex)
		if re != nil && re.MatchString(command) {
			if excl := rule.Match.CommandRegexExclude; excl != "" {
				if reExcl := e.compiledRegex(excl); reExcl != nil && reExcl.MatchString(command) {
					return false
				}
			}
			return true
		}
	}
	return false
}

// effectiveDecision returns rule.Decision, downgraded BLOCK/REQUIRE_APPROVAL→
// AUDIT when the rule opts into command_intent_downgrade (#2843) and every
// statement that makes the rule fire sits in a downgrade-labeled position (a
// sensitive literal inside a gh/git --body/--message argument, a heredoc body).
// This is the regex-fallback twin of RegexAnalyzer.Analyze's downgrade, so the
// accuracy corpus and inline-YAML tests (which run this path) reach the same
// verdict the live pipeline does. Per-statement scoping (via
// IntentExcludedForStatements) keeps a chained real access at BLOCK: only the
// downgrade labels move a decision, never a genuine executed access.
func (e *Engine) effectiveDecision(command string, rule Rule) Decision {
	if len(rule.Match.CommandIntentDowngrade) == 0 || e.intentClassifier == nil {
		return rule.Decision
	}
	if rule.Decision != DecisionBlock && rule.Decision != DecisionRequireApproval {
		return rule.Decision
	}
	statements := shellparse.SplitTopLevelStatements(command)
	if analyzer.IntentExcludedForStatements(e.intentClassifier, command, statements, rule.Match.CommandIntentDowngrade, func(stmt string) bool {
		return e.matchRulePattern(stmt, rule)
	}) {
		return DecisionAudit
	}
	return rule.Decision
}

// compiledRegex returns a pre-compiled regex from cache, or compiles on demand.
func (e *Engine) compiledRegex(pattern string) *regexlit.Matcher {
	if m, ok := e.regexCache[pattern]; ok {
		return m
	}
	m, err := regexlit.Compile(pattern)
	if err != nil {
		return nil
	}
	e.regexCache[pattern] = m
	return m
}

func (e *Engine) checkProtectedPaths(paths []string) (bool, string) {
	for _, path := range paths {
		expandedPath := e.expandPath(path)
		for _, pattern := range e.policy.Defaults.ProtectedPaths {
			expandedPattern := e.expandPath(pattern)
			if matchGlob(expandedPath, expandedPattern) {
				return true, pattern
			}
		}
	}
	return false, ""
}

func (e *Engine) expandPath(path string) string {
	if strings.HasPrefix(path, "~/") && e.homeDir != "" {
		return filepath.Join(e.homeDir, path[2:])
	}
	if strings.HasPrefix(path, "~") && e.homeDir != "" {
		return e.homeDir
	}
	return path
}

func matchGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		remainder := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(remainder, "/")
	}

	matched, _ := filepath.Match(pattern, path)
	return matched
}

func buildExplanation(result EvalResult) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Decision: %s\n", result.Decision)

	if len(result.TriggeredRules) > 0 {
		fmt.Fprintf(&sb, "Triggered rules: %s\n", strings.Join(result.TriggeredRules, ", "))
	}

	if len(result.Reasons) > 0 {
		sb.WriteString("Reasons:\n")
		for _, reason := range result.Reasons {
			fmt.Fprintf(&sb, "  - %s\n", reason)
		}
	}

	return sb.String()
}
