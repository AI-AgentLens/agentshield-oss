package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
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
//
// It is the single evaluation entry point: the hook (cli/hook.go), `check`,
// `scan` and shield-server all arrive here, which is why #3991's safety
// guarantee lives here — see EvaluateProgramPaths.
func (e *Engine) EvaluateWithParsedCwd(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string) EvalResult {
	return e.EvaluateProgramPaths(command, paths, parsed, cwd, ProgramPathsStricter)
}

// ProgramPathMode selects how an evaluation treats a command word spelled as a
// path (#3991): `/usr/bin/rm`, `"/usr/bin/tar"`, `~root/bin/tar`, `| /usr/bin/nc`.
type ProgramPathMode int

const (
	// ProgramPathsStricter is production: evaluate as written (OFF) and, for a
	// command with a path-spelled command word, again reading those words as
	// the programs they run (ON); keep ON only when STRICTLY more restrictive.
	ProgramPathsStricter ProgramPathMode = iota
	// ProgramPathsOff evaluates as written only — byte-for-byte pre-#3991.
	ProgramPathsOff
	// ProgramPathsOn is the ON evaluation alone. Diagnostics and tests only:
	// on its own it carries no guarantee of being at least as strict as OFF.
	ProgramPathsOn
)

// EvaluateProgramPaths is EvaluateWithParsedCwd with the #3991 mode explicit.
// Production uses ProgramPathsStricter through EvaluateWithParsedCwd; the other
// modes exist so the relaxation sweep can compare OFF, ON and the result.
//
// # The guarantee, and where it comes from
//
// A path-spelled command word defeated every rule keyed on a program name —
// `/usr/bin/rm -rf /` went BLOCK -> AUDIT. Reading such words as their
// programs closes that, but reading them anywhere a match RELAXES the verdict
// (an ALLOW rule, an exemption, a downgrade, an ALLOW's position exclusion, an
// AUDIT finding that displaces a stricter default) opens new fail-opens, and
// the combiner is not monotone in findings, so no per-consumer classification
// can prove "never less restrictive than before". Codex found three relaxations
// in pass 1 and three more in pass 2, each from a different consumer.
//
// So the guarantee is structural. OFF is exactly the pre-#3991 evaluation. ON
// runs only when the command has a path-spelled command word, and its result
// replaces OFF's only when strictly more restrictive under stricterResult's
// local total order. The returned decision is therefore never below OFF's,
// whatever any analyzer does with the program name. The restrict-only opt-in
// in the analyzers (AnalysisContext.ResolveProgramPaths) is PRECISION: it keeps
// ON from inventing ALLOWs and needless FPs. It is not what makes this safe,
// and safety does not depend on its consumer table being complete.
//
// What the record carries: when OFF is returned (almost always), exactly the
// pre-#3991 decision, rules, reasons and taxonomy refs. When ON is returned, ON's
// — the rules that fired once the program name was read, which is the evidence
// for the stricter verdict. The two are never merged.
func (e *Engine) EvaluateProgramPaths(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, mode ProgramPathMode) EvalResult {
	switch mode {
	case ProgramPathsOff:
		return e.evaluate(command, paths, parsed, cwd, false)
	case ProgramPathsOn:
		return e.evaluate(command, paths, parsed, cwd, true)
	}
	off := e.evaluate(command, paths, parsed, cwd, false)
	// The regex-only fallback (no registry) reads no program names, so ON
	// would equal OFF; do not pay for it twice.
	if e.registry == nil || !mayHaveProgramPaths(command, parsed) {
		return off
	}
	on := e.evaluate(command, paths, parsed, cwd, true)
	return stricterResult(off, on)
}

// stricterResult returns on when its decision is STRICTLY more restrictive than
// off's, and off otherwise — ties, and anything outside the order, keep off.
// This is the max() #3991's safety rests on (see EvaluateProgramPaths).
//
// The order is local and total — ALLOW < AUDIT < REQUIRE_APPROVAL < BLOCK — and
// deliberately NOT the combiner's decisionToSeverity, which has no
// REQUIRE_APPROVAL case and ranks it below ALLOW (#3298). Using that here would
// let an ON result at AUDIT replace an OFF REQUIRE_APPROVAL.
//
// Both results have already been through applyModeDowngrade, so under
// audit-only a BLOCK arrives as AUDIT with OriginalDecision=BLOCK. Ranking on
// Decision there ties OFF's plain AUDIT with ON's downgraded BLOCK, keeps OFF,
// and drops the "would have blocked" record the shadow-rollout view reads
// (#4021). So rank on the pre-downgrade decision. applyModeDowngrade is the
// only writer of OriginalDecision, so enforce mode ranks exactly as before; and
// because the downgrade is monotone, the returned Decision still never falls
// below OFF's.
func stricterResult(off, on EvalResult) EvalResult {
	rank := func(d Decision) int {
		switch d {
		case DecisionAllow:
			return 0
		case DecisionAudit:
			return 1
		case DecisionRequireApproval:
			return 2
		case DecisionBlock:
			return 3
		}
		return -1
	}
	preDowngrade := func(r EvalResult) Decision {
		if r.OriginalDecision != "" {
			return r.OriginalDecision
		}
		return r.Decision
	}
	ro, rn := rank(preDowngrade(off)), rank(preDowngrade(on))
	if ro < 0 || rn <= ro {
		return off
	}
	return on
}

// mayHaveProgramPaths is the cheap test for "is there a path-spelled command
// word for ON to read" — at the top level or in a pipeline stage, in any parsed
// segment at any depth (carriers, resolved indirect executables, quoted words),
// on any line, or inside executed text (piped/heredoc/substitution bodies).
// A miss only means ON is not run for that command: the result is OFF, i.e.
// the pre-#3991 behaviour — a coverage gap, never a relaxation.
//
// Ordered cheapest first, because it runs on EVERY command: a lexical scan,
// then a walk of the tree the caller already parsed (the hook always passes
// one), and only when a path starts right after a quote, `(`, backquote or
// `=`, or sits anywhere on a later line — the only places a command word
// inside a carrier, heredoc, substitution or indirect assignment can begin —
// the line split (each line peeled of the prefixes that do not change which
// program runs, #4032), the executed-text extraction and, without a caller's
// tree, a parse.
func mayHaveProgramPaths(command string, parsed *analyzer.ParsedCommand) bool {
	if !strings.ContainsAny(command, "/~") {
		return false
	}
	if shellparse.BasenameCommandWord(command) != "" {
		return true
	}
	if parsed != nil && shellparse.ProgramView(parsed) != nil {
		return true
	}
	// xargs's own target (#4014, #3992) is a command word no statement starts
	// with — `… | xargs /usr/bin/tar --to-command=sh`, or a carrier as the
	// target (`xargs sh -c '/usr/bin/tar …'`). Every peel that can expose a
	// command word must be mirrored here, or ON is skipped for it; the
	// relaxation sweep's pre-check-miss assertion catches the next one.
	if strings.Contains(command, "xargs") {
		for _, t := range shellparse.XargsPipeSinkTargets(command) {
			if shellparse.BasenameCommandWord(t) != "" {
				return true
			}
			for _, frag := range shellparse.InlineCodeFragments(t) {
				if shellparse.BasenameCommandWord(frag) != "" {
					return true
				}
			}
		}
	}
	if !embeddedPathWordRe.MatchString(command) {
		// A path that is not right after a quote can still be a command word
		// behind a wrapper prefix INSIDE a quoted body that runs
		// (`echo 'sudo -n /usr/bin/rm …' | bash`, #4046). Admitting every
		// quoted path would parse `git commit -m "fix /foo"`, so the executed
		// text is extracted only when the command has a carrier shape at all.
		if !strings.ContainsAny(command, "|<>$`") || !anyPathWordRe.MatchString(command) {
			return false
		}
		return executedBodyHasPathCommandWord(command)
	}
	for _, line := range strings.Split(command, "\n") {
		if pathCommandWordBehindPrefixes(line) {
			return true
		}
	}
	if executedBodyHasPathCommandWord(command) {
		return true
	}
	if parsed == nil {
		return shellparse.ProgramView(shellparse.Parse(command, 2)) != nil
	}
	return false
}

// embeddedPathWordRe matches an absolute or home-anchored path in either of
// two positions, and its language is a strict SUPERSET of every earlier
// version's — a gate that admits less than main did is a regression, however
// the rest of the gate improves (Codex pass 1 on #4032 found exactly that).
//
//  1. Right after a quote, newline, `(`, backquote or `=`, with an optional
//     bare `sudo ` (#4021 item 2) — where a command word nested in a carrier
//     body, substitution or indirect assignment begins. The `sudo` alternative
//     stays because it is what admits `echo 'sudo /usr/bin/rm …' | bash`: the
//     quoted body is not a line, so the per-line peel below never sees it, and
//     dropping the alternative turned that command from BLOCK into AUDIT.
//  2. Anywhere on a line after the first, because a later line's command word
//     can sit behind prefixes that do not change which program runs
//     (`sudo -n /usr/bin/rm`, `X=1 env /usr/bin/rm`, `echo a; nohup
//     /usr/bin/rm`; #4032). Which prefixes those are is not this regex's
//     call: it only admits the line, and pathCommandWordBehindPrefixes decides
//     with the analyzers' own peels. Listing them here would have left the
//     next spelling, as listing `sudo` alone did.
var embeddedPathWordRe = regexp.MustCompile("(?:[\n'\"(`=]\\s*(?:sudo\\s+)?|\n[^\n]*\\s)(/|~[A-Za-z0-9._-]*/)[^\\s/]")

// anyPathWordRe admits a path-spelled word anywhere after whitespace, a quote,
// `(`, backquote or `=`. It is only the cheap gate for the executed-text scan
// (#4046); pathCommandWordBehindPrefixes decides.
var anyPathWordRe = regexp.MustCompile("[\\s'\"(`=](/|~[A-Za-z0-9._-]*/)[^\\s/]")

// executedBodyHasPathCommandWord reports whether any text the command will RUN
// without being a top-level statement (piped/heredoc/substitution bodies)
// has a path-spelled command word, behind the same prefixes the analyzers peel.
func executedBodyHasPathCommandWord(command string) bool {
	for _, body := range shellparse.ExecutedText(command) {
		if pathCommandWordBehindPrefixes(body) {
			return true
		}
	}
	return false
}

// pathCommandWordBehindPrefixes reports whether text has a command word spelled
// as an absolute or home-anchored path, looking behind the prefixes that do not
// change which program runs — leading assignments and `!`, and exec wrappers
// with their options (`sudo -n`, `sudo --`, `nice -n 1`, `X=1 sudo`) — in each
// sequenced statement and pipeline stage of the text.
//
// The peels are the ones the analyzers' restrict candidates already run
// (StatementMatchCandidates: StripCommandPrefixes, StripExecWrapperPrefix),
// not a prefix list of this file's, so this gate cannot admit a wrapper ON
// does not read, or miss one it does: a wrapper is added in one place,
// shellparse.ExecWrappers. Before #4032 the gate ran BasenameCommandWord
// alone, which peels only a bare `sudo`, and a later heredoc line such as
// `sudo -n /usr/bin/rm -rf /var/log` — BLOCK on its own — fell to the policy
// default because ON was never run for it.
//
// Lexical first, then the parses, and only for text that carries a path at
// all: this runs once per line of a multi-line command that the cheaper
// checks above have already declined.
//
// Pinned honestly (Opus pass on #4032): for the heredoc class the regex
// widening is the fix, not this peel. normalize skips the parse when a heredoc
// is present, so the caller's tree is nil and the ProgramView(Parse) fallback
// at the end of mayHaveProgramPaths sees through the wrappers on its own; a
// mutant without the StripExecWrapperPrefix call still BLOCKs every wrapper
// heredoc probe. The peel is what keeps the gate honest when a caller DOES
// pass a tree, and that path is currently unpinned by a test.
func pathCommandWordBehindPrefixes(text string) bool {
	if !strings.ContainsAny(text, "/~") {
		return false
	}
	if shellparse.BasenameCommandWord(text) != "" {
		return true
	}
	for _, stmt := range shellparse.SplitTopLevelStatements(text) {
		if s := shellparse.StripCommandPrefixes(stmt); s != "" && shellparse.BasenameCommandWord(s) != "" {
			return true
		}
		if s := shellparse.StripExecWrapperPrefix(stmt); s != "" && shellparse.BasenameCommandWord(s) != "" {
			return true
		}
	}
	return false
}

// evaluate is one evaluation, with #3991's program-name reading on (resolve)
// or off. Off, it is byte-for-byte the pre-#3991 EvaluateWithParsedCwd.
func (e *Engine) evaluate(command string, paths []string, parsed *analyzer.ParsedCommand, cwd string, resolve bool) EvalResult {
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
	// A protected path used only by its designated consumer (ssh -i, kubectl
	// --kubeconfig, …) is recorded, not blocked — see consumers.go. Decided
	// lazily on the first protected-path hit; finish() folds the record into
	// whatever verdict the rest of evaluation reaches.
	consumerNote := ""
	consumerOnly := func() bool {
		if consumerNote != "" {
			return true
		}
		ok, exe := e.protectedPathConsumerOnly(command, parsed)
		if ok {
			consumerNote = fmt.Sprintf("Protected credential path used by its designated consumer (%s) — recorded, not blocked", exe)
		}
		return ok
	}
	// envConsumerNote is the assignment half of the same idea (#3630) and is
	// kept in a SEPARATE variable on purpose: consumerOnly() suppresses a
	// BLOCK, and an assignment must never be able to do that. `ssh -i key
	// host` laundering a `cat` was the bug #3670 fixed on the mount side; an
	// `export KUBECONFIG=…` laundering one would be the same shape.
	envConsumerNote := ""
	// uniDecision/uniRules/uniReasons carry the Unicode smuggling finding
	// (populated below, before finish() is ever called) so finish() can fold
	// it in most-restrictive-wins — see #4007. Declared here, ahead of the
	// closure that reads them, because a Go closure cannot forward-reference
	// a variable declared later in the same function body.
	var uniDecision Decision
	var uniRules, uniReasons []string
	finish := func(r EvalResult) EvalResult {
		// Fold the Unicode smuggling finding in most-restrictive-wins, the
		// same rule the combiner applies to every other analyzer (#4007): a
		// strictly higher severity below replaces it outright (so a
		// block-level homoglyph finding still wins when nothing else fired),
		// an equal severity unions the rule ids, and a lower severity below
		// leaves it untouched (so a real BLOCK found downstream is never
		// displaced by a lone AUDIT-level homoglyph elsewhere in the line).
		// This used to be a `return finish(result)` right after the scan,
		// which skipped the protected-path check and RunAll/fallback
		// entirely — one non-ASCII letter anywhere in the command silently
		// downgraded every BLOCK to AUDIT.
		if len(uniRules) > 0 {
			switch {
			case decisionSeverity(uniDecision) > decisionSeverity(r.Decision):
				r.Decision = uniDecision
				r.TriggeredRules = append([]string{}, uniRules...)
				r.Reasons = append([]string{}, uniReasons...)
				r.TaxonomyRefs = nil
			case decisionSeverity(uniDecision) == decisionSeverity(r.Decision):
				r.TriggeredRules = append(r.TriggeredRules, uniRules...)
				r.Reasons = append(r.Reasons, uniReasons...)
			}
		}
		// Read before applyModeDowngrade: in audit-only mode a BLOCK arrives
		// here already rewritten to AUDIT, and annotating that with
		// "recorded, not blocked" would describe the wrong event.
		//
		// BLOCK only, deliberately. REQUIRE_APPROVAL is not "blocked for
		// something else" — it is the *default decision* of the shipped
		// configs/default_policy.yaml template, so treating it as blocking
		// suppressed the record on every command under that policy, which is
		// the one users are told to copy. Measured 2026-09-06 against a
		// binary built from this tree: `export KUBECONFIG=$HOME/.kube/config`
		// under the template got REQUIRE_APPROVAL with NO rule id, while the
		// identical command under the Go DefaultPolicy() (AUDIT) was
		// correctly attributed. The flag half (#3625, consumerNote) never had
		// this guard and was attributed under both. Beyond consistency: a
		// REQUIRE_APPROVAL prompt is precisely where a human benefits from
		// being told the command hands a credential path to KUBECONFIG.
		blocking := r.Decision == DecisionBlock
		r = applyModeDowngrade(r, e.mode)
		notes := make([]string, 0, 2)
		if consumerNote != "" {
			notes = append(notes, consumerNote)
		}
		// The assignment record explains an otherwise unattributed AUDIT. It
		// is not added to a command that is being blocked for something else
		// — there the block is the event, and a "recorded, not blocked"
		// reason alongside it would read as a contradiction.
		if envConsumerNote != "" && !blocking {
			notes = append(notes, envConsumerNote)
		}
		if len(notes) > 0 {
			r.TriggeredRules = append(r.TriggeredRules, ProtectedPathConsumerRuleID)
			r.Reasons = append(r.Reasons, notes...)
			if r.Decision == DecisionAllow {
				r.Decision = DecisionAudit
			}
		}
		r.Explanation = buildExplanation(r)
		return r
	}

	// Built-in: Unicode smuggling detection (runs before all rules, but no
	// longer returns early — see #4007). Its decision/rules/reasons are
	// captured here and folded into the final result inside finish(), most-
	// restrictive-wins against the protected-path check and RunAll/fallback,
	// instead of short-circuiting them.
	uniScan := unicheck.Scan(command)
	if !uniScan.Clean {
		hasBlockLevel := false
		for _, threat := range uniScan.Threats {
			uniRules = append(uniRules, "unicode-"+threat.Category)
			uniReasons = append(uniReasons, threat.Description)
			if threat.Severity == "block" {
				hasBlockLevel = true
			}
		}
		if hasBlockLevel {
			uniDecision = DecisionBlock
		} else {
			uniDecision = DecisionAudit
		}
	}

	if blocked, rule := e.checkProtectedPaths(paths, cwd); blocked && !consumerOnly() {
		result.Decision = DecisionBlock
		result.TriggeredRules = append(result.TriggeredRules, "protected-path")
		result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied: %s", rule))
		return finish(result)
	}

	// If an analyzer registry is set, use the full pipeline.
	// Otherwise, fall back to built-in regex-only matching.
	if e.registry != nil {
		ctx := &analyzer.AnalysisContext{
			RawCommand:          command,
			Paths:               paths,
			Parsed:              parsed,
			Cwd:                 cwd,
			ExecContext:         e.execContext,
			ResolveProgramPaths: resolve,
		}
		combined := e.registry.RunAll(ctx, string(e.policy.Defaults.Decision))
		result.Decision = Decision(combined.Decision)
		result.TriggeredRules = combined.TriggeredRules
		result.Reasons = combined.Reasons
		// Issue #3111: carry the taxonomy refs of the winning findings out to
		// the audit event. The protected-path post-pass below can add a rule
		// with no taxonomy — that's fine, it just contributes no ref.
		result.TaxonomyRefs = combined.TaxonomyRefs
		// #3995: the notes the stages left on the context ride out with the
		// verdict. Read after RunAll; nothing decides on them.
		result.Notes = ctx.Notes

		// Layer 2.5 post-pass: re-run protected-path matching against any
		// paths the substitution analyzer reconstructed from `Name=value`
		// assignments. The early check at the top of this method only sees
		// paths the normalizer extracted from raw argv tokens; split-concat
		// bypasses (P1=~/.ssh; P2=id_rsa; cat $P1/$P2) only become concrete
		// after the AST walk. We override to BLOCK on a hit because
		// protected paths are non-negotiable — combiner severity doesn't
		// apply when the policy explicitly named the path off-limits.
		if blocked, rule := e.checkProtectedPaths(ctx.MaterializedPaths, cwd); blocked && !consumerOnly() {
			result.Decision = DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "protected-path-via-substitution")
			result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied (resolved via variable substitution): %s", rule))
		}

		// Assignment half of the consumer table (#3630): naming a protected
		// path into a designated consumer's environment credential slot
		// (`export KUBECONFIG=~/.kube/config`) is recorded, never blocked.
		// Deliberately does not feed checkProtectedPaths — see
		// AnalysisContext.Assignments and ProtectedEnvAssignment.
		if env, ok := e.ProtectedEnvAssignment(ctx.Assignments); ok {
			envConsumerNote = fmt.Sprintf("Protected credential path assigned to %s, a designated consumer's environment credential slot — recorded, not blocked", env)
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

	// ifsCommand is the third instance of exactly that reasoning, and it was
	// simply missing (found by the #3717 cross-path parity table): `${IFS}`/
	// `$IFS` is the shell's own word separator, so `cmd${IFS}--flag` runs
	// `cmd --flag` while no raw-text rule matches. The pipeline has folded it
	// since #3044 — the largest single bypass class measured in this codebase,
	// 68% of BLOCKing commands — but the fallback never did, so disabling the
	// pipeline turned every ${IFS}-obfuscated invocation into a silent miss.
	//
	// Deliberately only the plain fold, NOT the composed
	// DequoteCommand(ifsCommand) form the pipeline also carries (#3209): that
	// composition has no witness on this path, and widening the fallback past
	// what a test pins is how the two paths drift in the other direction.
	ifsCommand := shellparse.NormalizeIFS(command)

	// emittedCommand decodes the escape sequences a printf format string or an
	// `echo -e` argument expands, when that text reaches an executor (#3802):
	// `printf '\\nufw disable\\n' | sh` runs the payload while no raw-text rule
	// opening with `\\b` can match across the literal backslash-n. Fourth
	// instance of the reasoning spelled out for foldedCommand above — the
	// pipeline gets this via RegexAnalyzer's wholeCommandForms, and without its
	// own candidate here, disabling the pipeline reopens the bypass.
	// TestEmittedSeparatorParityAcrossEvaluationPaths pins the two together.
	emittedCommand := shellparse.DecodeEmittedSeparators(command)

	// interpExecCandidates recovers command text from an exec call inside an
	// interpreter heredoc body — "csrutil disable" from a python heredoc
	// calling os.system("csrutil disable") (#3697). This is the regex-only
	// fallback path, so it needs its own candidate for the same reason
	// foldedCommand/materializedCommand/ifsCommand above do: the pipeline
	// gets it via RegexAnalyzer's wholeCommandForms, but disabling the
	// pipeline must not reopen the bypass. Computed once, tried per rule
	// like every other whole-command candidate.
	interpExecCandidates := analyzer.InterpreterHeredocExecStatements(command)

	// executedText: what an echo/printf/heredoc emits when the command hands
	// it to an executor, and every substitution body (#3938). The pipeline
	// gets these via RegexAnalyzer's per-statement retry; without its own
	// candidate here, disabling the pipeline reopens the quote-before-anchor
	// bypass. Tried only for restricting rules: an ALLOW must never be earned
	// by a fragment (the same fail-safe the pipeline's retry keeps).
	// TestExecutedTextParityAcrossEvaluationPaths pins the two together.
	executedText, unresolvedText := shellparse.ExecutedTextReport(command)
	// #3995 twin of the pipeline's notes for the regex-only path.
	var notes []analyzer.Note
	if unresolvedText > 0 {
		notes = analyzer.AppendNote(notes, analyzer.Note{Kind: analyzer.NoteExecutedTextUnresolved, Detail: strconv.Itoa(unresolvedText)})
	}

	// #3995: the excused probe below asks the same candidate forms the
	// match chain asks, in the same order, so an excusal that only shows on
	// a normalized form (a dequoted self-mgmt payload, a materialized path)
	// is recorded exactly as the pipeline records it. Codex review of #4005.
	probeForms := []string{command}
	for _, f := range []string{dequotedCommand, foldedCommand, materializedCommand, ifsCommand, emittedCommand} {
		if f != "" {
			probeForms = append(probeForms, f)
		}
	}
	probeForms = append(probeForms, interpExecCandidates...)
	probeForms = append(probeForms, executedText...)

	// #4088 pass 1: mirror of RegexAnalyzer's raw-command ALLOW verdict. A
	// prefix ALLOW is judged on the raw command, never on the dequoted, folded
	// or IFS-normalised candidates below, any of which can lose a redirect
	// bash still performs. Lazy: most commands meet no ALLOW prefix rule.
	rawAllowDisq, rawAllowDisqDone := false, false
	rawAllowDisqualified := func() bool {
		if !rawAllowDisqDone {
			rawAllowDisq, rawAllowDisqDone = shellparse.AllowDisqualified(command), true
		}
		return rawAllowDisq
	}
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
		if rule.Decision == DecisionAllow && len(rule.Match.CommandPrefix) > 0 && rawAllowDisqualified() {
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
		case ifsCommand != "" && e.matchRule(ifsCommand, rule):
			matchedCmd = ifsCommand
		case emittedCommand != "" && e.matchRule(emittedCommand, rule):
			matchedCmd = emittedCommand
		}
		if matchedCmd == "" {
			for _, cand := range interpExecCandidates {
				if e.matchRule(cand, rule) {
					matchedCmd = cand
					break
				}
			}
		}
		if matchedCmd == "" && rule.Decision != DecisionAllow {
			for _, cand := range executedText {
				if e.matchRule(cand, rule) {
					matchedCmd = cand
					break
				}
			}
		}
		if matchedCmd == "" {
			// #3995: a restricting rule whose raw pattern fires but whose own
			// exclusion removed it leaves an "excused" note — the same record
			// the pipeline path writes, on the raw command only.
			if rule.Decision == DecisionBlock || rule.Decision == DecisionRequireApproval {
				for _, form := range probeForms {
					if !e.matchRulePattern(form, rule) {
						continue
					}
					// The pattern fires on this form and matchRule did not:
					// one of the two exclusions removed it.
					switch {
					case e.intentExcluded(form, rule):
						stmts, _ := analyzer.AttributionStatements(form)
						notes = analyzer.AppendNote(notes, analyzer.Note{Kind: analyzer.NoteExcused, Rule: rule.ID, Detail: "intent:" + strings.Join(analyzer.MatchedIntentLabels(e.intentClassifier, form, stmts, rule.Match.CommandIntentExclude), ",")})
					case e.positionExcluded(form, rule):
						notes = analyzer.AppendNote(notes, analyzer.Note{Kind: analyzer.NoteExcused, Rule: rule.ID, Detail: "position:" + strings.Join(analyzer.MatchedPositions(form, rule.Match.CommandPositionExclude, analyzer.NewStatementFoldContext(form), func(s string) bool { return e.matchRulePattern(s, rule) }), ",")})
					}
					break
				}
			}
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
			stmts, _ := analyzer.AttributionStatements(matchedCmd)
			notes = analyzer.AppendNote(notes, analyzer.Note{Kind: analyzer.NoteDowngraded, Rule: rule.ID, Detail: "intent:" + strings.Join(analyzer.MatchedIntentLabels(e.intentClassifier, matchedCmd, stmts, analyzer.UnionIntentLabels(rule.Match.CommandIntentDowngrade, rule.Match.CommandIntentExclude)), ",")})
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
	result.Notes = notes

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
// the output-redirect condition added by #4082 — live on
// shellparse.PrefixRuleMatches, which is the single implementation shared
// with the analyzer's regex path.
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
	if e.intentExcluded(command, rule) {
		return false
	}
	return !e.positionExcluded(command, rule)
}

// positionExcluded is the regex-fallback half of command_position_exclude
// (#3376) — the analyzer-pipeline half lives in RegexAnalyzer.Analyze. Both
// call the same analyzer.PositionExcluded with the same raw-pattern predicate
// (matchRulePattern here, matchRegexRule there, both exclude-label-free) and
// the same fold context (#3725), so the two paths cannot drift the way
// #3232/#3234 found command_regex_exclude and command_intent_exclude had.
//
// Costs an AST parse (building foldCtx) plus another inside PositionExcluded
// itself, so it runs last: only a rule that already matched and survived its
// intent labels pays for it.
func (e *Engine) positionExcluded(command string, rule Rule) bool {
	if len(rule.Match.CommandPositionExclude) == 0 {
		return false
	}
	foldCtx := analyzer.NewStatementFoldContext(command)
	return analyzer.PositionExcluded(command, rule.Match.CommandPositionExclude, foldCtx, func(s string) bool {
		return e.matchRulePattern(s, rule)
	})
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
	statements, parsed := analyzer.AttributionStatements(command)
	return analyzer.IntentExcludedForStatements(e.intentClassifier, command, statements, parsed, rule.Match.CommandIntentExclude, e.statementMatcher(command, rule))
}

// statementMatcher builds the per-statement predicate that
// analyzer.IntentExcludedForStatements uses to attribute a match to a
// statement, for both command_intent_exclude and command_intent_downgrade on
// this regex-fallback path.
//
// It is the twin of RegexAnalyzer.Analyze's own statementMatcher and shares its
// candidate generator (analyzer.StatementMatchCandidates), which is the whole
// point (#3717): before this, both paths tested each statement with the plain
// matcher against RAW text only, while the top-level match folded ${IFS}
// separators, unset-parameter splices, quote splices and friends. An
// obfuscated real statement therefore did not count as matching and was
// skipped during attribution, leaving a coincidentally-matching doc-text
// sibling to carry the whole decision and downgrade (or suppress) a BLOCK that
// actually executed — a fail-open, since the attestation then records "no
// violation" for a statement that ran.
//
// Raw text is tried first so a statement that matches as written never pays
// for candidate generation; StatementMatchCandidates costs several AST parses.
// The memo is per predicate (i.e. per rule, per call) rather than per
// evaluation: only a rule whose pattern already matched the whole command ever
// reaches here, so cross-rule sharing would buy little and cost a threaded
// cache on every matchRule signature.
func (e *Engine) statementMatcher(command string, rule Rule) func(string) bool {
	var foldCtx *analyzer.StatementFoldContext
	forms := map[string][]string{}
	return func(stmt string) bool {
		if e.matchRulePattern(stmt, rule) {
			return true
		}
		cands, ok := forms[stmt]
		if !ok {
			if foldCtx == nil {
				// Built from the WHOLE command — the symbol table because a
				// defining "NAME=value" assignment lives even when the use
				// site is a separate statement (#3089), the assignment
				// context so a fold cannot contradict a sibling statement's
				// assignment. Same as the pipeline path.
				foldCtx = analyzer.NewStatementFoldContext(command)
			}
			cands = analyzer.StatementMatchCandidates(stmt, foldCtx)
			forms[stmt] = cands
		}
		for _, cand := range cands {
			if e.matchRulePattern(cand, rule) {
				return true
			}
		}
		return false
	}
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
// statement that makes the rule fire sits in a downgrade-labeled OR
// exclude-labeled position (a sensitive literal inside a gh/git --body/
// --message argument, a heredoc body, or an is_self_mgmt/is_bash_comment
// statement — see analyzer.UnionIntentLabels for why the exclude labels also
// count here, #3792). This is the regex-fallback twin of
// RegexAnalyzer.Analyze's downgrade, so the accuracy corpus and inline-YAML
// tests (which run this path) reach the same verdict the live pipeline does.
// Per-statement scoping (via IntentExcludedForStatements) keeps a chained
// real access at BLOCK: only the downgrade/exclude labels move a decision,
// never a genuine executed access.
func (e *Engine) effectiveDecision(command string, rule Rule) Decision {
	if len(rule.Match.CommandIntentDowngrade) == 0 || e.intentClassifier == nil {
		return rule.Decision
	}
	if rule.Decision != DecisionBlock && rule.Decision != DecisionRequireApproval {
		return rule.Decision
	}
	statements, parsed := analyzer.AttributionStatements(command)
	labels := analyzer.UnionIntentLabels(rule.Match.CommandIntentDowngrade, rule.Match.CommandIntentExclude)
	if analyzer.IntentExcludedForStatements(e.intentClassifier, command, statements, parsed, labels, e.statementMatcher(command, rule)) {
		return DecisionAudit
	}
	return rule.Decision
}

// compiledRegex returns the pre-compiled matcher for a pattern, compiling on
// demand for the (unreachable) miss.
//
// The miss path does not store its result — see the twin comment on
// RegexAnalyzer.cachedRegex. NewEngine pre-compiles every rule's CommandRegex
// and CommandRegexExclude, and those are the only patterns reaching here
// (matchRulePattern passes CommandRegex; regexExcluded passes
// CommandRegexExclude). Writing to regexCache here would make Engine.Evaluate
// unsafe to call from two goroutines, and the failure mode is
// `fatal error: concurrent map writes` — an unrecoverable process abort in the
// one component that must never die.
//
// TestEngineRegexCacheIsReadOnlyAfterConstruction holds the line.
func (e *Engine) compiledRegex(pattern string) *regexlit.Matcher {
	if m, ok := e.regexCache[pattern]; ok {
		return m
	}
	m, err := regexlit.Compile(pattern)
	if err != nil {
		return nil
	}
	return m
}

// checkProtectedPaths matches paths (already resolved by normalize against
// cwd) against the configured protected_paths patterns. cwd must be the value
// normalize.NormalizeCommand used to produce paths.
//
// A pattern matches in either of two ways, and the first is exactly main's
// check, so this can only ADD matches, never remove one (#4025 Codex pass 1):
//  1. the path against the pattern as written (~ expanded);
//  2. for a relative pattern, a path under cwd, made relative to cwd, against
//     the pattern. The hook hands over absolute paths, so without this a
//     pattern like "secrets/**" never matched there (#4020). Relativising the
//     path, rather than joining cwd onto the pattern, keeps cwd out of glob
//     syntax: a cwd such as /work/project[1] would otherwise become a
//     character class. See relativeToCwd for what it refuses.
func (e *Engine) checkProtectedPaths(paths []string, cwd string) (bool, string) {
	for _, path := range paths {
		expandedPath := e.expandPath(path)
		for _, pattern := range e.policy.Defaults.ProtectedPaths {
			expandedPattern := e.expandPath(pattern)
			if matchGlob(expandedPath, expandedPattern) {
				return true, pattern
			}
			if rel, ok := relativeToCwd(expandedPath, expandedPattern, cwd); ok &&
				matchGlob(rel, filepath.Clean(expandedPattern)) {
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

// relativeToCwd returns path relative to cwd, for matching a relative
// protected_paths pattern. A relative pattern describes paths UNDER cwd:
//   - a path outside cwd is refused. Its cwd-relative form starts with "../",
//     and matchGlob's literal-prefix test would let "../**" claim every
//     absolute path on the machine, or "*/x" claim "../x" (#4025 Opus review).
//     So a pattern that climbs out of cwd ("../**") never matches here; it
//     keeps only main's as-written match, as before this change.
//   - a relative path (from variable substitution, "./secrets/token") is
//     joined onto cwd first, so "./" and "secrets/.." spellings still match.
func relativeToCwd(path, pattern, cwd string) (string, bool) {
	if cwd == "" || !filepath.IsAbs(cwd) || filepath.IsAbs(pattern) || strings.HasPrefix(pattern, "~") {
		return "", false
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	rel, err := filepath.Rel(filepath.Clean(cwd), path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
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
