package analyzer

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/regexlit"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
	pkgunicode "github.com/AI-AgentLens/agentshield/internal/unicode"
)

// RegexRule is a simplified rule representation for the regex analyzer.
// It mirrors the fields from policy.Rule that the regex analyzer needs,
// avoiding an import cycle with the policy package.
type RegexRule struct {
	ID            string
	Decision      string
	Confidence    float64
	Reason        string
	Taxonomy      string
	Exact         string
	Prefixes      []string
	Regex         string
	RegexExclude  string   // if non-empty, suppress the match when this pattern matches
	IntentExclude []string // suppress when ctx.CommandFacts has any of these (see intent.go)
	// IntentDowngrade downgrades a BLOCK/REQUIRE_APPROVAL match to AUDIT (instead
	// of suppressing it) when the match sits only in statements carrying one of
	// these labels — e.g. a sensitive-string literal inside a gh/git --body/
	// --message argument, which is documentation, not an executed access (#2843).
	// Uses the same per-statement scoping as IntentExclude, so a chained real
	// access in a non-doc-text statement still fires at full severity, and the
	// downgraded finding is still AUDITed (logged) rather than dropped — no FN.
	IntentDowngrade []string
	// PositionExclude lists syntactic POSITIONS at which this rule's own match
	// is not evidence — see PositionExcluded and internal/shellparse. Distinct
	// from IntentExclude, which classifies the whole command's text: this asks
	// where the match landed in the parsed command. Checked only after a match
	// has fired, because it costs an AST parse.
	PositionExclude []string
	// FoldSeparators also matches the command with Unicode separators folded
	// to a space (#4310). Prose-matching rules only; see policy.Match.
	FoldSeparators bool
	// RequireCI gates the rule on the runtime CI/CD execution context (issue
	// #3291). nil = no gate (rule always applies). *true = rule applies ONLY
	// when ctx.ExecContext.CI is true (tighten posture for attacker-facing CI
	// agents). *false = rule applies ONLY outside CI. Populated from
	// policy.Match.Context.CI. The check is a cheap nil-test per rule, done
	// before any matching, so a gated-out rule costs effectively nothing.
	RequireCI *bool
}

// RegexAnalyzer wraps the existing regex/prefix/exact rule matching logic
// as an Analyzer in the pipeline. This is Layer 0 — the fastest and most
// basic analysis layer.
type RegexAnalyzer struct {
	rules []RegexRule
	// regexCache holds required-literal-prefiltered matchers, not bare
	// regexps: every rule is tried against every candidate form of every
	// command, so the corpus-wide scan is the pipeline's dominant cost.
	// See internal/regexlit.
	regexCache map[string]*regexlit.Matcher
	classifier *IntentClassifier
	// positionSensitive[i] reports whether rules[i] can match a sub-statement
	// that it did not already match against the whole command — i.e. whether
	// the per-statement retry in Analyze can possibly change its verdict.
	// Parallel to rules; see isPositionSensitive.
	positionSensitive []bool
}

// isPositionSensitive reports whether a rule's verdict depends on WHERE in the
// input it matches.
//
// An unanchored regex is monotonic over substrings: if it matches a statement,
// it necessarily also matches the whole command (the statement is a substring),
// so the whole-command check in Analyze already found it and retrying per
// statement is pure wasted work. With ~1,100 pack rules that waste is what
// blew the pipeline perf budget.
//
// Only these rule shapes are position-sensitive:
//   - Regex containing "^" — the anchor is the entire point (39 pack rules).
//   - Regex containing "$" — an end anchor is defeated just as easily, since
//     wrapping APPENDS text ("...; }") rather than prepending it. A rule like
//     `wget .* -O models/deployed/.*\.safetensors$` misses inside a brace group
//     for exactly the mirror-image reason "^" rules miss behind a "cd &&".
//   - Prefixes — strings.HasPrefix is anchored by definition.
//   - Exact — equality against the whole input.
//   - A RegexExclude that is itself POSITIONAL — see below (#3901).
//
// # The monotonicity argument holds for the MATCH and fails for the EXCLUSION
//
// The skip above rests on a rule's own pattern being monotonic over substrings:
// match a statement and you necessarily match the whole command, so the
// whole-command pass already found it. True, and it is why the optimization is
// sound for matching.
//
// An exclusion inverts the direction. `command_regex_exclude` SUPPRESSES, and a
// positional one can match the whole command while matching no individual
// statement — the excused tool sits in a statement that merely PRECEDES the
// malicious one:
//
//	sed -n 1p notes.txt && claude --dangerously-skip-permissions
//
// The whole-command pass sees `sed` in execution position, suppresses the rule,
// and the per-statement retry that would have fired it cleanly on statement 2 is
// skipped as "pure wasted work". Measured: 13 of 73 BLOCK rules carrying an
// exclusion were switched off this way, 10 of them silently dropping to AUDIT.
// Retrying them closes 8; the survivors are recorded in
// prefix_bypass_baseline.txt with the reason each is a different defect.
//
// The tell is that `ts-block-ad-enum-tools` — whose exclusion is the sloppiest
// in the corpus, a bare `\b(grep|rg|awk|sed)\b` — was NOT bypassable, purely
// because its own regex carries a `^` and so was already being retried. The
// exclusion's quality was never what protected it; the anchor was.
//
// # Why only POSITIONAL exclusions, and not every exclusion
//
// Exclusions come in two kinds and they want opposite scoping:
//
//   - POSITIONAL — "this benign tool is the thing being run here", written with
//     an execution-position anchor (`^`, or post-&&/;/|). It is a claim about a
//     STATEMENT, so it must be evaluated per statement.
//   - GUARD CONDITION — "this command carries a safety property", e.g.
//     ts-block-agent-orchestration-server-fail-open excluding on
//     `AUTH_ENABLED=true` / `AUTH_TOKEN=...` / `--host 127.0.0.1`. It is a claim
//     about the WHOLE command, and re-evaluating it per statement breaks it: the
//     first cut of this fix made `AUTH_ENABLED=true AUTH_TOKEN=s3cr3t python
//     api_server.py` BLOCK, because a candidate form of the statement no longer
//     carried the assignment that proves auth is on. Caught by TN-ORCHFAILOPEN-002.
//
// The anchor is the discriminator, and it is the exclusion's own declaration of
// intent rather than a guess about it: an author who wrote `(?:^|&&\s*|;\s*)` was
// making a positional claim. A `^` inside a negated character class (`[^;&|]`) is
// not an anchor, so those are stripped before looking.
//
// Cost: ~112 rules carry an exclusion, a subset of which are positional; that is
// against ~1,100 rules total, not a doubling. Measured with SHIELD_PERF_BUDGET=1:
// typical p95 744µs -> 758µs (+1.8%, budget 3ms), adversarial p95 15.94ms ->
// 16.00ms (+0.3%, budget 55ms). The prefilter work (internal/regexlit) is what
// makes the retried set affordable, which was its point.
func isPositionSensitive(r RegexRule) bool {
	return r.Exact != "" || len(r.Prefixes) > 0 ||
		strings.ContainsAny(r.Regex, "^$") ||
		hasPositionalAnchor(r.RegexExclude)
}

// hasPositionalAnchor reports whether a pattern contains a real `^` anchor, as
// opposed to a `^` that merely negates a character class.
func hasPositionalAnchor(pat string) bool {
	if pat == "" {
		return false
	}
	return strings.Contains(strings.ReplaceAll(pat, "[^", "["), "^")
}

// NewRegexAnalyzer creates a regex analyzer from RegexRule definitions.
// Pre-compiles all regexes at initialization for O(1) lookup during evaluation.
func NewRegexAnalyzer(rules []RegexRule) *RegexAnalyzer {
	cache := make(map[string]*regexlit.Matcher, len(rules)*2)
	for _, r := range rules {
		for _, pat := range [...]string{r.Regex, r.RegexExclude} {
			if pat == "" {
				continue
			}
			if m, err := regexlit.Compile(pat); err == nil {
				cache[pat] = m
			}
		}
	}
	posSensitive := make([]bool, len(rules))
	for i, r := range rules {
		posSensitive[i] = isPositionSensitive(r)
	}
	return &RegexAnalyzer{
		rules:             rules,
		regexCache:        cache,
		classifier:        NewIntentClassifier(),
		positionSensitive: posSensitive,
	}
}

func (a *RegexAnalyzer) Name() string { return "regex" }

// Analyze evaluates the raw command against all regex/prefix/exact rules.
// Returns one Finding per matching rule.
//
// A quote-spliced token (`~/.ss'h'/id_r'sa'`) resolves to the real,
// unmodified path/keyword when a shell actually runs the command, but
// evades a naive substring/regex match against the pre-quote-removal text.
// PR #2814 closed this class for the structural protected_paths/args_any
// glob surfaces; command_regex matching here still compared raw text only
// (issue #2854). dequotedCommand is a best-effort AST-based reconstruction
// with quote artifacts stripped from static words — "" when the raw command
// has no quotes/backslashes, nothing was rewritten, or parsing failed, in
// which case only the raw command is checked (unchanged behavior).
func (a *RegexAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	var findings []Finding
	// One memo for this evaluation: the 120 rules carrying
	// command_intent_exclude / command_intent_downgrade all classify the same
	// raw command and the same statement list. See IntentClassifier.Memo.
	classifier := a.classifier.Memo()
	dequotedCommand := shellparse.DequoteCommand(ctx.RawCommand)
	ifsNormalized := shellparse.NormalizeIFS(ctx.RawCommand)
	// Built once from the FULL raw command: the symbol table because a
	// defining "NAME=value" assignment lives even when the usage
	// ("$NAME ...") is a separate statement (#3089), and the assignment
	// context because a fold applied to ONE statement must not contradict an
	// assignment in a sibling one (see StatementFoldContext).
	foldCtx := NewStatementFoldContext(ctx.RawCommand)

	// Alternative renderings of the WHOLE command, checked for every rule; see
	// buildWholeCommandForms, which redactedForms shares (#4400).
	wholeCommandForms := buildWholeCommandForms(ctx.RawCommand, dequotedCommand, ifsNormalized)

	// Per-statement match candidates, memoized for this evaluation.
	// StatementMatchCandidates costs several AST parses per statement and has
	// two consumers here — retryCandidates below (does the rule fire at all?)
	// and statementMatcher (which statement does a match belong to?) — that
	// each walk the same command, split by different splitters. Keying the
	// memo on the statement TEXT is what lets the two share work whenever the
	// splitters agree, which is the common case.
	stmtForms := map[string][]string{}
	statementCandidates := func(s string) []string {
		if f, ok := stmtForms[s]; ok {
			return f
		}
		f := StatementMatchCandidates(s, foldCtx)
		stmtForms[s] = f
		return f
	}
	// restrictCandidates adds the program-name renderings of path-spelled
	// command words (#3991) on top of statementCandidates. RESTRICT-ONLY: it
	// feeds the per-statement retry below — closed to ALLOW rules — and
	// nothing else. statementMatcher (attribution for intent excludes and
	// downgrades) deliberately keeps statementCandidates: a match found only
	// by reading /tmp/x/git as git must never earn a doc-text excuse.
	restrictForms := map[string][]string{}
	restrictCandidates := func(s string) []string {
		if !ctx.ResolveProgramPaths {
			return statementCandidates(s)
		}
		if f, ok := restrictForms[s]; ok {
			return f
		}
		f := restrictCandidatesFrom(s, statementCandidates(s), statementCandidates)
		restrictForms[s] = f
		return f
	}
	// restrictFoldCtx is foldCtx with PositionExcluded's redacted forms
	// widened to the restrict candidates. Handed ONLY to restricting rules: a
	// surviving redacted match cancels an exclusion, which tightens a BLOCK
	// rule and LOOSENS an ALLOW rule (Codex pass 2 on #3993, R1).
	restrictFoldCtx := foldCtx
	if ctx.ResolveProgramPaths {
		restrictFoldCtx = foldCtx.withRestrictForms()
	}

	// statementMatcher builds the per-statement predicate that
	// IntentExcludedForStatements uses to attribute a match to a statement.
	//
	// It deliberately uses the SAME candidate set as the per-statement retry
	// below (#3717). Testing raw statement text only meant an obfuscated real
	// statement did not count as matching and was skipped during attribution,
	// so an adjacent doc-text sibling that repeated the rule's pattern
	// verbatim became the only counted statement and carried the whole
	// decision — downgrading (or, for command_intent_exclude, suppressing) a
	// BLOCK that actually executed. Sharing the candidate generator rather
	// than re-deriving it is the point: a fold added to the top-level match
	// cannot silently fail to reach attribution.
	//
	// policy.Engine's regex-fallback twin (intentExcluded / effectiveDecision)
	// builds the same predicate over the same function, so the two paths
	// cannot disagree.
	statementMatcher := func(rule RegexRule) func(string) bool {
		return func(stmt string) bool {
			// Raw text first, so a statement that matches as written never
			// pays for candidate generation. statementCandidates(stmt)[0] is
			// stmt itself, so this is a short-circuit, not a second predicate.
			if a.matchRegexRule(stmt, rule) {
				return true
			}
			for _, cand := range statementCandidates(stmt) {
				if a.matchRegexRule(cand, rule) {
					return true
				}
			}
			return false
		}
	}

	// Extra match candidates for the per-statement retry below, computed at most
	// once per command (the packs carry ~1,100 rules, so rebuilding this per
	// rule would blow the pipeline perf budget). Anything already covered by the
	// two whole-command checks above is left out.
	// Executed text (#3938) is reported once, eagerly, so the
	// executed_text_unresolved note (#3995) depends on the command alone and
	// not on whether some later rule happened to trigger the lazy retry.
	executedBodies, unresolvedBodies := shellparse.ExecutedTextReport(ctx.RawCommand)
	if unresolvedBodies > 0 {
		ctx.AddNote(NoteExecutedTextUnresolved, "", strconv.Itoa(unresolvedBodies))
	}

	// programCandidates is every text the program-name reading produced that
	// no as-written form contains: the restrict-only extras of each statement
	// and executed-text body, plus the whole command read that way. Tried for
	// every restricting rule, positional or not (Codex pass 2, G5): the
	// positional retry below is an optimisation that relies on an unanchored
	// pattern having already seen every substring of the raw text, and a
	// program-name rendering is NEW text — `sudo\s+zzprobe` never saw
	// "sudo zzprobe" in "sudo /tmp/x/zzprobe", and `\A` is not a "^".
	var programForms []string
	programFormsReady := false
	programCandidates := func() []string {
		if programFormsReady || !ctx.ResolveProgramPaths {
			return programForms
		}
		programFormsReady = true
		seen := map[string]bool{ctx.RawCommand: true}
		for _, f := range wholeCommandForms {
			seen[f] = true
		}
		add := func(f string) {
			if f != "" && !seen[f] {
				seen[f] = true
				programForms = append(programForms, f)
			}
		}
		if whole := shellparse.BasenameCommandWord(ctx.RawCommand); whole != "" {
			add(whole)
			add(shellparse.DequoteCommand(whole))
		}
		extras := func(s string) {
			base := map[string]bool{}
			for _, f := range statementCandidates(s) {
				base[f] = true
			}
			for _, f := range restrictCandidates(s) {
				if !base[f] {
					add(f)
				}
			}
		}
		for _, st := range shellparse.SplitSequencedStatements(ctx.RawCommand) {
			if st = strings.TrimRight(st, " \t\n;"); st != "" {
				extras(st)
			}
		}
		for _, body := range executedBodies {
			extras(body)
		}
		return programForms
	}

	var candidates []string
	candidatesReady := false
	retryCandidates := func() []string {
		if candidatesReady {
			return candidates
		}
		candidatesReady = true

		seen := map[string]bool{ctx.RawCommand: true}
		if dequotedCommand != "" {
			seen[dequotedCommand] = true
		}
		if ifsNormalized != "" {
			seen[ifsNormalized] = true
		}
		for _, s := range shellparse.SplitSequencedStatements(ctx.RawCommand) {
			// A statement's source span keeps its trailing separator
			// ("curl ... | deno run -;" inside a brace group). Rules anchored at
			// BOTH ends — ^(curl|wget)\b.*\|\s*deno...$ — then fail on the "$".
			// Trim the separator so the statement reads as the command it is.
			// Only ";" and whitespace are trimmed. "&" is NOT: it means "run in
			// the background", which rules legitimately match on ("nohup ... &"),
			// so stripping it would create a new blind spot while closing another.
			s = strings.TrimRight(s, " \t\n;")
			if s == "" {
				continue
			}
			for _, f := range restrictCandidates(s) {
				if f == "" || seen[f] {
					continue
				}
				seen[f] = true
				candidates = append(candidates, f)
			}
		}
		// Text the shell will RUN that is not a top-level statement (#3938):
		// what an echo/printf/heredoc emits when the command pipes it into a
		// shell or writes-then-executes it, and every substitution body. A
		// leading-anchor alternation lists every separator but a quote, so
		// `echo 'install -m 4755 x y' | bash` never matched at the raw level
		// and the label withdrawals had nothing to act on — 291 fitness
		// probes on 78 BLOCK rules. Retried as commands of their own, the
		// same way a statement is, so "^" means start of what executes.
		for _, body := range executedBodies {
			for _, f := range restrictCandidates(body) {
				if f == "" || seen[f] {
					continue
				}
				seen[f] = true
				candidates = append(candidates, f)
			}
		}
		return candidates
	}

	// Parse fallback (#3467): the intent stage could not parse the command,
	// so every per-statement attribution below runs on the whole text as one
	// statement. Recorded once per evaluation (#3995); matching is unchanged.
	if !ctx.RawStatementsParsed && len(ctx.RawStatements) > 0 {
		ctx.AddNote(NoteParseFallback, "", "")
	}

	// matchAnyForm is the rule's whole match predicate: the raw command, its
	// whole-command forms (dequoted, IFS-normalized, leading-exec-folded),
	// and — for a restricting, position-sensitive rule — the per-statement
	// retry candidates (#3045: 39 pack rules anchor with "^"; against the
	// whole raw command any prefix defeats them, and "cd <project> &&" is the
	// single most common prefix an agent writes. Retrying each top-level
	// statement makes "^" mean "start of a command". An ALLOW rule keeps
	// whole-command semantics: a fragment must never vouch for the whole
	// command, or "<malicious>; history | grep git" launders itself.)
	//
	// One closure for both callers — the normal path and the excused-match
	// probe (#3995) that asks whether a rule its labels just excused would
	// have fired — so the two can never disagree about what "fires" means.
	// #4088 pass 1 (Opus review): an ALLOW prefix rule is judged on the RAW
	// command's write/indirect-execution verdict, never on a rewritten form's.
	// Several forms below lose a redirect bash still performs, and without
	// this the form that lost it earned the ALLOW. Asked only after such a
	// rule has matched some form, and at most once per command, so commands
	// no ALLOW prefix rule matches pay no extra parse.
	rawAllowDisq, rawAllowDisqDone := false, false
	rawAllowDisqualified := func() bool {
		if !rawAllowDisqDone {
			rawAllowDisq, rawAllowDisqDone = shellparse.AllowDisqualified(ctx.RawCommand), true
		}
		return rawAllowDisq
	}
	var matchAnyFormInner func(ruleIdx int, rule RegexRule) bool
	matchAnyForm := func(ruleIdx int, rule RegexRule) bool {
		if !matchAnyFormInner(ruleIdx, rule) {
			return false
		}
		return !(rule.Decision == "ALLOW" && len(rule.Prefixes) > 0 && rawAllowDisqualified())
	}
	matchAnyFormInner = func(ruleIdx int, rule RegexRule) bool {
		if a.matchRegexRule(ctx.RawCommand, rule) {
			return true
		}
		for _, form := range wholeCommandForms {
			if a.matchRegexRule(form, rule) {
				return true
			}
		}
		if rule.Decision != "ALLOW" && a.positionSensitive[ruleIdx] {
			for _, cand := range retryCandidates() {
				if a.matchRegexRule(cand, rule) {
					return true
				}
			}
		}
		// Program-name renderings for every restricting rule (#3991, Codex
		// pass 2 G5). Positional rules already got them through
		// retryCandidates. Inside matchAnyForm so the excused-match probe
		// and the normal path keep one definition of "fires"; empty unless
		// this is the engine's ON evaluation.
		if rule.Decision != "ALLOW" && !a.positionSensitive[ruleIdx] {
			for _, cand := range programCandidates() {
				if a.matchRegexRule(cand, rule) {
					return true
				}
			}
		}
		return false
	}
	restricts := func(rule RegexRule) bool {
		return rule.Decision == "BLOCK" || rule.Decision == "REQUIRE_APPROVAL"
	}

	for ruleIdx, rule := range a.rules {
		// CI-context gate (issue #3291): a rule carrying match.context.ci only
		// applies when the runtime execution context matches. Checked first, so
		// a rule gated out by context skips all matching work. Zero-value
		// ctx.ExecContext (CI:false) is the trusted-developer baseline, under
		// which a `ci: true` rule never fires.
		if rule.RequireCI != nil && *rule.RequireCI != ctx.ExecContext.CI {
			continue
		}
		// Intent-label exclusion is scoped per top-level shell statement
		// (see IntentExcludedForStatements) so a chained, unrelated
		// dangerous statement can't be excused by an adjacent doc-text/
		// heredoc/self-mgmt-shaped one within the same compound command.
		if len(rule.IntentExclude) > 0 {
			excluded := IntentExcludedForStatements(classifier, ctx.RawCommand, ctx.RawStatements, ctx.RawStatementsParsed, rule.IntentExclude, statementMatcher(rule))
			if excluded {
				// Attestation (#3995): a restricting rule whose pattern DOES
				// fire here, excused entirely by its labels, leaves a note.
				// The probe costs what an unexcused command already pays,
				// and only on excused ones. The decision is unchanged.
				if restricts(rule) && matchAnyForm(ruleIdx, rule) {
					ctx.AddNote(NoteExcused, rule.ID, "intent:"+strings.Join(MatchedIntentLabels(classifier, ctx.RawCommand, ctx.RawStatements, rule.IntentExclude), ","))
				}
				continue
			}
		}
		matched := matchAnyForm(ruleIdx, rule)
		// Positional exclusion (#3376). Applied after matching rather than
		// before, because it needs the rule's own predicate to attribute the
		// match to a position and it costs an AST parse — a rule that did not
		// fire must not pay for it.
		posFoldCtx := foldCtx
		if restrictingDecision(rule.Decision) {
			posFoldCtx = restrictFoldCtx
		}
		if matched && len(rule.PositionExclude) > 0 &&
			PositionExcluded(ctx.RawCommand, rule.PositionExclude, posFoldCtx, func(s string) bool {
				return a.matchRegexRule(s, rule)
			}) {
			matched = false
			if restricts(rule) {
				ctx.AddNote(NoteExcused, rule.ID, "position:"+strings.Join(MatchedPositions(ctx.RawCommand, rule.PositionExclude, posFoldCtx, func(s string) bool {
					return a.matchRegexRule(s, rule)
				}), ","))
			}
		}
		if matched {
			decision := rule.Decision
			reason := rule.Reason
			// Context-aware downgrade (#2843): a BLOCK/REQUIRE_APPROVAL match that
			// sits only inside doc-text statements (a sensitive literal in a
			// gh/git --body/--message argument) is documenting a pattern, not
			// executing an access — downgrade to AUDIT so it stays logged but
			// doesn't interrupt. Same per-statement scoping as IntentExclude: a
			// chained real access in a non-doc-text statement keeps its BLOCK.
			// The label list is IntentDowngrade UNIONED with IntentExclude
			// (#3792): a compound command can have one statement excused only by
			// an exclude label (e.g. is_self_mgmt) and a sibling excused only by
			// a downgrade label (e.g. in_heredoc) — neither list alone covers
			// every matched statement, so without the union both checks fail
			// closed and the match stays at full BLOCK. See UnionIntentLabels
			// for why this can only weaken a decision, never suppress one.
			if len(rule.IntentDowngrade) > 0 &&
				(decision == "BLOCK" || decision == "REQUIRE_APPROVAL") &&
				IntentExcludedForStatements(classifier, ctx.RawCommand, ctx.RawStatements, ctx.RawStatementsParsed, UnionIntentLabels(rule.IntentDowngrade, rule.IntentExclude), statementMatcher(rule)) {
				reason = reason + " [downgraded BLOCK→AUDIT: the sensitive pattern appears inside a documentation/message argument (gh/git --body/--message), not an executed access]"
				decision = "AUDIT"
				ctx.AddNote(NoteDowngraded, rule.ID, "intent:"+strings.Join(MatchedIntentLabels(classifier, ctx.RawCommand, ctx.RawStatements, UnionIntentLabels(rule.IntentDowngrade, rule.IntentExclude)), ","))
			}
			f := Finding{
				AnalyzerName: "regex",
				RuleID:       rule.ID,
				Decision:     decision,
				Confidence:   rule.Confidence,
				Reason:       reason,
				TaxonomyRef:  rule.Taxonomy,
			}
			if f.Confidence == 0 {
				f.Confidence = 0.70 // default regex confidence
			}
			findings = append(findings, f)
		}
	}
	return findings
}

// matchRegexRule checks if a command matches a single rule (exact, prefix, or regex).
// Uses pre-compiled regexes from the cache for performance.
func (a *RegexAnalyzer) matchRegexRule(command string, rule RegexRule) bool {
	if a.matchRegexRuleForm(command, rule) {
		return true
	}
	if rule.FoldSeparators {
		if folded, changed := pkgunicode.FoldUnicodeSeparators(command); changed {
			return a.matchRegexRuleForm(folded, rule)
		}
	}
	return false
}

func (a *RegexAnalyzer) matchRegexRuleForm(command string, rule RegexRule) bool {
	// RegexExclude applies to EVERY match kind, not just the regex one. It used
	// to be consulted only inside the rule.Regex branch below, so a rule
	// combining Prefixes (or Exact) with RegexExclude had an exclude that
	// parsed, validated, and did nothing — here and in policy.Engine.matchRule
	// (#3232). No shipped rule had that combination, which is why it survived:
	// the field was a latent trap rather than a live bug, and the first rule to
	// reach for it would have silently got no exclusion at all.
	excluded := func() bool {
		if rule.RegexExclude == "" {
			return false
		}
		reExcl := a.cachedRegex(rule.RegexExclude)
		return reExcl != nil && reExcl.MatchString(command)
	}

	if rule.Exact != "" {
		if command == rule.Exact {
			return !excluded()
		}
	}

	// Single implementation shared with policy.Engine — see #3199 and the
	// doc comment on shellparse.PrefixRuleMatches. This is the copy the
	// deployed binary actually evaluates.
	if shellparse.PrefixRuleMatches(command, rule.Prefixes, rule.Decision == "ALLOW") {
		return !excluded()
	}

	if rule.Regex != "" {
		re := a.cachedRegex(rule.Regex)
		if re != nil && re.MatchString(command) {
			return !excluded()
		}
	}

	return false
}

// cachedRegex returns the pre-compiled matcher for a pattern.
//
// The miss path compiles WITHOUT storing, which reads like a wasted
// opportunity and is not. NewRegexAnalyzer compiles every rule's Regex and
// RegexExclude up front, and those two fields are the only patterns any caller
// passes (matchRegexRule, the sole caller, reads exactly them). So a miss means
// the pattern already failed to compile at construction and is about to fail
// again, returning nil.
//
// The store was therefore dead code — and dead code that writes to a shared map
// is not harmless. cmd/shield-server shares ONE engine across HTTP requests and
// says so in its own type comment ("that path is read-only after construction").
// A concurrent Go map write is `fatal error: concurrent map writes`, which the
// runtime cannot recover from — not a panic that a fail-safe AUDIT default can
// absorb, an unrecoverable abort of the process that is meant to be enforcing.
//
// Keeping the map read-only after construction is what makes that documented
// contract true. TestRegexCacheIsReadOnlyAfterConstruction holds the line.
func (a *RegexAnalyzer) cachedRegex(pattern string) *regexlit.Matcher {
	if m, ok := a.regexCache[pattern]; ok {
		return m
	}
	m, err := regexlit.Compile(pattern)
	if err != nil {
		return nil
	}
	return m
}

// matchRegexRuleStandalone is the standalone version for tests that don't have an analyzer instance.
func matchRegexRule(command string, rule RegexRule) bool {
	// Must stay in step with (*RegexAnalyzer).matchRegexRule above, including
	// applying RegexExclude to Exact/Prefixes matches and not only to Regex
	// ones (#3232).
	excluded := func() bool {
		if rule.RegexExclude == "" {
			return false
		}
		reExcl, err := regexp.Compile(rule.RegexExclude)
		return err == nil && reExcl.MatchString(command)
	}
	if rule.Exact != "" && command == rule.Exact {
		return !excluded()
	}
	if shellparse.PrefixRuleMatches(command, rule.Prefixes, rule.Decision == "ALLOW") {
		return !excluded()
	}
	if rule.Regex != "" {
		re, err := regexp.Compile(rule.Regex)
		if err == nil && re.MatchString(command) {
			return !excluded()
		}
	}
	return false
}
