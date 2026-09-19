package analyzer

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/regexlit"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
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
func isPositionSensitive(r RegexRule) bool {
	return r.Exact != "" || len(r.Prefixes) > 0 ||
		strings.ContainsAny(r.Regex, "^$")
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

	// Alternative renderings of the WHOLE command that mean exactly what the raw
	// text means, checked for every rule (not just anchored ones, unlike the
	// per-statement candidates below).
	//
	// The line-continuation form has to live here rather than in the anchored-
	// only retry: a backslash-newline lands wherever the line happened to wrap,
	// so it breaks patterns in the MIDDLE — `aws\s+ec2\s+terminate-instances`
	// fails on `aws \<NL>ec2 ...` even though the rule has no "^" at all (#3055).
	// Both this and the joined per-statement forms are needed: this one recovers
	// unanchored rules, the per-statement one recovers anchored rules whose
	// statement is nested inside a compound.
	var wholeCommandForms []string
	{
		seen := map[string]bool{ctx.RawCommand: true}
		addForm := func(s string) {
			if s == "" || seen[s] {
				return
			}
			seen[s] = true
			wholeCommandForms = append(wholeCommandForms, s)
		}
		addForm(dequotedCommand)
		addForm(ifsNormalized)
		// Compose the two: DequoteCommand bails on ctx.RawCommand whole-sale
		// the moment ANY word contains a ParamExp — including the ${IFS}/$IFS
		// token itself — so a command combining an ${IFS} separator with an
		// unrelated quote/backslash artifact elsewhere never got dequoted at
		// all via dequotedCommand above. Re-running DequoteCommand on the
		// ALREADY-IFS-normalized text (no more ${IFS} ParamExp left to bail
		// on) recovers it for unanchored rules the same way the per-statement
		// retry already does for anchored ones (#3044's composition, below).
		// Found via #3209: "cat${IFS}/etc\/shadow" downgraded BLOCK -> ALLOW
		// because neither candidate alone was both IFS-split AND dequoted.
		if ifsNormalized != "" {
			addForm(shellparse.DequoteCommand(ifsNormalized))
		}
		if joined := shellparse.JoinLineContinuations(ctx.RawCommand); joined != "" {
			addForm(joined)
			addForm(shellparse.DequoteCommand(joined))
			addForm(shellparse.NormalizeIFS(joined))
		}
		// A `printf` format string or an `echo -e` argument whose escape
		// sequences the program EXPANDS, when that text is handed to an executor
		// (#3802). `printf '\\nufw disable\\n' | sh` runs the payload while the
		// two raw characters before it are a backslash and an `n` — both word
		// characters — so a rule opening with `\\b` cannot match. Measured at
		// 30.8% of BLOCKing commands that survive the `echo '<cmd>' | sh`
		// control. A whole-command form rather than an anchored-only retry for
		// the same reason line continuations are one: the escape lands
		// mid-pattern, so it defeats unanchored rules too.
		if emitted := shellparse.DecodeEmittedSeparators(ctx.RawCommand); emitted != "" {
			addForm(emitted)
			addForm(shellparse.DequoteCommand(emitted))
			addForm(shellparse.NormalizeIFS(emitted))
		}
		// Indirect executable names ("x=aws; $x ec2 terminate-instances ...",
		// "$(echo aws) ec2 ...") are not substring-monotonic the way
		// quote-stripping/IFS-normalization are — the resolved word ("aws")
		// isn't a literal substring of the original text, so an UNANCHORED
		// rule (which only ever checks whole-command forms, see
		// isPositionSensitive) would never see it without this candidate
		// (#3089). The per-statement version below additionally covers
		// anchored ("^") rules against a resolved statement in isolation.
		if resolved := shellparse.ResolveIndirectExecutables(ctx.RawCommand); resolved != "" {
			addForm(resolved)
			addForm(shellparse.DequoteCommand(resolved))
			addForm(shellparse.NormalizeIFS(resolved))
			// Same composition as the per-statement retry below: the
			// resolved text can itself be a wrapper/carrier ("env dd ...",
			// "bash -c 'dd ...'") that needs its own established peel.
			if unwrapped := shellparse.StripExecWrapperPrefix(resolved); unwrapped != "" {
				addForm(unwrapped)
				addForm(shellparse.DequoteCommand(unwrapped))
			}
			for _, frag := range shellparse.InlineCodeFragments(resolved) {
				addForm(frag)
				addForm(shellparse.NormalizeIFS(frag))
			}
		}
		// A brace-expansion group ("~/.{ssh,x}/id_rsa") hides the sensitive path
		// segment as literal text no substring of the raw command contains — the
		// "unanchored regex already saw every substring" argument that gates the
		// position-sensitive-only retry below does not apply here, so every rule
		// gets a shot at each resolved alternative, not just anchored ones (#3085).
		for _, alt := range shellparse.ExpandBraces(ctx.RawCommand) {
			addForm(alt)
			// Compose with the other static transforms, same as every other
			// candidate source above (indirect-exec, line-continuation): a
			// brace-expanded alternative can ITSELF still carry a quote-splice
			// or ANSI-C ($'...') encoding that only resolves once dequoted —
			// e.g. "~/.{aws,x}/$'\x63'$'\x72'..." needs BOTH the brace group
			// resolved AND the ANSI-C fragments decoded before "credentials"
			// appears as literal text. Without this, composing brace-expansion
			// hiding with any other encoding reopens the gap each fix closed
			// individually (issue #3099 follow-up).
			addForm(shellparse.DequoteCommand(alt))
			addForm(shellparse.NormalizeIFS(alt))
		}
		// A '?'/'*' pathname-expansion wildcard hides a sensitive path segment
		// one shell-expansion phase after brace expansion — same "unmodeled
		// expansion phase" gap as ExpandBraces above, same reason every rule
		// (not just anchored ones) needs a shot at each resolution (#3102).
		for _, alt := range shellparse.DeglobSensitivePaths(ctx.RawCommand) {
			addForm(alt)
			addForm(shellparse.DequoteCommand(alt))
			addForm(shellparse.NormalizeIFS(alt))
		}
		// An unset-parameter splice ("cur${zqx}l", "${zqx:-curl}") is a
		// whole-command concern for the same reason line continuations are:
		// it lands mid-pattern, so it defeats unanchored rules too. Applied
		// as a pass over every form collected above rather than at each
		// addForm site, because it composes with all of them — a brace group,
		// an indirect exec name and a quote-splice can each still carry one.
		//
		// Order matters in the composition with DequoteCommand, and in the
		// opposite direction from the ${IFS} case documented below:
		// DequoteCommand bails on any word containing a ParamExp, so
		// "~/.ss${zqx}h/id_r'sa'" stays undequotable until the splice is
		// folded away FIRST, which is what makes this a pass over the
		// already-collected forms rather than another entry in the list.
		for _, f := range append([]string{ctx.RawCommand}, wholeCommandForms...) {
			if folded := shellparse.NormalizeUnsetParamExp(f); folded != "" {
				addForm(folded)
				addForm(shellparse.DequoteCommand(folded))
			}
			// A SINGLE-QUOTED inline-code body — `trap 'cat /${zqx}etc/shadow'
			// EXIT`, `eval '...'`, `bash -c '...'` — contains no ParamExp node
			// at all, because single quotes are fully literal to the parser.
			// The whole-command fold above is therefore a complete no-op on it;
			// the splice only becomes visible once the body is re-read as code.
			//
			// The per-statement candidates below fold these too, but those are
			// only consulted for position-sensitive (anchored) rules — so an
			// UNANCHORED rule matching a substring of the body (the /etc/shadow
			// rule is one) never saw the folded text. Only the folded fragment
			// is promoted here, never the raw one, so this cannot widen what
			// unanchored rules match for any command that has no splice.
			for _, frag := range shellparse.InlineCodeFragments(f) {
				addForm(shellparse.NormalizeUnsetParamExp(frag))
				// The comment just above — "only the folded fragment is
				// promoted, never the raw one" — rested on an assumption that
				// held right up until #3241: that a reconstructed payload is
				// always a SUBSTRING of the text it came from, so an unanchored
				// rule had already seen it. Payload reconstruction used to strip
				// quotes off the two ends of the word; it now performs real
				// quote removal, because that is what the carrier's own shell
				// does. `bash -c rm\ -rf\ /` reconstructs to "rm -rf /", which
				// appears nowhere in the raw command — new literal text, exactly
				// like a brace expansion or a resolved indirect exec name, and
				// needing whole-command promotion for the same reason.
				//
				// Gated on the substring test rather than promoted outright.
				// For every payload whose word boundaries were already visible
				// — `bash -c 'rm -rf /'` and every other ordinary spelling —
				// the fragment IS a substring, nothing is added, and what
				// unanchored rules match is byte-for-byte unchanged. The gate
				// is what keeps this from being a blanket widening.
				if !strings.Contains(f, frag) {
					addForm(frag)
					addForm(shellparse.DequoteCommand(frag))
				}
			}
		}
		// A whole-word brace group ("{rm,-rf,/}") is a DIFFERENT construct
		// from ExpandBraces' path-segment alternatives above: the group IS
		// the entire word, so its items become the command word and its
		// arguments, not alternative candidates for one argument — resolving
		// `{rm,-rf,/}` to alternatives yields "rm", "-rf", "/" as three
		// separate candidates, none of which is the command that runs.
		// Applied as a pass over every form collected so far (same reasoning
		// as the unset-parameter fold above — it composes with quote-splices,
		// indirect-exec names and IFS separators) rather than its own addForm
		// site, so it runs after the unset-parameter fold and sees an
		// already-simplified form (issue #3217).
		for _, f := range append([]string{ctx.RawCommand}, wholeCommandForms...) {
			if expanded := shellparse.NormalizeBraceWordList(f); expanded != "" {
				addForm(expanded)
				addForm(shellparse.DequoteCommand(expanded))
				addForm(shellparse.NormalizeIFS(expanded))
			}
		}
		// A split-concat assignment ("P1=~/.ssh; P2=id_rsa; cat $P1/$P2") reads
		// exactly the path a literal-keyed command_regex rule is written
		// against, but the raw text never contains that literal — Layer 2.5
		// (substitution.go) already resolves this for the ~10 protected_paths
		// globs, but none of the other ~1,100 pack rules ever saw it (issue
		// #3249). Applied as a pass over every form collected so far, same
		// reasoning as the brace-word-list pass just above: it composes with
		// quote-splices, IFS separators and brace-expanded alternatives.
		for _, f := range append([]string{ctx.RawCommand}, wholeCommandForms...) {
			if materialized := shellparse.MaterializeAssignments(f); materialized != "" {
				addForm(materialized)
				addForm(shellparse.DequoteCommand(materialized))
				addForm(shellparse.NormalizeIFS(materialized))
			}
		}
		// Command-execution literals recovered from inside an interpreter
		// heredoc body (#3697) — "csrutil disable" from a python heredoc
		// calling os.system("csrutil disable"). Checked for every rule, not
		// just anchored ones: this is literal command text a real call would
		// run, exactly like the other whole-command forms above. Use 2 of 2
		// — see InterpreterHeredocExecStatements' doc comment; use 1
		// (per-statement exclusion scoping) is ctx.RawStatements, populated
		// separately via AttributionStatements.
		for _, cand := range InterpreterHeredocExecStatements(ctx.RawCommand) {
			addForm(cand)
			addForm(shellparse.DequoteCommand(cand))
		}
	}

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
			for _, f := range statementCandidates(s) {
				if f == "" || seen[f] {
					continue
				}
				seen[f] = true
				candidates = append(candidates, f)
			}
		}
		return candidates
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
				continue
			}
		}
		matched := a.matchRegexRule(ctx.RawCommand, rule)
		for _, form := range wholeCommandForms {
			if matched {
				break
			}
			matched = a.matchRegexRule(form, rule)
		}
		// Per-statement retry (issue #3045). 39 pack rules anchor with "^"
		// (e.g. "^(sudo\s+)?mkfs", "^(sudo\s+)?dd\s+.*if=/dev/(zero|urandom)").
		// Anchored against the WHOLE raw command, any prefix defeats them —
		// "cd /tmp && mkfs.ext4 /dev/sda1" and "echo hi; dd if=/dev/zero
		// of=/dev/sda" both slipped to AUDIT/ALLOW. That is not just an
		// adversarial evasion: prefixing with "cd <project> &&" is the single
		// most common thing an agent does, so these were live false negatives.
		//
		// Retrying each top-level statement makes "^" mean "start of a
		// command", which is what the rule authors intended and what keeps
		// their FP-avoidance intent intact: "^avml" still will not match the
		// statement "apt install avml", because that statement starts with
		// "apt". Purely additive — the whole-command match above is unchanged,
		// so cross-statement patterns still work.
		//
		// Restricted to rules that RESTRICT (BLOCK/AUDIT/REQUIRE_APPROVAL). An
		// ALLOW rule must keep whole-command semantics: if an explicit ALLOW
		// could be earned by a single sub-statement, an attacker could launder a
		// malicious command by appending a benign one that trips an allowlist
		// rule ("<malicious>; history | grep git"). Fail-safe — never let a
		// fragment vouch for the whole command.
		if !matched && rule.Decision != "ALLOW" && a.positionSensitive[ruleIdx] {
			// Candidates include each statement, its dequoted form (quote-splice
			// inside a wrapped statement: the whole-command dequote above
			// reconstructs `{ cat ~/.gi'thub'/creden'tials'; }` with the braces
			// still attached, so an anchored rule still misses — #2854), and the
			// form with leading env assignments / "!" stripped (#3048).
			for _, cand := range retryCandidates() {
				if a.matchRegexRule(cand, rule) {
					matched = true
					break
				}
			}
		}
		// Positional exclusion (#3376). Applied after matching rather than
		// before, because it needs the rule's own predicate to attribute the
		// match to a position and it costs an AST parse — a rule that did not
		// fire must not pay for it.
		if matched && len(rule.PositionExclude) > 0 &&
			PositionExcluded(ctx.RawCommand, rule.PositionExclude, foldCtx, func(s string) bool {
				return a.matchRegexRule(s, rule)
			}) {
			matched = false
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
