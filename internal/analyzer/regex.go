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
	// Built once from the FULL raw command, where a defining "NAME=value"
	// assignment lives even when the usage ("$NAME ...") is a separate
	// statement — see ResolveIndirectExecutable's doc comment (#3089).
	execSyms := shellparse.BuildExecSymbolTable(ctx.RawCommand)

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
		add := func(s string) {
			if s == "" || seen[s] {
				return
			}
			seen[s] = true
			candidates = append(candidates, s)
			// Fold unset-parameter expansions on the way IN, so every peel
			// below gets it for free — the splice can hide inside whatever a
			// peel extracts, not just in the statement the peel started from.
			// `trap 'cat /${zqx}etc/shadow' EXIT` is the case that forced
			// this: InlineCodeFragments recovers the trap body, and the body
			// still carries the splice. Doing it here rather than at each peel
			// site means a peel added later cannot forget it. Non-recursive on
			// purpose — folding is idempotent, so the second fold of a folded
			// form returns the "" no-op sentinel anyway.
			if folded := shellparse.NormalizeUnsetParamExp(s); folded != "" && !seen[folded] {
				seen[folded] = true
				candidates = append(candidates, folded)
			}
			// Same reasoning, for split-concat assignments (#3249): a carrier
			// body can itself contain "p=id_rsa; cat ~/.ssh/$p" — the literal
			// a rule is written against never appears in ITS text either,
			// same as ctx.RawCommand's own split-concat case the
			// wholeCommandForms pass already folds (line ~310). That pass
			// only walks ctx.RawCommand and its whole-command forms, never a
			// fragment recovered from inside a carrier, so a rule needing
			// this fold saw nothing when the split-concat assignment was
			// delivered through eval/bash -c/trap instead of written
			// directly (#3321).
			if materialized := shellparse.MaterializeAssignments(s); materialized != "" && !seen[materialized] {
				seen[materialized] = true
				candidates = append(candidates, materialized)
			}
		}

		// addInlineCodeForms registers the code carried inside `bash -c '...'`,
		// `eval '...'`, `trap '...' EXIT`, a shell heredoc body and friends
		// (#3050/#3059/#3081), in every shape a peel can expose.
		//
		// It exists as ONE function because there are two call sites — the
		// statement as written, and the statement after its executable has been
		// resolved through one level of indirection (#3089) — and they had
		// drifted. The `s` site peeled leading assignments off a recovered
		// fragment; the `resolved` site did not; neither peeled an exec
		// wrapper. So `bash -c 'env dd if=/dev/zero of=/dev/sda'` handed the
		// ^-anchored dd rule a fragment still beginning with `env`, and
		// `x=bash; $x -c 'env dd ...'` was a second, independent instance of
		// the same omission.
		//
		// That gap pre-dates #3221 — `env` is the oldest entry in the wrapper
		// table, and #3057 peels wrappers off a STATEMENT — it simply had no
		// witness, because no corpus TP was wrapper-prefixed until #3221 added
		// some. Wrapping those in a carrier composed the two features for the
		// first time and three carrier parity sweeps went over budget at once.
		//
		// Keeping the peels here rather than in add() confines the parse cost
		// to commands that actually carry inline code. Keeping them in one
		// function is what stops the next peel from being added to one call
		// site and not the other.
		// It recurses because a carrier body is very often another carrier:
		// `bash <<EOF ... bash -c 'dd if=/dev/zero of=/dev/sda' ... EOF`,
		// `bash <<EOF ... su -c 'rm -rf /' ... EOF`, heredoc-wrapped `eval`.
		// One level of extraction leaves the ^-anchored rule looking at
		// `bash -c '...'`, which it does not match. This is the "double-wrapped
		// payload" residual #3081 recorded and attributed to maxParseDepth's
		// default of 2 — true for the AST layers, but the regex layer's own
		// extraction was simply not recursive, and that half is fixable here
		// without touching the parse depth every analyzer shares.
		//
		// Depth is capped at maxInlineCodeNesting rather than left to terminate
		// naturally on "no carrier found". Termination is not in doubt — a
		// fragment with no inline code yields none — but the cost is
		// multiplicative per level and an adversarial input can nest carriers
		// as deep as it likes.
		const maxInlineCodeNesting = 3
		var addInlineCodeForms func(text string, depth int)
		addInlineCodeForms = func(text string, depth int) {
			if depth > maxInlineCodeNesting {
				return
			}
			for _, frag := range shellparse.InlineCodeFragments(text) {
				add(frag)
				add(shellparse.NormalizeIFS(frag))
				if fs := shellparse.StripCommandPrefixes(frag); fs != "" {
					add(fs)
					add(shellparse.NormalizeIFS(fs))
				}
				if fw := shellparse.StripExecWrapperPrefix(frag); fw != "" {
					add(fw)
					add(shellparse.DequoteCommand(fw))
					add(shellparse.NormalizeIFS(fw))
				}
				// A fragment can itself be a bare indirection — `eval "$zc"`
				// and `bash -c "$zc"` both recover the fragment "$zc" above,
				// unresolved, when zc is a constant scalar assigned earlier in
				// the raw command. ResolveIndirectExecutable already resolves
				// exactly this shape for a plain STATEMENT (#3089); it was
				// never called on a fragment recovered from a carrier's BODY,
				// so the two features — carrier-body extraction and indirect-
				// executable resolution — never composed (#3238). Both halves
				// independently produce the right answer; only the call was
				// missing, so this mirrors the peels above rather than adding
				// a new mechanism.
				if resolved := shellparse.ResolveIndirectExecutable(frag, execSyms); resolved != "" {
					add(resolved)
					add(shellparse.DequoteCommand(resolved))
					add(shellparse.NormalizeIFS(resolved))
					if fs := shellparse.StripCommandPrefixes(resolved); fs != "" {
						add(fs)
						add(shellparse.NormalizeIFS(fs))
					}
					if fw := shellparse.StripExecWrapperPrefix(resolved); fw != "" {
						add(fw)
						add(shellparse.DequoteCommand(fw))
						add(shellparse.NormalizeIFS(fw))
					}
					// The resolved value is the scalar's whole runtime text,
					// which is very often a COMPOUND command ("if true; then
					// rm -rf /; fi") rather than a single simple one — the
					// scalar carries whatever the attacker assigned it, same
					// as ctx.RawCommand itself can be compound. Splitting it
					// the same way the top-level command is split (#3045) is
					// what lets an anchored rule see "rm -rf /" as its own
					// statement instead of only the unmatchable "if true;
					// then rm -rf /; fi" blob. Deliberately NOT re-entering
					// addStatementForms here (its own call back into
					// addInlineCodeForms would make this mutually recursive
					// with no combined depth limit) — this is one bounded
					// pass of the cheap peels only, not the full arsenal.
					for _, sub := range shellparse.SplitSequencedStatements(resolved) {
						sub = strings.TrimRight(sub, " \t\n;")
						if sub == "" || sub == resolved {
							continue
						}
						add(sub)
						add(shellparse.DequoteCommand(sub))
						add(shellparse.NormalizeIFS(sub))
					}
					addInlineCodeForms(resolved, depth+1)
				}
				addInlineCodeForms(frag, depth+1)
			}
		}

		// addStatementForms registers every text shape a single statement can
		// legitimately be matched in: as written, with quote artifacts removed,
		// with ${IFS}/$IFS word-splitting separators collapsed to a literal
		// space (#3044 — a bare ${IFS} default-whitespace substitution
		// defeated 68% of BLOCKing commands corpus-wide, the largest single
		// bypass class found in this codebase), and with prefixes that do not
		// change which command runs peeled off.
		addStatementForms := func(s string) {
			add(s)
			// A whole-word brace group ("{env,dd,if=/dev/zero,of=/dev/sda}")
			// can BE the prefix-plus-command shape the peels below exist to
			// see through — StripCommandPrefixes/StripExecWrapperPrefix look
			// for a literal "NAME=value "/"env "/"! " token at the START of
			// the text, which a brace group hides entirely (it is one token,
			// no spaces, until expanded). Expand up front, replacing the
			// working statement, so every peel below runs against the
			// corrected text the same way it already runs against the raw
			// one (issue #3217).
			if expanded := shellparse.NormalizeBraceWordList(s); expanded != "" {
				s = expanded
				add(s)
			}
			dequoted := shellparse.DequoteCommand(s)
			add(dequoted)
			ifsNormalized := shellparse.NormalizeIFS(s)
			add(ifsNormalized)
			// Composed forms, both orders: a quote-splice AND an ${IFS}
			// separator can coexist in the same statement
			// ("cat${IFS}~/.gi'thub'/creden'tials'"), and each transform
			// alone leaves the other artifact standing. Order matters here —
			// DequoteCommand bails on any word containing a ParamExp
			// (dynamic content), so "cat${IFS}~/.gi'thub'/creden'tials'"
			// dequotes to "" (the $IFS glues the whole thing into one
			// unresolvable word) until IFS is normalized FIRST, splitting it
			// into a separate, now purely-static, quoted word.
			if dequoted != "" {
				add(shellparse.NormalizeIFS(dequoted))
			}
			if ifsNormalized != "" {
				add(shellparse.DequoteCommand(ifsNormalized))
			}
			// An unset-parameter splice inside this statement
			// ("r${zqx}m -rf /", "${zqx:-dd} if=/dev/zero of=/dev/sda").
			// Composed with dequoting in that order only: DequoteCommand
			// bails on any word holding a ParamExp, so the splice has to go
			// first for a statement carrying both.
			if folded := shellparse.NormalizeUnsetParamExp(s); folded != "" {
				add(folded)
				add(shellparse.DequoteCommand(folded))
				add(shellparse.NormalizeIFS(folded))
			}

			// Leading env assignments and "!" negation sit BEFORE the command
			// word and do not change which command runs, but they defeat every
			// "^"-anchored rule (#3048). Note this applies even when the command
			// is a SINGLE statement equal to ctx.RawCommand — "LC_ALL=C dd
			// if=/dev/zero of=/dev/sda" has nothing to split, yet still needs
			// its stripped form checked.
			if stripped := shellparse.StripCommandPrefixes(s); stripped != "" {
				add(stripped)
				add(shellparse.DequoteCommand(stripped))
				add(shellparse.NormalizeIFS(stripped))
			}

			// Code carried inside `bash -c '...'` / `sh -c "..."` (#3050). The
			// structural analyzer can see in there once the fragment is
			// dequoted, but regex anchors still only see "bash -c ...", so
			// `bash -c "dd if=/dev/zero of=/dev/sda"` kept missing the
			// ^-anchored dd rule.
			addInlineCodeForms(s, 1)

			// An execution wrapper is the same shape of prefix: `env`, `exec`,
			// `nohup`, `timeout 10` and friends do not change WHICH command
			// runs, but they defeat anchored rules exactly as an assignment
			// does. The AST layers have seen through wrappers for a while; the
			// regex layer had no equivalent, leaving a hard 11.1% floor (#3057).
			if unwrapped := shellparse.StripExecWrapperPrefix(s); unwrapped != "" {
				add(unwrapped)
				add(shellparse.DequoteCommand(unwrapped))
				add(shellparse.NormalizeIFS(unwrapped))
			}

			// A statement's own executable can be named through one level of
			// indirection — "x=dd; $x if=/dev/zero of=/dev/sda" or "$(echo dd)
			// if=/dev/zero of=/dev/sda" run exactly "dd if=/dev/zero
			// of=/dev/sda" (#3089). The AST layer already resolves this via
			// shellparse.Parse's own symbol table; execSyms is built once from
			// ctx.RawCommand (where the defining assignment lives, even when
			// it's a separate preceding statement) and reused for every
			// candidate here.
			if resolved := shellparse.ResolveIndirectExecutable(s, execSyms); resolved != "" {
				add(resolved)
				add(shellparse.DequoteCommand(resolved))
				add(shellparse.NormalizeIFS(resolved))
				if stripped := shellparse.StripCommandPrefixes(resolved); stripped != "" {
					add(stripped)
				}
				// The wrapper/carrier ITSELF can be the thing delivered
				// indirectly — "x=env; $x dd if=/dev/zero of=/dev/sda" or
				// "x=bash; $x -c 'dd if=/dev/zero of=/dev/sda'" — so re-run the
				// same wrapper-stripping and inline-code extraction used for
				// the plain statement `s` against the newly-resolved text too;
				// otherwise composing indirection with an already-covered
				// carrier (env/nice/timeout, bash -c, eval, trap) reopens the
				// exact gap those carriers' own fixes closed (#3057, #3050,
				// #3059/#3084), one level removed (#3089).
				if unwrapped := shellparse.StripExecWrapperPrefix(resolved); unwrapped != "" {
					add(unwrapped)
					add(shellparse.DequoteCommand(unwrapped))
					add(shellparse.NormalizeIFS(unwrapped))
				}
				addInlineCodeForms(resolved, 1)
			}

			// Re-run the prefix/inline-code/wrapper peels against the
			// ${IFS}-normalized form too: each of those identifies its target
			// by the literal first-word text ("nice", "env", "bash -c"), which
			// an unresolved ${IFS} glued onto it defeats — "/bin/nice${IFS}dd"
			// parses as ONE token, not "/bin/nice" separate from "dd", so
			// StripExecWrapperPrefix's wrapper-name lookup never matches it.
			// Only the exec-wrapper case is wired below: prefix-strip and
			// inline-code-fragment extraction don't depend on ${IFS} being
			// glued to a following word the way a wrapper's own name does,
			// so running them a second time on ifsNormalized would just
			// re-derive forms add() already dedupes.
			if ifsNormalized != "" {
				if unwrapped := shellparse.StripExecWrapperPrefix(ifsNormalized); unwrapped != "" {
					add(unwrapped)
					add(shellparse.DequoteCommand(unwrapped))
				}
			}
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
			addStatementForms(s)

			// A backslash-newline is whitespace the shell deletes before
			// tokenizing, so `rm \<NL>-rf /` IS `rm -rf /` — but no regex
			// matches a backslash where it expects a space, and 52.5% of
			// BLOCKing commands degraded behind one (#3055). Re-render the
			// statement on a single line and match that shape too.
			if joined := shellparse.JoinLineContinuations(s); joined != "" {
				addStatementForms(joined)
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
			excluded := IntentExcludedForStatements(classifier, ctx.RawCommand, ctx.RawStatements, rule.IntentExclude, func(stmt string) bool {
				return a.matchRegexRule(stmt, rule)
			})
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
		if matched {
			decision := rule.Decision
			reason := rule.Reason
			// Context-aware downgrade (#2843): a BLOCK/REQUIRE_APPROVAL match that
			// sits only inside doc-text statements (a sensitive literal in a
			// gh/git --body/--message argument) is documenting a pattern, not
			// executing an access — downgrade to AUDIT so it stays logged but
			// doesn't interrupt. Same per-statement scoping as IntentExclude: a
			// chained real access in a non-doc-text statement keeps its BLOCK.
			if len(rule.IntentDowngrade) > 0 &&
				(decision == "BLOCK" || decision == "REQUIRE_APPROVAL") &&
				IntentExcludedForStatements(classifier, ctx.RawCommand, ctx.RawStatements, rule.IntentDowngrade, func(stmt string) bool {
					return a.matchRegexRule(stmt, rule)
				}) {
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

func (a *RegexAnalyzer) cachedRegex(pattern string) *regexlit.Matcher {
	if m, ok := a.regexCache[pattern]; ok {
		return m
	}
	m, err := regexlit.Compile(pattern)
	if err != nil {
		return nil
	}
	a.regexCache[pattern] = m
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
