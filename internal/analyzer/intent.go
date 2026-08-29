package analyzer

import (
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// CommandFacts captures structural facts about a command's TEXT that are
// useful for rule exclusions but tangential to the rule's primary signal. A
// rule whose signal would be a false positive in any of these contexts opts
// out via command_intent_exclude in YAML (the successor of the retired
// {{DOC_CONTEXT}} regex macro).
//
// Naming: this is deliberately NOT called "intents" — the semantic analyzer's
// ctx.Intents ([]CommandIntent) classifies what a command DOES (file-delete,
// network-exfil, …); CommandFacts records what the command text IS.
//
// The labels are named for the *fact about the command*, not the action a
// rule should take — IsDocText says "this command's own arguments are display
// text" (echo, git -m, gh --body, etc.); whether to suppress on that fact is
// a per-rule decision.
//
// Adding a label: add the field, add a name constant below, extend
// IntentClassifier with the matching regex, extend HasAny + IsValidIntentLabel.
// Add TP+TN coverage in intent_test.go for the new label, including the
// doc-context corpus test.
type CommandFacts struct {
	IsBashComment bool // ^# — line never executes
	IsDocText     bool // command's args are display/message text (echo, git -m, gh --body, …)
	InHeredoc     bool // cat/tee << EOF — body is data written to a file, not execution
	IsSelfMgmt    bool // agentshield <allowlisted-subcommand>

	// InInterpreterHeredoc is set for a heredoc fed to a NON-SHELL interpreter
	// (python3/node/ruby/perl/php/Rscript). The body is source code in that
	// language, so a shell-command pattern appearing in it is a string literal
	// the *shell* will never execute as a command.
	//
	// Deliberately excludes bash/sh/zsh/ksh/dash: their heredoc body IS shell,
	// so excusing it would let `bash <<EOF … EOF` launder any command. That is
	// not a hypothetical — see TestInterpreterHeredocNeverExcusesShellHeredoc.
	//
	// This is a SEPARATE label from InHeredoc rather than a widening of it,
	// because "body is inert data" (cat/tee) and "body is code in another
	// language" carry different risk. A rule opts into the second only when a
	// shell-pattern hit inside foreign source is genuinely not actionable for
	// that rule. Rules that are the sole coverage for an attack path (e.g. the
	// security-daemon/auditd BLOCKs) must NOT opt in — an attacker can reach
	// the shell from inside a python heredoc via os.system(), and those rules
	// are what catch it.
	InInterpreterHeredoc bool
}

// Label name constants — referenced from YAML rules via command_intent_exclude.
// These are the canonical strings; typos in YAML are caught at policy load
// time by IsValidIntentLabel.
const (
	LabelIsBashComment = "is_bash_comment"
	LabelIsDocText     = "is_doc_text"
	LabelInHeredoc     = "in_heredoc"
	LabelIsSelfMgmt    = "is_self_mgmt"

	// LabelInInterpreterHeredoc — heredoc body fed to a non-shell interpreter.
	// Never matches bash/sh/zsh/ksh/dash (their body is shell).
	LabelInInterpreterHeredoc = "in_interpreter_heredoc"
)

// HasAny reports whether any of the named labels is set on the receiver.
// Used by analyzers to short-circuit when a rule's command_intent_exclude
// list intersects the command's labels. Unknown names are ignored — policy
// load is the gate for label-name validity.
func (l CommandFacts) HasAny(names []string) bool {
	for _, n := range names {
		switch n {
		case LabelIsBashComment:
			if l.IsBashComment {
				return true
			}
		case LabelIsDocText:
			if l.IsDocText {
				return true
			}
		case LabelInHeredoc:
			if l.InHeredoc {
				return true
			}
		case LabelIsSelfMgmt:
			if l.IsSelfMgmt {
				return true
			}
		case LabelInInterpreterHeredoc:
			if l.InInterpreterHeredoc {
				return true
			}
		}
	}
	return false
}

// IsValidIntentLabel reports whether a label name is recognized. Policy
// loading should reject rules referencing unknown labels — silent typos
// would suppress nothing and create stealth FPs.
func IsValidIntentLabel(name string) bool {
	switch name {
	case LabelIsBashComment, LabelIsDocText, LabelInHeredoc, LabelIsSelfMgmt,
		LabelInInterpreterHeredoc:
		return true
	}
	return false
}

// IntentClassifier tags commands with structural facts (CommandFacts) used
// by rule exclusions. Runs once per command at the head of the analyzer
// pipeline, mutating AnalysisContext.CommandFacts. Like SubstitutionAnalyzer,
// it produces no Findings — pure enrichment.
type IntentClassifier struct {
	bashComment *regexp.Regexp
	docText     *regexp.Regexp
	heredoc     *regexp.Regexp
	interpHered *regexp.Regexp
	selfMgmt    *regexp.Regexp

	// memo caches Classify results. nil on the shared classifier; non-nil
	// only on the short-lived per-evaluation copies handed out by Memo.
	memo map[string]CommandFacts

	// wrapperFuncs / wrapperFuncsSet cache shellparse.SelfMgmtWrapperFunctionNames
	// for the current evaluation (#3314) — same Memo-scoped lifetime and
	// rationale as memo above. wrapperFuncsSet distinguishes "not computed
	// yet" from "computed, found none" so a nil result isn't recomputed on
	// every rule that requests the is_self_mgmt label.
	wrapperFuncs    map[string]bool
	wrapperFuncsSet bool
}

// Memo returns a copy of c that caches Classify results.
//
// Classify is a pure function of the command text, but the
// command_intent_exclude path calls it once per rule that opts in — 120
// community rules today — always on the same few strings (the raw command and
// its top-level statements). Profiling the 2026-08-09 perf-budget breach put
// 33.6% of pipeline CPU in Classify, essentially all of it recomputation of
// an answer already known.
//
// The memo lives on a copy, not on the shared classifier, and that placement
// is the whole design: the shared classifier is reachable from concurrent
// evaluations (MCP proxy, hook) so a cache on it would need a lock — handing
// back as contention what it saved in regex work — and would grow without
// bound in a long-running process. A copy scoped to one evaluation needs
// neither: it is single-threaded by construction and freed with the
// evaluation. Create one per command; never store one.
func (c *IntentClassifier) Memo() *IntentClassifier {
	cp := *c
	cp.memo = make(map[string]CommandFacts, 8)
	return &cp
}

// selfMgmtWrapperFuncs lazily computes and caches
// shellparse.SelfMgmtWrapperFunctionNames(command) — see #3314.
//
// Gated on c.memo != nil, the same signal Classify uses to decide whether it
// is safe to cache at all: memo is only non-nil on a Memo()-scoped copy,
// where every call within the copy's lifetime passes the same command (one
// evaluation). On the shared, un-Memo'd classifier (memo == nil) — reachable
// from concurrent evaluations, and reused across DIFFERENT commands by
// callers like the *IntentClassifier-sharing test loops in this package —
// caching by this same rule would go stale the moment a second command
// reused the instance, since unlike memo (keyed by statement text) this
// result has no command-keyed cache, just one slot. Recomputing on every
// call is the safe fallback for that case, exactly mirroring what happens to
// Classify when memo is nil.
func (c *IntentClassifier) selfMgmtWrapperFuncs(command string) map[string]bool {
	if c.memo == nil {
		return shellparse.SelfMgmtWrapperFunctionNames(command)
	}
	if c.wrapperFuncsSet {
		return c.wrapperFuncs
	}
	c.wrapperFuncs = shellparse.SelfMgmtWrapperFunctionNames(command)
	c.wrapperFuncsSet = true
	return c.wrapperFuncs
}

// docTextAlternations are the per-shape regexes that together define the
// IsDocText label. Each line corresponds to one alternation in the retired
// {{DOC_CONTEXT}} macro. Kept as separate strings so each shape is
// individually testable and the union is mechanical.
var docTextAlternations = []string{
	// echo/printf — args are display text.
	`^(echo|printf)\s`,
	// git commit/tag/notes/stash/merge -m/-F/--message/--file (compound-aware via &&/;).
	`(?:^|&&\s*|;\s*)git\s+(?:commit|tag|notes\s+(?:add|edit|append)|stash(?:\s+(?:push|save))?|merge)\b.*(?:\s-[mF]\s|\s--(?:message|file)[\s=])`,
	// gh issue/pr/release/gist/repo --body/--comment/--title/--notes/--description (compound-aware).
	// --comment covers `gh issue close/comment --comment "..."` — distinct from
	// --body, which `gh issue comment` also accepts for the same purpose (#3147).
	`(?:^|&&\s*|;\s*)gh\s+(?:issue|pr|release|gist|repo)\s+\S+\b.*\s--(?:body(?:-file)?|comment(?:-file)?|title|notes|description)(?:\s|=)`,
	// gh short flags -b/-t (compound-aware).
	`(?:^|&&\s*|;\s*)gh\s+.*\s-[bt]\s`,
	// System messaging.
	`^(logger|wall|say|notify-send|terminal-notifier)\s`,
	// npm/yarn version -m/--message.
	`^(npm|yarn)\s+version\s.*(?:\s-m\s|\s--message[\s=])`,
	// aws sns publish --message.
	`^aws\s+sns\s+publish\s+.*--message[\s=]`,
	// gcloud --description.
	`^gcloud\s+.*\s--description\s`,
	// docker --label, kubectl annotate/label.
	`^docker\s+(?:build|run)\s+.*--label\s`,
	`^kubectl\s+(?:annotate|label)\s`,
	// buildkite annotation.
	`^buildkite-agent\s+annotate\s`,
}

// NewIntentClassifier compiles all label regexes once. Panics on compile
// failure — these are package-internal patterns, an unparseable one is a
// programmer error, not a runtime condition.
func NewIntentClassifier() *IntentClassifier {
	return &IntentClassifier{
		bashComment: regexp.MustCompile(`^\s*#`),
		// (?s) so a doc-text flag (--body/--title/-m/...) is still found when
		// it's separated from the command name by a backslash-continued
		// newline (`gh issue create \\\n  --title "..." \\\n  --body ...`) —
		// without dotall, `.` can't cross the literal newline the shell
		// leaves in place, and the whole command reads as NOT doc-text even
		// though it's one logical statement (issues #2838, #2842).
		docText: regexp.MustCompile(`(?s)` + strings.Join(docTextAlternations, "|")),
		heredoc: regexp.MustCompile(`(?s)(?:^\s*|&&\s*|;\s*)(?:cat|tee)\s+.*<<`),
		// Non-shell interpreters only. `[^\n&;|]*` forbids a command separator
		// between the interpreter and the `<<`, so `python3 -c x && bash <<EOF`
		// cannot be mislabelled as an interpreter heredoc via the python prefix.
		interpHered: regexp.MustCompile(`(?s)(?:^\s*|&&\s*|;\s*|\|\s*)(?:python3?|node|ruby|perl|php|Rscript|osascript)\b[^\n&;|]*<<`),
		selfMgmt:    regexp.MustCompile(`agentshield\s+(?:mcp-eval|scan|setup|setup-mcp|pack|log|watchdog|update|login)(?:\s|$)`),
	}
}

// Classify returns the CommandFacts for a raw command string. Allocation-free
// in the common case (no labels match → zero-value struct).
func (c *IntentClassifier) Classify(cmd string) CommandFacts {
	if c.memo != nil {
		if f, ok := c.memo[cmd]; ok {
			return f
		}
		f := c.classify(cmd)
		c.memo[cmd] = f
		return f
	}
	return c.classify(cmd)
}

func (c *IntentClassifier) classify(cmd string) CommandFacts {
	return CommandFacts{
		IsBashComment: c.bashComment.MatchString(cmd),
		IsDocText:     c.docText.MatchString(cmd),
		InHeredoc:     c.heredoc.MatchString(cmd),

		InInterpreterHeredoc: c.interpHered.MatchString(cmd),
		IsSelfMgmt:           c.selfMgmt.MatchString(cmd),
	}
}

// Name implements Analyzer.
func (c *IntentClassifier) Name() string { return "intent-classifier" }

// Analyze populates ctx.CommandFacts, ctx.RawStatements and
// ctx.RawStatementsParsed, and returns no findings.
func (c *IntentClassifier) Analyze(ctx *AnalysisContext) []Finding {
	ctx.CommandFacts = c.Classify(ctx.RawCommand)
	topLevel, parsed := shellparse.SplitTopLevelStatementsChecked(ctx.RawCommand)
	ctx.RawStatementsParsed = parsed
	ctx.RawStatements = append(
		topLevel,
		carrierResolvedStatements(ctx.RawCommand)...,
	)
	return nil
}

// carrierResolvedStatements recovers the shell statements a carrier (`eval
// "$zc"`, `bash -c "$zc"`, `trap '...' EXIT`, and friends) actually runs, so
// IntentExcludedForStatements can classify what the carrier's BODY does, not
// just the raw top-level statement that invokes it (#3321).
//
// Without this, a carrier's payload sitting inside a single-quoted variable
// assignment is architecturally invisible to per-statement scoping: the
// assignment statement ("zc='cat ~/.ssh/id_rsa; git commit -m \"notes\"'") is
// ONE raw top-level statement — SplitTopLevelStatements cannot look inside a
// quoted string literal — so that statement's own text ends up serving as
// BOTH the evidence a rule matched (the literal substring "~/.ssh/id_rsa"
// sits right there in the quoted value) AND the evidence for exclusion or
// downgrade (the quoted value also contains "git commit -m", so the whole
// statement classifies as doc-text). That reopens the exact #2843 bypass
// (`{ cat ~/.ssh/id_rsa; git commit -m "notes"; }` collapsing into one
// statement) one layer up, behind the carrier's quote boundary instead of a
// `{ }` grouping.
//
// Mirrors the fragment-recovery chain RegexAnalyzer.Analyze already builds
// for MATCH candidates (ResolveIndirectExecutable + InlineCodeFragments,
// #3089/#3238): a rule that matches the carrier's resolved body gets to
// classify against that body's own sub-statements, split the same way
// ctx.RawStatements already splits the top level (SplitTopLevelStatements,
// not SplitSequencedStatements — this list is consulted for the same
// per-statement classification ctx.RawStatements exists for, so it needs the
// same pipe-splitting granularity, not the match-candidate one).
func carrierResolvedStatements(command string) []string {
	execSyms := shellparse.BuildExecSymbolTable(command)
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimRight(strings.TrimSpace(s), ";")
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}

	// Depth-bounded for the same reason regex.go's addInlineCodeForms is: a
	// carrier body is often another carrier (bash <<EOF ... eval '...' ...
	// EOF), and an adversarial input can nest carriers arbitrarily deep.
	const maxDepth = 3
	var walk func(text string, depth int)
	walk = func(text string, depth int) {
		if depth > maxDepth {
			return
		}
		for _, frag := range shellparse.InlineCodeFragments(text) {
			// A carrier consuming a constant scalar assigned earlier
			// (`eval "$zc"`) recovers only the bare, unresolved reference
			// ("$zc") — resolve it through the same symbol table the regex
			// analyzer's own candidate generation uses (#3089/#3238).
			if resolved := shellparse.ResolveIndirectExecutable(frag, execSyms); resolved != "" {
				frag = resolved
			}
			for _, sub := range shellparse.SplitTopLevelStatements(frag) {
				add(sub)
			}
			walk(frag, depth+1)
		}
	}
	for _, s := range shellparse.SplitTopLevelStatements(command) {
		walk(s, 1)
	}
	return out
}

// IntentExcludedForStatements decides whether a rule's command_intent_exclude
// labels should suppress a match, scoped per top-level shell statement.
//
// ctx.CommandFacts (and the bare Classify(cmd) call) treat the label as true
// if ANY part of the whole raw command looks doc-text/heredoc/self-mgmt/
// comment-shaped — which is correct for a single statement, but for a
// compound command it lets an unrelated, genuinely dangerous statement be
// laundered by an adjacent benign one:
//
//	cat ~/.ssh/id_rsa; git commit -m "notes"
//
// The trailing `git commit -m` makes the WHOLE command read as doc-text,
// silently suppressing the credential-read BLOCK on the first statement.
//
// statements and parsed must come from
// shellparse.SplitTopLevelStatementsChecked(command) (typically
// ctx.RawStatements / ctx.RawStatementsParsed, computed once by Analyze and
// reused across rules). matchesStatement reports whether the rule's own
// predicate (regex/exact/prefix, plus any command_regex_exclude) fires
// against a single statement's text in isolation — the caller supplies this
// since RegexRule's match shape lives in this package but the fallback
// engine's Rule shape lives in internal/policy.
//
// Only statements the rule itself would match need to satisfy the exclude
// label — an innocuous statement chained before/after a legitimately-excused
// one (e.g. `cd /tmp && tee /tmp/notes << EOF`) must keep being excused, so
// this is NOT "every statement must match the label" (that would reintroduce
// FPs on harmless setup/prefix statements).
//
// If no single statement matches the rule on its own, the match only exists
// by spanning a statement-separator inside the rule's own pattern (a
// command_regex deliberately written with a literal [;&|] class connecting
// a trigger on one side to a sink on the other, e.g.
// `declare -n ...=....*[;&|].*eval`). Per #3255, this is not rare: it is the
// ONLY path such rules ever take, because no single statement can ever
// satisfy them alone. Falling back to the whole-command label check there
// let an unrelated, adjacent statement (most commonly a decoy heredoc)
// launder the real cross-statement attack — the same class of bypass
// TestIntentExcludedForStatements_ChainedBypass closed for the ordinary
// per-statement case, reopened by construction for the spanning case. We
// cannot attribute the match to a single statement, so — matching this
// function's fail-safe posture everywhere else — we do not exclude.
//
// parsed=false means statements is the SplitTopLevelStatementsChecked
// single-element parse-failure fallback, not a genuine one-statement command
// — byte-for-byte the same shape, but with no guarantee the text is even
// syntactically valid shell (#3467: a lossy textual mutation can glue two
// real statements into one unparseable blob, e.g. a dropped newline
// terminator). Trusting labelMatches(command) there would classify an
// attacker-controlled, possibly-multi-statement blob as if it were one
// statement — the same whole-command-HasAny() bypass this function exists to
// close, just reached through the parse-failure door instead of a genuine
// compound command. Fail closed instead, matching the spanning-match posture
// above.
func IntentExcludedForStatements(classifier *IntentClassifier, command string, statements []string, parsed bool, exclude []string, matchesStatement func(string) bool) bool {
	if len(exclude) == 0 {
		return false
	}

	// #3314: a credential-shaped literal handed to a locally-defined shell
	// function that does nothing but relay it into `agentshield mcp-eval` is
	// exactly as inert as passing it to mcp-eval directly — the marker just
	// lives in a SIBLING statement (the function's own definition), which
	// SplitTopLevelStatements produces as its own top-level statement
	// (#3045) rather than merging into the call site. wrapperFuncs is nil
	// unless the rule actually requests is_self_mgmt, so this costs an AST
	// parse only on that path — see selfMgmtWrapperFuncs.
	var wrapperFuncs map[string]bool
	for _, label := range exclude {
		if label == LabelIsSelfMgmt {
			wrapperFuncs = classifier.selfMgmtWrapperFuncs(command)
			break
		}
	}
	labelMatches := func(stmt string) bool {
		facts := classifier.Classify(stmt)
		for _, label := range exclude {
			if label == LabelIsSelfMgmt {
				// #3548: is_self_mgmt's fact is "an agentshield mcp-eval/
				// scan/... invocation appears in this text" — true
				// regardless of which flag a sensitive-looking literal
				// reaches. --mcp-policy is the one mcp-eval flag that loads
				// a real file (unlike --arg/--json, which only ever
				// string-match), so a DYNAMIC --mcp-policy value (e.g. a
				// for-loop binding) must not be excused by that fact alone
				// — a static --mcp-policy literal is unaffected, since it's
				// caught independently by the structural protected-path
				// check.
				if facts.IsSelfMgmt && !shellparse.MCPEvalDynamicPolicyFlag(stmt) {
					return true
				}
				continue
			}
			if facts.HasAny([]string{label}) {
				return true
			}
		}
		return wrapperFuncs != nil && wrapperFuncs[shellparse.StatementLeadingCommandName(stmt)]
	}

	if len(statements) <= 1 {
		if !parsed {
			return false
		}
		return labelMatches(command)
	}

	matchedAny := false
	for _, stmt := range statements {
		if !matchesStatement(stmt) {
			continue
		}
		matchedAny = true
		if !labelMatches(stmt) {
			return false
		}
	}
	return matchedAny
}
