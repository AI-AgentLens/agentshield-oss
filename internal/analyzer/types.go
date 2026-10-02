package analyzer

import (
	"github.com/AI-AgentLens/agentshield/internal/execenv"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

// Analyzer is the interface every analysis layer implements.
// Each analyzer receives the full AnalysisContext (original input + accumulated
// enrichments from prior layers) and returns zero or more Findings.
type Analyzer interface {
	// Name returns the analyzer's identifier (e.g., "regex", "structural", "semantic").
	Name() string

	// Analyze inspects the command and returns findings.
	// Analyzers may also enrich ctx (e.g., structural sets ctx.Parsed).
	Analyze(ctx *AnalysisContext) []Finding
}

// AnalysisContext carries the original input and accumulated enrichments
// through all analyzer layers. Every analyzer reads from and writes to this.
type AnalysisContext struct {
	RawCommand string
	Args       []string
	Cwd        string
	Paths      []string // filesystem paths extracted by normalizer
	Domains    []string // domains extracted by normalizer

	// ExecContext describes the runtime environment this command is being
	// evaluated in — currently whether the process lives inside a CI/CD
	// runner (issue #3291). Set by the engine from execenv.Detect at
	// evaluation time. Zero-value (CI:false) when the engine has no exec
	// context configured — the historical trusted-developer baseline — so any
	// analyzer reading it must be safe with that default. Rules opt into
	// gating on this via `match.context.ci` (see analyzer.RegexRule.RequireCI).
	ExecContext execenv.Context

	// Enrichments added by analyzers (downstream layers can read these)
	Parsed *ParsedCommand // set by structural analyzer (or reused from normalizer)
	// Intents is the semantic analyzer's behavioral classification (what the
	// command DOES: file-delete, network-exfil, code-execute, …). Unrelated to
	// CommandFacts below, which records structural facts about the command
	// text itself.
	Intents      []CommandIntent // set by semantic analyzer
	DataFlows    []DataFlow      // set by dataflow analyzer (Phase 3)
	SessionState *SessionState   // set by stateful analyzer (Phase 4)

	// MaterializedPaths are paths reconstructed from variable substitution
	// (Layer 2.5 — Substitution analyzer). Populated when a command like
	//   P1=~/.ssh; P2=id_rsa; cat $P1/$P2
	// is statically resolvable to a concrete path. The engine re-runs
	// protected-path matching against these post-pipeline so split-concat
	// bypasses are caught by the same policy that catches the literal form.
	// Empty when no substitution-derived paths are recoverable.
	MaterializedPaths []string

	// Notes records where the pipeline knowingly gave up or excused a match
	// (#3995). An attestation record, never a decision input: nothing reads
	// Notes to decide, and a note's absence is not evidence of anything.
	// Appended through AddNote so duplicates from repeated probes collapse.
	Notes []Note

	// Assignments are the constant `NAME=value` bindings the Substitution
	// analyzer resolved, in name order. Deliberately SEPARATE from
	// MaterializedPaths: an assignment reads nothing, so a protected path
	// appearing here must never produce a BLOCK (`P=~/.kube/config` alone
	// has always been allowed and stays allowed). The engine consults this
	// set only to ATTRIBUTE an assignment into a designated consumer's
	// environment credential slot — `export KUBECONFIG=~/.kube/config` is
	// kubectl's credential slot by environment rather than by flag, so it is
	// recorded as protected-path-consumer AUDIT instead of going unnamed
	// (#3630). Covers `export VAR=`, the `VAR=… cmd` prefix form, and a bare
	// `VAR=…` statement. Empty when nothing statically resolved.
	Assignments []Assignment

	// CommandFacts are structural facts about the command TEXT (is it a bash
	// comment, doc-text vehicle like `git -m`/`gh --body`, heredoc body,
	// agentshield self-management). Populated by IntentClassifier — the
	// first analyzer in the pipeline. Rules opt out via
	// command_intent_exclude in YAML rather than OR-ing alternations into
	// shared regex macros. Zero-value when the classifier hasn't run
	// (e.g., regex-fallback path), so any analyzer reading these must be
	// safe with a default of "no labels set". Not to be confused with
	// Intents above (the semantic analyzer's behavioral classification).
	CommandFacts CommandFacts

	// RawStatements are the literal source text of each top-level shell
	// statement in RawCommand (split on &&/||/;/|/bare-newline, heredoc
	// bodies preserved) — see shellparse.SplitTopLevelStatements. Populated
	// by IntentClassifier alongside CommandFacts. Consumed by
	// IntentExcludedForStatements to scope command_intent_exclude per
	// statement instead of over the whole command, so a chained dangerous
	// statement can't be excused by an adjacent doc-text-shaped one.
	RawStatements []string

	// RawStatementsParsed reports whether RawCommand's top-level split
	// (shellparse.SplitTopLevelStatementsChecked) reflects a genuine shell
	// parse, as opposed to the single-element fallback used when RawCommand
	// fails to parse as shell syntax. false is indistinguishable from a real
	// single-statement command by RawStatements' shape alone — both are a
	// one-element slice holding the whole text — so IntentExcludedForStatements
	// needs this separately to fail closed on a parse-failure fallback
	// instead of trusting whole-blob classification (#3467).
	RawStatementsParsed bool

	// ResolveProgramPaths turns on #3991's reading of path-spelled command
	// words as the programs they run (`/usr/bin/rm` as `rm`): restrictView,
	// the regex layer's restrict candidates, and guardian's archive check.
	// Off, every analyzer behaves byte-for-byte as it did before #3991.
	//
	// It is set per evaluation by policy.Engine, never globally: the engine
	// evaluates a path-spelled command both ways and keeps the ON result only
	// when it is strictly more restrictive (policy.stricterResult). That max()
	// is the safety guarantee. The restrict-only discipline below is
	// precision — it keeps ON from inventing ALLOWs — not safety.
	ResolveProgramPaths bool

	// programView memoizes shellparse.ProgramView(Parsed) — see
	// restrictView. Unexported: it is a restrict-only rendering and must
	// not become something any analyzer reads by default.
	programView     *ParsedCommand
	programViewDone bool
}

// restrictView returns the program-name view of ctx.Parsed (#3991): every
// segment's Executable replaced by the program it runs when it was spelled as
// an absolute or home-anchored path, or nil when no segment was.
//
// RESTRICT-ONLY. Evaluate a rule or check against it only when a match there
// makes the decision stricter — a BLOCK/AUDIT/REQUIRE_APPROVAL rule that is not
// negated, a hard-coded detection — and only as a union with the match against
// ctx.Parsed itself, so the result can gain findings and never lose one. Never
// an ALLOW rule, an exemption, an intent label that an ALLOW rule could read,
// or a file-identity comparison: a binary planted at /tmp/x/rm is not rm.
//
// When the raw command itself spells a command word as a path, the view is
// built from a re-parse of the command with those words resolved, so that the
// parser's own name-keyed decomposition applies too: `/usr/bin/bash -c '…'`
// and `/usr/bin/su -c '…'` are only split into their inner commands when the
// carrier is recognised, and the inner `rm --recursive --force /` is caught
// only there. Remaining path-spelled words (inside a carrier body, say) are
// then resolved segment by segment.
func (ctx *AnalysisContext) restrictView() *ParsedCommand {
	if !ctx.ResolveProgramPaths {
		return nil
	}
	if !ctx.programViewDone {
		ctx.programViewDone = true
		base := ctx.Parsed
		resolved := false
		if rewritten := shellparse.BasenameCommandWord(ctx.RawCommand); rewritten != "" {
			if rp := shellparse.Parse(rewritten, restrictViewParseDepth); rp != nil {
				base, resolved = rp, true
			}
		}
		pv := shellparse.ProgramView(base)
		if pv == nil && resolved {
			pv = base
		}
		ctx.programView = pv
	}
	return ctx.programView
}

// restrictViewParseDepth is the indirect-execution depth of restrictView's
// re-parse: config.AnalyzerConfig's default. A deployment configured deeper
// gets a shallower restrict view than its main parse — less coverage for the
// path-spelled case, never a relaxation.
const restrictViewParseDepth = 2

// restrictingDecision reports whether a finding at decision d makes the
// verdict stricter than doing nothing, i.e. whether a rule at d may be
// matched against restrictView. ALLOW, and anything unrecognised, may not.
func restrictingDecision(d string) bool {
	switch d {
	case "BLOCK", "AUDIT", "REQUIRE_APPROVAL":
		return true
	}
	return false
}

// Assignment is one constant `NAME=value` binding resolved by the
// Substitution analyzer. Value is the materialized right-hand side with
// $HOME already folded to `~` (same folding the path check applies), so a
// consumer of this type compares it exactly as it would an argv word.
type Assignment struct {
	Name  string
	Value string
}

// Finding is a single result from an analyzer.
type Finding struct {
	AnalyzerName string   // "regex", "structural", "semantic", etc.
	RuleID       string   // rule that produced this finding
	Decision     string   // "BLOCK", "AUDIT", "ALLOW"
	Confidence   float64  // 0.0–1.0, used by combiner for prioritization
	Reason       string   // human-readable explanation
	TaxonomyRef  string   // link to taxonomy entry
	Tags         []string // e.g., ["exfiltration", "credential-access"]
}

// ---------------------------------------------------------------------------
// Type aliases — canonical types live in shellparse, re-exported here for
// backward compatibility so all existing analyzer code compiles unchanged.
// ---------------------------------------------------------------------------

type ParsedCommand = shellparse.ParsedCommand
type CommandSegment = shellparse.CommandSegment
type Redirect = shellparse.Redirect

// ---------------------------------------------------------------------------
// CommandIntent — produced by the semantic analyzer
// ---------------------------------------------------------------------------

// CommandIntent classifies a command's purpose using a security-relevant taxonomy.
type CommandIntent struct {
	Category   string  // e.g., "file-delete", "network-exfil", "code-execute"
	Risk       string  // "critical", "high", "medium", "low", "info"
	Confidence float64 // 0.0–1.0
	Segment    int     // which pipeline segment this applies to (-1 = whole command)
	Detail     string  // human-readable explanation
}

// ---------------------------------------------------------------------------
// DataFlow — produced by the dataflow analyzer (Phase 3 placeholder)
// ---------------------------------------------------------------------------

// DataFlow tracks data movement from source to sink through a command.
type DataFlow struct {
	Source    string // e.g., "/dev/zero", "~/.ssh/id_rsa", "env"
	Sink      string // e.g., "/dev/sda", "curl", "network"
	Transform string // e.g., "base64", "gzip", "pipe"
	Risk      string // "critical", "high", "medium", "low"
}

// ---------------------------------------------------------------------------
// SessionState — produced by the stateful analyzer (Phase 4 placeholder)
// ---------------------------------------------------------------------------

// SessionState tracks state across multiple commands in a session.
type SessionState struct {
	CommandCount  int
	RiskScore     float64
	AccessedPaths []string
}

// Note kinds (#3995). A bare default decision used to be indistinguishable
// from an evaluated one: when a rule's pattern fired but its labels excused
// it, when the shell parser gave up and the text was matched as one blob,
// when the scope walker dropped a binding past its cap, or when text fed to
// an executor could not be resolved, the event carried nothing. Every one of
// those is a place the pipeline knows it is being lossy; a Note says so on
// the audit event so a receipt can tell "nothing matched" from "something
// matched and was excused" and from "we could not fully evaluate this".
//
// The decision never changes on account of a note (the 2026-09-06 rule:
// only deny what you can justify). Kinds:
const (
	// NoteExcused: a restricting rule's pattern fires on this command and
	// the rule's own exclusion removed it — intent labels (regex and
	// semantic stages) or a position (regex stage). Rule names the rule;
	// Detail names the exclusion. command_regex_exclude is NOT noted: it is
	// part of the pattern itself (a match predicate, not an excusal).
	NoteExcused = "excused"
	// NoteDowngraded: a BLOCK/REQUIRE_APPROVAL match was downgraded to AUDIT
	// by command_intent_downgrade (#2843). The AUDIT already names the rule;
	// the note makes the downgrade machine-readable.
	NoteDowngraded = "downgraded"
	// NoteParseFallback: the shell parser failed, so per-statement
	// attribution ran on the whole text as one statement (#3467).
	NoteParseFallback = "parse_fallback"
	// NoteScopeAlternatesCapped: the scope walker dropped a conditional
	// binding past maxScopeAlternates (#3769 shape 5), so a protected read
	// behind it may have reached the default decision unattributed.
	NoteScopeAlternatesCapped = "scope_alternates_capped"
	// NoteExecutedTextUnresolved: text handed to an executor carried an
	// unexpanded `$` or backquote and was not retried (#3938). Detail is
	// the count of such texts.
	NoteExecutedTextUnresolved = "executed_text_unresolved"
	// NotePolicyDegraded: a policy layer could not be loaded and evaluation
	// ran without it (#4077: an unreadable disk packs directory, so premium
	// and custom rules were absent). Written by the caller that loads the
	// policy, not by an analyzer stage. Detail names the missing layer and
	// what the decision was actually evaluated against, so the SaaS never
	// attests a degraded evaluation as full enforcement.
	NotePolicyDegraded = "policy_degraded"
)

// Note is one attestation record on an evaluation. See the kinds above.
type Note struct {
	Kind   string `json:"kind"`
	Rule   string `json:"rule,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// AppendNote adds n to notes unless an identical note is already there.
func AppendNote(notes []Note, n Note) []Note {
	for _, have := range notes {
		if have == n {
			return notes
		}
	}
	return append(notes, n)
}

// AddNote records a note on the context (nil-safe, deduplicated).
func (ctx *AnalysisContext) AddNote(kind, rule, detail string) {
	if ctx == nil {
		return
	}
	ctx.Notes = AppendNote(ctx.Notes, Note{Kind: kind, Rule: rule, Detail: detail})
}

// MatchedIntentLabels returns the labels in want that hold on the command or
// on any of its attribution statements — the ones that could have excused a
// match — in want's order. A note's Detail names these rather than the
// rule's whole configured list, so an auditor can tell "was a comment" from
// "was self-management" (Opus review of #4005). Falls back to want when
// nothing holds on that view (an excusal decided on a carrier-resolved or
// heredoc-recovered statement), so the note is never empty.
func MatchedIntentLabels(classifier *IntentClassifier, command string, statements []string, want []string) []string {
	if classifier == nil || len(want) == 0 {
		return want
	}
	facts := []CommandFacts{classifier.Classify(command)}
	for _, s := range statements {
		if s != command {
			facts = append(facts, classifier.Classify(s))
		}
	}
	var out []string
	for _, label := range want {
		for _, f := range facts {
			if f.HasAny([]string{label}) {
				out = append(out, label)
				break
			}
		}
	}
	if len(out) == 0 {
		return want
	}
	return out
}

// MatchedPositions returns the positions in want that on their own exclude
// the match, in want's order; falls back to want if none does alone.
func MatchedPositions(command string, want []string, foldCtx *StatementFoldContext, matches func(string) bool) []string {
	var out []string
	for _, p := range want {
		if PositionExcluded(command, []string{p}, foldCtx, matches) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return want
	}
	return out
}
