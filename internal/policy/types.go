package policy

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionAudit Decision = "AUDIT"
	DecisionBlock Decision = "BLOCK"
	// DecisionRequireApproval pauses execution and asks the user to confirm.
	// Currently no rule in this repo emits it — it's defined so the
	// audit-only downgrade path (issue #1952) can name the case it handles
	// without forcing callers to use a magic string. When a rule starts
	// emitting it, the existing downgrade logic in engine.applyModeDowngrade
	// will collapse it to AUDIT in audit-only mode.
	DecisionRequireApproval Decision = "REQUIRE_APPROVAL"
)

type Policy struct {
	Version    string      `yaml:"version"`
	Defaults   Defaults    `yaml:"defaults"`
	Network    Network     `yaml:"network"`
	Rules      []Rule      `yaml:"rules"`
	DataLabels []DataLabel `yaml:"data_labels,omitempty"`
	// DisableRules lists rule IDs the user has chosen to skip. The runtime
	// engine filters these out before evaluation. Managed mode ignores this
	// list for community rules — only rules tagged policy_override_allowed
	// can be relaxed by a non-admin.
	DisableRules []string `yaml:"disable_rules,omitempty"`
	// EnforcementMode is the SaaS-pushed enforcement mode for this org's
	// agents — surfaced in the YAML so the AI Agent Lens dashboard can flip
	// a whole org into "audit-only" without touching local config files.
	// Issue #1952. Values:
	//   ""           → no opinion (falls through to local config / default)
	//   "enforce"    → BLOCK rules block
	//   "audit-only" → BLOCK/REQUIRE_APPROVAL downgrade to AUDIT
	// Local config (~/.agentshield/agentshield.yaml `mode:`) and the CLI
	// `--mode` flag both win over this. See config.Load precedence comment.
	EnforcementMode string `yaml:"enforcement_mode,omitempty"`
}

// IsRuleDisabled reports whether the given rule ID has been disabled via the
// policy's `disable_rules:` list. Both the analyzer pipeline and the
// regex-fallback engine consult this — wherever a rule could fire, this is
// the gate that stops it.
func (p *Policy) IsRuleDisabled(id string) bool {
	if id == "" || len(p.DisableRules) == 0 {
		return false
	}
	for _, d := range p.DisableRules {
		if d == id {
			return true
		}
	}
	return false
}

type Defaults struct {
	Decision       Decision `yaml:"decision"`
	NonInteractive Decision `yaml:"non_interactive"`
	LogRedaction   bool     `yaml:"log_redaction"`
	ProtectedPaths []string `yaml:"protected_paths"`
}

type Network struct {
	AllowDomains []string `yaml:"allow_domains"`
}

type Rule struct {
	ID         string    `yaml:"id"`
	Taxonomy   string    `yaml:"taxonomy,omitempty"`
	Match      Match     `yaml:"match"`
	Decision   Decision  `yaml:"decision"`
	Confidence float64   `yaml:"confidence,omitempty"`
	Reason     string    `yaml:"reason"`
	Tests      *RuleTest `yaml:"tests,omitempty"` // inline TP/TN test cases
}

// RuleTest holds inline test cases for a rule. TP commands must trigger the rule;
// TN commands must NOT trigger it. Used by TestRuleYAMLTests to validate every rule.
type RuleTest struct {
	TP []string `yaml:"tp"`           // true positives: commands that MUST fire the rule
	TN []string `yaml:"tn,omitempty"` // true negatives: commands that must NOT fire the rule
}

type Match struct {
	CommandExact        string   `yaml:"command_exact,omitempty"`
	CommandPrefix       []string `yaml:"command_prefix,omitempty"`
	CommandRegex        string   `yaml:"command_regex,omitempty"`
	CommandRegexExclude string   `yaml:"command_regex_exclude,omitempty"`
	// CommandIntentExclude lists IntentClassifier labels that suppress this
	// rule. Any-match: if any listed label is set on the command, the rule
	// is skipped. Replaces the {{DOC_CONTEXT}} regex macro for new rules.
	// Valid labels are defined in internal/analyzer/intent.go (currently
	// is_bash_comment, is_doc_text, in_heredoc, is_self_mgmt). Unknown
	// labels cause policy load to fail — typos are not silently ignored.
	CommandIntentExclude []string `yaml:"command_intent_exclude,omitempty"`
	// CommandIntentDowngrade lists IntentClassifier labels that DOWNGRADE this
	// rule's BLOCK/REQUIRE_APPROVAL to AUDIT (instead of suppressing it) when the
	// match sits only in statements carrying one of these labels — e.g. a
	// sensitive-string literal inside a gh/git --body/--message argument, which
	// documents a pattern rather than executing an access (#2843). Same
	// per-statement scoping and label validation as CommandIntentExclude; the
	// downgraded finding is still AUDITed (logged), so there is no false negative.
	CommandIntentDowngrade []string `yaml:"command_intent_downgrade,omitempty"`
	// CommandPositionExclude lists syntactic POSITIONS at which this rule's
	// match is not evidence: `loop_wordlist`, the word list of a
	// `for NAME in …` clause whose loop variable never reaches a position
	// that could open, run, or retain it (#3376); or `search_needle`, the
	// PATTERN operand of a grep-family invocation — a search term compared
	// against file content, never a target (#3382).
	//
	// It is a different question from CommandIntentExclude, not a variant of
	// it. An intent label classifies the whole command's TEXT ("these
	// arguments are a commit message"); a position label asks where the rule's
	// own match landed in the parsed command, which is the only thing that can
	// answer "is this path a filesystem target or a string being searched
	// for?". Valid labels are defined in internal/analyzer/position.go;
	// unknown labels fail policy load.
	CommandPositionExclude []string         `yaml:"command_position_exclude,omitempty"`
	Structural             *StructuralMatch `yaml:"structural,omitempty"`
	Dataflow               *DataflowMatch   `yaml:"dataflow,omitempty"`
	Semantic               *SemanticMatch   `yaml:"semantic,omitempty"`
	Stateful               *StatefulMatch   `yaml:"stateful,omitempty"`
	// Context gates a rule on the runtime execution environment (issue #3291).
	// It is a precondition, not a matcher: it decides whether the rule APPLIES,
	// not what text it matches, so it must be combined with a command_regex /
	// command_prefix / command_exact predicate. Currently only supported on
	// such regex-family rules — BuildAnalyzerPipeline rejects a context gate on
	// a structural/dataflow/semantic/stateful rule at load time rather than
	// letting it silently no-op (the recurring "inert match field" trap).
	Context *ContextMatch `yaml:"context,omitempty"`
}

// ContextMatch gates a rule on the runtime execution context. Today it carries
// a single dimension — CI/CD-ness — as a tri-state pointer mirroring the
// StructuralMatch.HasPipe convention:
//
//	ci: true   → rule applies ONLY inside a CI/CD runner (tighten posture when
//	             input provenance is untrusted / the agent is attacker-facing)
//	ci: false  → rule applies ONLY outside CI (rare; reserved for symmetry)
//	(unset)    → no CI gate
//
// The CI signal itself is detected by internal/execenv from environment
// variables and supplied to the engine via SetExecContext — see that package
// for the threat rationale (OWASP Agentic Security & Governance v2.01 p.65).
type ContextMatch struct {
	CI *bool `yaml:"ci,omitempty"`
}

// StructuralMatch defines a rule that matches against the parsed shell AST
// rather than raw command strings. This is more robust than regex because
// it handles flag reordering, sudo wrapping, and long-form flags.
type StructuralMatch struct {
	// Command identification
	Executable StringOrList `yaml:"executable,omitempty"` // exact match: "rm" or ["rm", "unlink"]
	SubCommand string       `yaml:"subcommand,omitempty"` // e.g., "install" for "npm install"

	// Flag predicates (short or long form, e.g., "r" matches both -r and --recursive)
	FlagsAll  []string `yaml:"flags_all,omitempty"`  // must have ALL of these
	FlagsAny  []string `yaml:"flags_any,omitempty"`  // must have at least ONE
	FlagsNone []string `yaml:"flags_none,omitempty"` // must NOT have any of these

	// Argument predicates (glob patterns on positional args)
	ArgsAny  []string `yaml:"args_any,omitempty"`  // any positional arg matches any glob
	ArgsNone []string `yaml:"args_none,omitempty"` // no positional arg matches any of these

	// Pipe analysis
	HasPipe         *bool    `yaml:"has_pipe,omitempty"`           // command contains a pipe operator
	PipeTo          []string `yaml:"pipe_to,omitempty"`            // RHS of pipe is one of these executables
	PipeToFlagsNone []string `yaml:"pipe_to_flags_none,omitempty"` // don't match if pipe_to segment has any of these flags
	PipeFrom        []string `yaml:"pipe_from,omitempty"`          // LHS of pipe is one of these executables

	// Modifiers
	Negate bool `yaml:"negate,omitempty"` // invert match (for ALLOW overrides)
}

// DataflowMatch defines a rule that matches source→sink data flows through
// pipes, redirects, and command substitutions. Inspired by classical taint
// analysis: source (where data comes from) → via (transforms) → sink (where it goes).
type DataflowMatch struct {
	Source DataflowEndpoint `yaml:"source"`           // data origin
	Sink   DataflowEndpoint `yaml:"sink"`             // data destination
	Via    []string         `yaml:"via,omitempty"`    // optional transform commands in between
	Negate bool             `yaml:"negate,omitempty"` // invert match
}

// DataflowEndpoint describes one end of a data flow (source or sink).
type DataflowEndpoint struct {
	Type     string   `yaml:"type,omitempty"`     // pre-classified: "credential", "sensitive", "zero", "network", "device", "cron"
	Paths    []string `yaml:"paths,omitempty"`    // glob patterns on file paths
	Commands []string `yaml:"commands,omitempty"` // command names
}

// SemanticMatch defines a rule that matches against the command's classified
// intent. Runs after the built-in semantic analyzer, matching against the
// accumulated ctx.Intents. This enables decision overrides based on intent.
type SemanticMatch struct {
	Intent    string   `yaml:"intent,omitempty"`     // exact intent category match
	IntentAny []string `yaml:"intent_any,omitempty"` // any of these intent categories
	RiskMin   string   `yaml:"risk_min,omitempty"`   // minimum risk level: "critical" > "high" > "medium" > "low" > "info"
	Negate    bool     `yaml:"negate,omitempty"`     // invert match
}

// StatefulMatch defines a rule that matches multi-step attack chains within
// a compound command. Each step in the chain matches a segment, connected
// by operators (&&, ||, ;, |).
type StatefulMatch struct {
	Chain  []ChainStep `yaml:"chain"`            // ordered sequence of steps
	Negate bool        `yaml:"negate,omitempty"` // invert match
}

// ChainStep is one step in a stateful chain pattern.
type ChainStep struct {
	ExecutableAny []string `yaml:"executable_any,omitempty"` // segment executable is one of these
	FlagsAny      []string `yaml:"flags_any,omitempty"`      // segment has at least one of these flags
	FlagsNone     []string `yaml:"flags_none,omitempty"`     // segment must NOT have any of these flags
	ArgsAny       []string `yaml:"args_any,omitempty"`       // any positional arg matches glob
	Operator      string   `yaml:"operator,omitempty"`       // operator connecting to next step: "&&", "||", ";", "|"
}

// StringOrList allows YAML fields to accept either a single string or a list.
// "rm" → ["rm"], ["rm", "unlink"] → ["rm", "unlink"]
type StringOrList []string

func (s *StringOrList) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var single string
	if err := unmarshal(&single); err == nil {
		*s = []string{single}
		return nil
	}
	var list []string
	if err := unmarshal(&list); err != nil {
		return err
	}
	*s = list
	return nil
}

// DataLabel defines a customer-configured sensitive data pattern.
// Used by both the shell analyzer pipeline and MCP content scanning.
type DataLabel struct {
	ID         string             `yaml:"id"`
	Name       string             `yaml:"name"`
	Decision   Decision           `yaml:"decision"`
	Confidence float64            `yaml:"confidence,omitempty"`
	Reason     string             `yaml:"reason"`
	Patterns   []DataLabelPattern `yaml:"patterns"`
	ScanScope  *DataLabelScope    `yaml:"scan_scope,omitempty"`
}

// DataLabelPattern defines a single detection method within a data label.
type DataLabelPattern struct {
	Regex         string   `yaml:"regex,omitempty"`
	Keywords      []string `yaml:"keywords,omitempty"`
	CaseSensitive bool     `yaml:"case_sensitive,omitempty"`
	Context       string   `yaml:"context,omitempty"`
	Validator     string   `yaml:"validator,omitempty"`
}

// DataLabelScope controls which tool calls are scanned by a data label.
//
// Shell is a tri-state (pointer) for opting shell commands in/out of scoped
// labels (BUG-DL-004). When nil, a label with any Tools or Directions filter
// set is treated as MCP-scoped and does NOT match shell commands. Set
// shell: true to explicitly include shell commands alongside MCP tool calls,
// or shell: false to exclude shell regardless of other filters.
type DataLabelScope struct {
	Tools        []string `yaml:"tools,omitempty"`
	Directions   []string `yaml:"directions,omitempty"`
	MaxScanBytes int      `yaml:"max_scan_bytes,omitempty"`
	Shell        *bool    `yaml:"shell,omitempty"`
}

type EvalResult struct {
	Decision       Decision `json:"decision"`
	TriggeredRules []string `json:"rules,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	// TaxonomyRefs holds the taxonomy node ids of the rules behind this
	// decision (deduped, empties dropped). Built-in intercepts that have no
	// taxonomy entry (protected-path, unicode-*, enterprise-self-protect)
	// contribute nothing rather than a placeholder — an unresolvable ref is
	// worse than an absent one for attestation. Issue #3111.
	TaxonomyRefs []string `json:"taxonomy,omitempty"`
	Explanation  string   `json:"explanation,omitempty"`
	// OriginalDecision is set only when audit-only mode (issue #1952)
	// downgrades a BLOCK or REQUIRE_APPROVAL to AUDIT. It carries the
	// pre-downgrade decision out to the audit-log emitter so the SaaS can
	// show "would have blocked." Empty in enforce mode and in audit-only
	// mode when no downgrade happened (ALLOW/AUDIT pass through untouched).
	OriginalDecision Decision `json:"original_decision,omitempty"`
}
