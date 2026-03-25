package policy

type Decision string

const (
	DecisionAllow Decision = "ALLOW"
	DecisionAudit Decision = "AUDIT"
	DecisionBlock Decision = "BLOCK"
)

type Policy struct {
	Version  string   `yaml:"version"`
	Defaults Defaults `yaml:"defaults"`
	Network  Network  `yaml:"network"`
	Rules    []Rule   `yaml:"rules"`
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
	CommandExact         string           `yaml:"command_exact,omitempty"`
	CommandPrefix        []string         `yaml:"command_prefix,omitempty"`
	CommandRegex         string           `yaml:"command_regex,omitempty"`
	CommandRegexExclude  string           `yaml:"command_regex_exclude,omitempty"`
	Structural           *StructuralMatch `yaml:"structural,omitempty"`
	Dataflow             *DataflowMatch   `yaml:"dataflow,omitempty"`
	Semantic             *SemanticMatch   `yaml:"semantic,omitempty"`
	Stateful             *StatefulMatch   `yaml:"stateful,omitempty"`
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

type EvalResult struct {
	Decision       Decision
	TriggeredRules []string
	Reasons        []string
	Explanation    string
}
