package datalabel

// DataLabelConfig is the analyzer-side representation of a customer-defined
// data label. Converted from policy.DataLabel by FromPolicyLabels.
type DataLabelConfig struct {
	ID         string
	Name       string
	Decision   string
	Confidence float64
	Reason     string
	Patterns   []PatternConfig
	ScanScope  ScanScopeConfig
}

// PatternConfig defines a single detection pattern within a data label.
// A pattern uses exactly one detection method: Regex or Keywords.
type PatternConfig struct {
	Regex         string   // compiled at engine init
	Keywords      []string // fed into Aho-Corasick automaton
	CaseSensitive bool
	Context       string // optional regex — nearby text must match to confirm
	Validator     string // "luhn" etc — post-match confirmation
}

// ScanScopeConfig controls which tool calls and commands are scanned.
// Empty Tools/Directions mean "scan everything" when no scope is set.
//
// When Tools or Directions is set, the label is considered MCP-scoped and
// shell commands are NOT matched by default (see BUG-DL-004). Use the Shell
// field to explicitly opt shell commands in or out.
type ScanScopeConfig struct {
	Tools        []string // MCP tool name globs (empty = all tools)
	Directions   []string // "outbound", "inbound" (empty = any direction)
	MaxScanBytes int      // 0 = default (256KB)

	// Shell is a tri-state for shell-command matching:
	//   nil  = default (match shell only when no Tools/Directions filters are set)
	//   true = always match shell commands, regardless of Tools/Directions
	//   false = never match shell commands
	Shell *bool
}

// DataLabelMatch represents a confirmed detection of sensitive data.
type DataLabelMatch struct {
	LabelID    string
	LabelName  string
	Decision   string
	Confidence float64
	Reason     string
	PatternIdx int    // which pattern within the label matched
	MatchText  string // the matched substring (truncated for audit)
}

// defaultMaxScanBytes is the default maximum bytes to scan per text input.
const defaultMaxScanBytes = 256 * 1024 // 256KB

// maxMatchTextLen is the maximum length of MatchText stored in results.
// Longer matches are truncated to avoid bloating audit logs.
const maxMatchTextLen = 64

// contextWindowBytes is the number of bytes on each side of a regex match
// used to evaluate the pattern's context regex. Per BUG-DL-001, context must
// be checked against a window around the match — not the full document —
// or the context check provides no FP discrimination.
const contextWindowBytes = 200
