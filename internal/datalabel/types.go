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
// Empty fields mean "scan everything".
type ScanScopeConfig struct {
	Tools        []string // MCP tool name globs (empty = all tools)
	Directions   []string // "outbound", "inbound" (empty = outbound only)
	MaxScanBytes int      // 0 = default (256KB)
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
