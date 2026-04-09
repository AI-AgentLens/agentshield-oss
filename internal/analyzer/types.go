package analyzer

import "github.com/AI-AgentLens/agentshield/internal/shellparse"

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

	// Enrichments added by analyzers (downstream layers can read these)
	Parsed       *ParsedCommand  // set by structural analyzer (or reused from normalizer)
	Intents      []CommandIntent // set by semantic analyzer
	DataFlows    []DataFlow      // set by dataflow analyzer (Phase 3)
	SessionState *SessionState   // set by stateful analyzer (Phase 4)
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
