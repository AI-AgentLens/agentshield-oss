// Package guardian provides an optional analysis layer that detects prompt
// injection signals, obfuscated payloads, and context-aware threats that
// deterministic regex/structural/semantic rules cannot catch.
//
// Architecture:
//
//	GuardianProvider (interface)
//	  ├── HeuristicProvider  — ships built-in, zero dependencies
//	  └── LLMProvider        — future: wraps Ollama / OpenAI-compatible API
//
//	GuardianAnalyzer         — adapts any GuardianProvider to analyzer.Analyzer
//	                           so it plugs into the 6-layer pipeline.
package guardian

// Signal represents a single security signal detected by the guardian.
// Signals are the atomic output; the GuardianAnalyzer maps them to Findings.
type Signal struct {
	// ID is a short, unique identifier (e.g., "instruction_override").
	ID string

	// Category groups related signals (e.g., "prompt-injection", "obfuscation").
	Category string

	// Severity indicates impact: "critical", "high", "medium", "low".
	Severity string

	// Confidence is 0.0–1.0 how certain the provider is about this signal.
	Confidence float64

	// Description is a human-readable explanation of why this signal fired.
	Description string
}

// GuardianRequest is the input to a GuardianProvider.
type GuardianRequest struct {
	// RawCommand is the shell command being evaluated.
	RawCommand string

	// AgentContext is optional context about what the agent is doing.
	// Empty string means no context was provided.
	AgentContext string

	// PriorDecision is the pipeline's decision before the guardian runs.
	// The guardian can escalate but never downgrade.
	PriorDecision string

	// PriorSignals are tags/reasons from upstream analyzers.
	PriorSignals []string
}

// GuardianResponse is the output from a GuardianProvider.
type GuardianResponse struct {
	// Signals detected in this command.
	Signals []Signal

	// SuggestedDecision is the guardian's recommendation: "ALLOW", "AUDIT", "BLOCK".
	// The GuardianAnalyzer enforces escalation-only semantics (never downgrades).
	SuggestedDecision string

	// Explanation is a human-readable summary combining all signals.
	Explanation string
}

// GuardianProvider is the interface for any guardian implementation.
// The heuristic provider ships built-in; an LLM provider can be added later.
type GuardianProvider interface {
	// Name returns the provider identifier (e.g., "heuristic", "ollama").
	Name() string

	// Analyze inspects the request and returns detected signals + a suggested decision.
	Analyze(req GuardianRequest) (GuardianResponse, error)
}
