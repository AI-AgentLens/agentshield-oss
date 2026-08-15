package mcp

import "strings"

// ScanErrorMessage checks a JSON-RPC error message string for prompt injection
// directives, credential harvesting instructions, or behavioural manipulation patterns.
// MCP servers can embed adversarial payloads in error.message text that agents
// receive and process during error handling.
//
// Returns the PoisonSignal and description of the first match, or empty strings if clean.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-error-message-injection
func ScanErrorMessage(text string) (signal PoisonSignal, detail string) {
	if text == "" {
		return "", ""
	}
	lower := strings.ToLower(text)

	// Check pattern groups in priority order (highest-confidence first).
	// Reuses the same groups as description_scanner.go for consistent detection.
	for _, p := range hiddenInstructionPatterns {
		if p.re.MatchString(lower) {
			return SignalHiddenInstructions, p.description
		}
	}
	for _, p := range credentialHarvestPatterns {
		if p.re.MatchString(lower) {
			return SignalCredentialHarvest, p.description
		}
	}
	for _, p := range exfiltrationPatterns {
		if p.re.MatchString(lower) {
			return SignalExfiltrationIntent, p.description
		}
	}
	for _, p := range stealthPatterns {
		if p.re.MatchString(lower) {
			return SignalStealthInstruction, p.description
		}
	}
	for _, p := range behavioralManipulationPatterns {
		if p.re.MatchString(lower) {
			return SignalBehavioralManipulation, p.description
		}
	}
	return "", ""
}
