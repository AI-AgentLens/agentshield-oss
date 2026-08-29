package mcp

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
	forms := newProseForms(text)

	// Check pattern groups in priority order (highest-confidence first).
	// Reuses the same groups as description_scanner.go for consistent detection.
	for _, p := range hiddenInstructionPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalHiddenInstructions, p.description + note
		}
	}
	for _, p := range credentialHarvestPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalCredentialHarvest, p.description + note
		}
	}
	for _, p := range exfiltrationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalExfiltrationIntent, p.description + note
		}
	}
	for _, p := range stealthPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalStealthInstruction, p.description + note
		}
	}
	for _, p := range behavioralManipulationPatterns {
		if note, ok := proseMatchNote(p.re, forms); ok {
			return SignalBehavioralManipulation, p.description + note
		}
	}
	return "", ""
}
