package mcp

import (
	"strings"
)

// SamplingSignal identifies a type of threat found in a sampling/createMessage request.
type SamplingSignal string

const (
	SignalSamplingInjection  SamplingSignal = "sampling_injection"  // instruction override / system prompt injection
	SignalSamplingCredential SamplingSignal = "sampling_credential"  // credential extraction query
	SignalSamplingExfil      SamplingSignal = "sampling_exfiltration" // data exfiltration instruction
)

// SamplingFinding records one detected threat signal in a sampling message.
type SamplingFinding struct {
	Signal   SamplingSignal `json:"signal"`
	Detail   string         `json:"detail"`
	Role     string         `json:"role"`
	TextSnip string         `json:"text_snip,omitempty"` // first 80 chars of matching text
}

// SamplingScanResult is the result of scanning a sampling/createMessage request.
type SamplingScanResult struct {
	Blocked  bool              `json:"blocked"`
	Findings []SamplingFinding `json:"findings,omitempty"`
}

// ScanSamplingMessages scans sampling/createMessage request messages for injection,
// credential extraction, and exfiltration patterns. All sampling requests are logged
// (the caller always audits), but only those with detected threats are blocked.
func ScanSamplingMessages(params *SamplingCreateMessageParams) SamplingScanResult {
	var result SamplingScanResult

	// Scan each message in the sampling request
	for _, msg := range params.Messages {
		text := msg.Content.Text
		if text == "" {
			continue
		}
		lower := strings.ToLower(text)
		snip := text
		if len(snip) > 80 {
			snip = snip[:80] + "..."
		}

		// Check for instruction override / prompt injection patterns
		// (reuses the same pattern sets as description_scanner.go)
		for _, p := range hiddenInstructionPatterns {
			if p.re.MatchString(lower) {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingInjection,
					Detail:   p.description,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break // one finding per pattern category per message
			}
		}

		// Check for behavioral manipulation / jailbreak patterns
		for _, p := range behavioralManipulationPatterns {
			if p.re.MatchString(lower) {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingInjection,
					Detail:   p.description,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}

		// Check for credential harvesting patterns
		for _, p := range credentialHarvestPatterns {
			if p.re.MatchString(lower) {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingCredential,
					Detail:   p.description,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}

		// Check for exfiltration instruction patterns
		for _, p := range exfiltrationPatterns {
			if p.re.MatchString(lower) {
				result.Findings = append(result.Findings, SamplingFinding{
					Signal:   SignalSamplingExfil,
					Detail:   p.description,
					Role:     msg.Role,
					TextSnip: snip,
				})
				break
			}
		}
	}

	// Also scan the systemPrompt field if present
	if params.SystemPrompt != "" {
		lower := strings.ToLower(params.SystemPrompt)
		snip := params.SystemPrompt
		if len(snip) > 80 {
			snip = snip[:80] + "..."
		}

		for _, patterns := range [][]signalPattern{hiddenInstructionPatterns, behavioralManipulationPatterns} {
			for _, p := range patterns {
				if p.re.MatchString(lower) {
					result.Findings = append(result.Findings, SamplingFinding{
						Signal:   SignalSamplingInjection,
						Detail:   "systemPrompt: " + p.description,
						Role:     "system",
						TextSnip: snip,
					})
					break
				}
			}
		}
	}

	result.Blocked = len(result.Findings) > 0
	return result
}
