package guardian

import (
	"github.com/security-researcher-ca/agentshield/internal/analyzer"
)

// GuardianAnalyzer adapts a GuardianProvider to the analyzer.Analyzer interface
// so it can be plugged into the pipeline as the 6th layer.
//
// Escalation semantics: the guardian can only escalate decisions, never downgrade.
// ALLOW → AUDIT or BLOCK, AUDIT → BLOCK, BLOCK stays BLOCK.
type GuardianAnalyzer struct {
	provider GuardianProvider
}

// NewGuardianAnalyzer creates a pipeline-compatible analyzer wrapping a provider.
func NewGuardianAnalyzer(provider GuardianProvider) *GuardianAnalyzer {
	return &GuardianAnalyzer{provider: provider}
}

func (g *GuardianAnalyzer) Name() string { return "guardian" }

// Analyze runs the guardian provider and converts signals into pipeline Findings.
// Each signal becomes a separate Finding so the combiner can evaluate them individually.
func (g *GuardianAnalyzer) Analyze(ctx *analyzer.AnalysisContext) []analyzer.Finding {
	req := GuardianRequest{
		RawCommand: ctx.RawCommand,
	}

	resp, err := g.provider.Analyze(req)
	if err != nil {
		// Guardian failure is non-fatal: log and return no findings.
		// The deterministic pipeline still provides baseline protection.
		return nil
	}

	if len(resp.Signals) == 0 {
		return nil
	}

	var findings []analyzer.Finding
	for _, sig := range resp.Signals {
		decision := signalToDecision(sig)
		findings = append(findings, analyzer.Finding{
			AnalyzerName: "guardian",
			RuleID:       "guardian-" + sig.ID,
			Decision:     decision,
			Confidence:   sig.Confidence,
			Reason:       sig.Description,
			TaxonomyRef:  signalToTaxonomy(sig),
			Tags:         []string{"guardian", sig.Category},
		})
	}

	return findings
}

// signalToDecision maps a signal's severity to a pipeline decision.
func signalToDecision(sig Signal) string {
	switch sig.Severity {
	case "critical":
		return "BLOCK"
	case "high":
		return "BLOCK"
	case "medium":
		return "AUDIT"
	case "low":
		return "AUDIT"
	default:
		return "AUDIT"
	}
}

// signalToTaxonomy maps guardian signal categories to taxonomy references.
// This allows the combiner to correlate guardian findings with other analyzers.
func signalToTaxonomy(sig Signal) string {
	switch sig.Category {
	case "prompt-injection":
		return "unauthorized-execution/prompt-injection/" + sig.ID
	case "security-bypass":
		return "unauthorized-execution/security-bypass/" + sig.ID
	case "obfuscation":
		return "unauthorized-execution/obfuscation/" + sig.ID
	case "code-execution":
		return "unauthorized-execution/code-execution/" + sig.ID
	case "data-exfiltration":
		return "data-exfiltration/bulk-transfer/" + sig.ID
	case "credential-exposure":
		return "credential-exposure/inline-secret/" + sig.ID
	default:
		return "guardian/" + sig.Category + "/" + sig.ID
	}
}
