package analyzer

import "github.com/AI-AgentLens/agentshield/internal/datalabel"

// DataLabelAnalyzer is the 7th pipeline layer. It scans commands for
// customer-defined sensitive data patterns (PII, project codenames, etc.).
// When no data labels are configured, this analyzer is not registered
// in the pipeline — zero overhead.
type DataLabelAnalyzer struct {
	engine *datalabel.Engine
}

// NewDataLabelAnalyzer creates a data label analyzer wrapping the given engine.
// The engine must not be nil (caller checks via NewEngine return).
func NewDataLabelAnalyzer(engine *datalabel.Engine) *DataLabelAnalyzer {
	return &DataLabelAnalyzer{engine: engine}
}

// Name returns the analyzer identifier.
func (a *DataLabelAnalyzer) Name() string { return "datalabel" }

// Analyze scans the raw command for sensitive data patterns.
// It does not enrich AnalysisContext — findings are self-contained.
func (a *DataLabelAnalyzer) Analyze(ctx *AnalysisContext) []Finding {
	// Shell commands: no tool name, no direction
	matches := a.engine.ScanText(ctx.RawCommand, "", "")
	if len(matches) == 0 {
		return nil
	}

	findings := make([]Finding, len(matches))
	for i, m := range matches {
		confidence := m.Confidence
		if confidence == 0 {
			confidence = 0.90
		}

		findings[i] = Finding{
			AnalyzerName: "datalabel",
			RuleID:       "dl-" + m.LabelID,
			Decision:     m.Decision,
			Confidence:   confidence,
			Reason:       m.Reason,
			TaxonomyRef:  "data-protection/pii/" + m.LabelID,
		}
	}

	return findings
}
