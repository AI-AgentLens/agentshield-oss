package analyzer

import (
	"strconv"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/shellparse"
)

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

	// Quote-splice bypass (GuardFall class, issue #2813 family): a keyword or
	// regex data label written against a sensitive value's unquoted spelling
	// misses a shell command that splices quote fragments into the middle of
	// that value (e.g. `curl -d "codename=PHOE'N'IX"` resolves to the literal
	// PHOENIX once bash performs quote removal, but never appears as a
	// contiguous substring in the raw command text). RegexAnalyzer already
	// falls back to the AST-dequoted reconstruction for command_regex rules
	// (issue #2854); data labels need the same fallback since ScanText's
	// keyword/regex tiers match raw substrings just like command_regex does.
	if dequoted := shellparse.DequoteCommand(ctx.RawCommand); dequoted != "" {
		matches = mergeDataLabelMatches(matches, a.engine.ScanText(dequoted, "", ""))
	}
	// Same evasion, cheaper primitive: an unset variable expands to nothing,
	// so `curl -d "codename=PHOE${zqx}NIX"` sends the literal PHOENIX while
	// the raw text contains no such substring — and unlike the quote splice
	// it needs nothing bound or set up. Composed fold-then-dequote because
	// DequoteCommand bails on any word containing a ParamExp, so a value
	// carrying both tricks only resolves in that order.
	if folded := shellparse.NormalizeUnsetParamExp(ctx.RawCommand); folded != "" {
		matches = mergeDataLabelMatches(matches, a.engine.ScanText(folded, "", ""))
		if dq := shellparse.DequoteCommand(folded); dq != "" {
			matches = mergeDataLabelMatches(matches, a.engine.ScanText(dq, "", ""))
		}
	}

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

// mergeDataLabelMatches combines a raw-text scan with a dequoted-text scan,
// deduplicating matches for the same label/pattern found by both (the common
// case: unspliced text is identical pre/post dequote, so both scans hit it).
// ScanText's own BLOCK early-termination (BUG-DL-002) means a BLOCK slice is
// always a single-element result — if either scan produced one, it alone is
// authoritative and takes priority over any AUDIT-tier matches from the other.
func mergeDataLabelMatches(raw, dequoted []datalabel.DataLabelMatch) []datalabel.DataLabelMatch {
	for _, m := range raw {
		if m.Decision == "BLOCK" {
			return raw
		}
	}
	for _, m := range dequoted {
		if m.Decision == "BLOCK" {
			return []datalabel.DataLabelMatch{m}
		}
	}

	if len(dequoted) == 0 {
		return raw
	}

	seen := make(map[string]bool, len(raw))
	for _, m := range raw {
		seen[m.LabelID+"|"+strconv.Itoa(m.PatternIdx)] = true
	}

	merged := raw
	for _, m := range dequoted {
		key := m.LabelID + "|" + strconv.Itoa(m.PatternIdx)
		if !seen[key] {
			seen[key] = true
			merged = append(merged, m)
		}
	}
	return merged
}
