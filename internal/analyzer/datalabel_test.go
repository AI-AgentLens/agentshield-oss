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
