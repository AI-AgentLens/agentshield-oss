package analyzer

import (
	"testing"
)

func TestRegistry_RunAll_OrderMatters(t *testing.T) {
	// Structural must run before semantic (semantic reads ctx.Parsed)
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()
	registry := NewRegistry(
		[]Analyzer{structural, semantic},
		NewCombiner(StrategyMostRestrictive),
	)

	ctx := &AnalysisContext{RawCommand: "shred /dev/sda"}
	result := registry.RunAll(ctx, "AUDIT")

	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for shred /dev/sda, got %s", result.Decision)
	}
	if ctx.Parsed == nil {
		t.Error("expected ctx.Parsed to be set by structural analyzer")
	}
}

func TestRegistry_RunAll_DefaultDecisionWhenNoFindings(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()
	registry := NewRegistry(
		[]Analyzer{structural, semantic},
		NewCombiner(StrategyMostRestrictive),
	)

	ctx := &AnalysisContext{RawCommand: "echo hello"}
	result := registry.RunAll(ctx, "AUDIT")

	if result.Decision != "AUDIT" {
		t.Errorf("expected default AUDIT, got %s", result.Decision)
	}
}

func TestRegistry_RunAll_FullPipeline(t *testing.T) {
	regexRules := []RegexRule{
		{ID: "block-rm-root", Decision: "BLOCK", Regex: `^(rm|sudo rm)\s+-rf\s+/(\s|$)`, Reason: "rm -rf /"},
	}
	regex := NewRegexAnalyzer(regexRules)
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()
	registry := NewRegistry(
		[]Analyzer{regex, structural, semantic},
		NewCombiner(StrategyMostRestrictive),
	)

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"rm -rf / (regex+structural)", "rm -rf /", "BLOCK"},
		{"rm --recursive --force / (structural only)", "rm --recursive --force /", "BLOCK"},
		{"shred /dev/sda (semantic only)", "shred /dev/sda", "BLOCK"},
		{"echo hello (default)", "echo hello", "AUDIT"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := &AnalysisContext{RawCommand: tt.command}
			result := registry.RunAll(ctx, "AUDIT")
			if result.Decision != tt.want {
				t.Errorf("command %q: got %s, want %s (rules: %v)",
					tt.command, result.Decision, tt.want, result.TriggeredRules)
			}
		})
	}
}

func TestRegistry_Analyzers(t *testing.T) {
	structural := NewStructuralAnalyzer(2)
	semantic := NewSemanticAnalyzer()
	registry := NewRegistry([]Analyzer{structural, semantic}, nil)

	analyzers := registry.Analyzers()
	if len(analyzers) != 2 {
		t.Fatalf("expected 2 analyzers, got %d", len(analyzers))
	}
	if analyzers[0].Name() != "structural" {
		t.Errorf("expected first analyzer to be structural, got %s", analyzers[0].Name())
	}
	if analyzers[1].Name() != "semantic" {
		t.Errorf("expected second analyzer to be semantic, got %s", analyzers[1].Name())
	}
}
