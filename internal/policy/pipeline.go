package policy

import (
	"github.com/security-researcher-ca/agentshield/internal/analyzer"
	"github.com/security-researcher-ca/agentshield/internal/guardian"
)

// BuildAnalyzerPipeline creates a full analyzer registry from the engine's policy rules.
// The pipeline runs: regex → structural → semantic, combined with most_restrictive strategy.
// This is the standard pipeline for production use.
func BuildAnalyzerPipeline(pol *Policy, maxParseDepth int) *analyzer.Registry {
	if maxParseDepth <= 0 {
		maxParseDepth = 2
	}

	// Convert policy rules to analyzer-side types.
	// Each rule goes to the analyzer matching its match type.
	var regexRules []analyzer.RegexRule
	var structuralRules []analyzer.StructuralRule
	var dataflowRules []analyzer.DataflowRule
	var semanticRules []analyzer.UserSemanticRule
	var statefulRules []analyzer.StatefulRule

	for _, r := range pol.Rules {
		// Regex/prefix/exact match → RegexAnalyzer
		if r.Match.CommandExact != "" || len(r.Match.CommandPrefix) > 0 || r.Match.CommandRegex != "" {
			regexRules = append(regexRules, analyzer.RegexRule{
				ID:           r.ID,
				Decision:     string(r.Decision),
				Confidence:   r.Confidence,
				Reason:       r.Reason,
				Taxonomy:     r.Taxonomy,
				Exact:        r.Match.CommandExact,
				Prefixes:     r.Match.CommandPrefix,
				Regex:        r.Match.CommandRegex,
				RegexExclude: r.Match.CommandRegexExclude,
			})
		}

		// Structural match → StructuralAnalyzer
		if r.Match.Structural != nil {
			structuralRules = append(structuralRules, convertStructuralRule(r))
		}

		// Dataflow match → DataflowAnalyzer
		if r.Match.Dataflow != nil {
			dataflowRules = append(dataflowRules, convertDataflowRule(r))
		}

		// Semantic match → SemanticAnalyzer
		if r.Match.Semantic != nil {
			semanticRules = append(semanticRules, convertSemanticRule(r))
		}

		// Stateful match → StatefulAnalyzer
		if r.Match.Stateful != nil {
			statefulRules = append(statefulRules, convertStatefulRule(r))
		}
	}

	regex := analyzer.NewRegexAnalyzer(regexRules)
	structural := analyzer.NewStructuralAnalyzer(maxParseDepth)
	structural.SetUserRules(structuralRules)
	semantic := analyzer.NewSemanticAnalyzer()
	semantic.SetUserRules(semanticRules)
	dataflow := analyzer.NewDataflowAnalyzer()
	dataflow.SetUserRules(dataflowRules)
	stateful := analyzer.NewStatefulAnalyzer(nil) // nil = compound-command-only mode
	stateful.SetUserRules(statefulRules)
	guard := guardian.NewGuardianAnalyzer(guardian.NewHeuristicProvider())

	return analyzer.NewRegistry(
		[]analyzer.Analyzer{regex, structural, semantic, dataflow, stateful, guard},
		analyzer.NewCombiner(analyzer.StrategyMostRestrictive),
	)
}

// convertStructuralRule converts a policy.Rule with a StructuralMatch into
// an analyzer.StructuralRule (crossing the package boundary without import cycles).
func convertStructuralRule(r Rule) analyzer.StructuralRule {
	sm := r.Match.Structural
	return analyzer.StructuralRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Confidence: r.Confidence,
		Reason:     r.Reason,
		Taxonomy:   r.Taxonomy,
		Executable: []string(sm.Executable),
		SubCommand: sm.SubCommand,
		FlagsAll:   sm.FlagsAll,
		FlagsAny:   sm.FlagsAny,
		FlagsNone:  sm.FlagsNone,
		ArgsAny:    sm.ArgsAny,
		ArgsNone:   sm.ArgsNone,
		HasPipe:         sm.HasPipe,
		PipeTo:          sm.PipeTo,
		PipeToFlagsNone: sm.PipeToFlagsNone,
		PipeFrom:        sm.PipeFrom,
		Negate:     sm.Negate,
	}
}

// convertDataflowRule converts a policy.Rule with a DataflowMatch into
// an analyzer.DataflowRule.
func convertDataflowRule(r Rule) analyzer.DataflowRule {
	dm := r.Match.Dataflow
	return analyzer.DataflowRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Confidence: r.Confidence,
		Reason:     r.Reason,
		Taxonomy:   r.Taxonomy,
		Source: analyzer.DataflowRuleEndpoint{
			Type:     dm.Source.Type,
			Paths:    dm.Source.Paths,
			Commands: dm.Source.Commands,
		},
		Sink: analyzer.DataflowRuleEndpoint{
			Type:     dm.Sink.Type,
			Paths:    dm.Sink.Paths,
			Commands: dm.Sink.Commands,
		},
		Via:    dm.Via,
		Negate: dm.Negate,
	}
}

// convertSemanticRule converts a policy.Rule with a SemanticMatch into
// an analyzer.UserSemanticRule.
func convertSemanticRule(r Rule) analyzer.UserSemanticRule {
	sm := r.Match.Semantic
	return analyzer.UserSemanticRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Confidence: r.Confidence,
		Reason:     r.Reason,
		Taxonomy:   r.Taxonomy,
		Intent:     sm.Intent,
		IntentAny:  sm.IntentAny,
		RiskMin:    sm.RiskMin,
		Negate:     sm.Negate,
	}
}

// convertStatefulRule converts a policy.Rule with a StatefulMatch into
// an analyzer.StatefulRule.
func convertStatefulRule(r Rule) analyzer.StatefulRule {
	sm := r.Match.Stateful
	chain := make([]analyzer.ChainStepRule, len(sm.Chain))
	for i, step := range sm.Chain {
		chain[i] = analyzer.ChainStepRule{
			ExecutableAny: step.ExecutableAny,
			FlagsAny:      step.FlagsAny,
			FlagsNone:     step.FlagsNone,
			ArgsAny:       step.ArgsAny,
			Operator:      step.Operator,
		}
	}
	return analyzer.StatefulRule{
		ID:         r.ID,
		Decision:   string(r.Decision),
		Confidence: r.Confidence,
		Reason:     r.Reason,
		Taxonomy:   r.Taxonomy,
		Chain:      chain,
		Negate:     sm.Negate,
	}
}

// NewEngineWithAnalyzers creates an engine with the full analyzer pipeline enabled.
func NewEngineWithAnalyzers(p *Policy, maxParseDepth int) (*Engine, error) {
	engine, err := NewEngine(p)
	if err != nil {
		return nil, err
	}
	engine.SetRegistry(BuildAnalyzerPipeline(p, maxParseDepth))
	return engine, nil
}
