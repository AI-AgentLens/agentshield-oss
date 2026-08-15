package policy

import (
	"fmt"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/guardian"
)

// BuildAnalyzerPipeline creates a full analyzer registry from the engine's policy rules.
// The pipeline runs: regex → structural → semantic, combined with most_restrictive strategy.
// This is the standard pipeline for production use.
//
// Returns an error if the data label engine fails to initialize (e.g., invalid
// customer regex or unknown validator name). Per BUG-DL-007, init errors are
// surfaced to callers instead of silently disabling Layer 7.
func BuildAnalyzerPipeline(pol *Policy, maxParseDepth int) (*analyzer.Registry, error) {
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
		// Honor user opt-out from ~/.agentshield/policy.yaml `disable_rules:`.
		// Skipping at registration is cleaner than filtering findings later —
		// disabled rules never get evaluated, never produce findings, never
		// show up in audit logs as "fired then suppressed."
		if pol.IsRuleDisabled(r.ID) {
			continue
		}

		// Validate intent-exclude labels at load time — silent typos would
		// suppress nothing and produce stealth FPs. Fail loud instead.
		for _, label := range r.Match.CommandIntentExclude {
			if !analyzer.IsValidIntentLabel(label) {
				return nil, fmt.Errorf("rule %q: unknown intent label %q in command_intent_exclude", r.ID, label)
			}
		}
		// Same validation for downgrade labels — a typo would silently never
		// downgrade, reinstating the FP the rule opted out of.
		for _, label := range r.Match.CommandIntentDowngrade {
			if !analyzer.IsValidIntentLabel(label) {
				return nil, fmt.Errorf("rule %q: unknown intent label %q in command_intent_downgrade", r.ID, label)
			}
		}

		// CI-context gate validation (issue #3291): match.context is a
		// precondition on a regex-family predicate, not a matcher of its own.
		// Reject it on a structural/dataflow/semantic/stateful rule at load
		// time — those analyzers do not consult the gate, so silently accepting
		// it would ship a rule whose CI scoping does nothing (the recurring
		// "inert match field" trap CLAUDE.md warns about). Fail loud instead.
		hasRegexFamily := r.Match.CommandExact != "" || len(r.Match.CommandPrefix) > 0 || r.Match.CommandRegex != ""
		if r.Match.Context != nil {
			if !hasRegexFamily {
				return nil, fmt.Errorf("rule %q: match.context requires a command_regex/command_prefix/command_exact predicate — it is not supported on structural/dataflow/semantic/stateful rules", r.ID)
			}
			if r.Match.Structural != nil || r.Match.Dataflow != nil || r.Match.Semantic != nil || r.Match.Stateful != nil {
				return nil, fmt.Errorf("rule %q: match.context cannot be combined with a structural/dataflow/semantic/stateful match — the gate would apply only to the regex portion", r.ID)
			}
		}

		// Regex/prefix/exact match → RegexAnalyzer
		if hasRegexFamily {
			regexRules = append(regexRules, analyzer.RegexRule{
				ID:              r.ID,
				Decision:        string(r.Decision),
				Confidence:      r.Confidence,
				Reason:          r.Reason,
				Taxonomy:        r.Taxonomy,
				Exact:           r.Match.CommandExact,
				Prefixes:        r.Match.CommandPrefix,
				Regex:           r.Match.CommandRegex,
				RegexExclude:    r.Match.CommandRegexExclude,
				IntentExclude:   r.Match.CommandIntentExclude,
				IntentDowngrade: r.Match.CommandIntentDowngrade,
				RequireCI:       contextRequireCI(r.Match),
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
	// Layer 2.5: substitute constant `Name=value` assignments through the AST
	// so split-concat bypasses (P1=~/.ssh; P2=id_rsa; cat $P1/$P2) surface a
	// concrete path the engine can re-check after the pipeline. Stateless,
	// produces no findings — pure enrichment of ctx.MaterializedPaths.
	substitution := analyzer.NewSubstitutionAnalyzer()
	semantic := analyzer.NewSemanticAnalyzer()
	semantic.SetUserRules(semanticRules)
	dataflow := analyzer.NewDataflowAnalyzer()
	dataflow.SetUserRules(dataflowRules)
	stateful := analyzer.NewStatefulAnalyzer()
	stateful.SetUserRules(statefulRules)
	guard := guardian.NewGuardianAnalyzer(guardian.NewHeuristicProvider())

	// IntentClassifier runs first so ctx.CommandFacts is populated for every
	// downstream analyzer. Like SubstitutionAnalyzer, it produces no findings
	// — pure enrichment. Rules opt into label-based exclusion via YAML
	// command_intent_exclude (replacing the {{DOC_CONTEXT}} regex macro).
	intentClassifier := analyzer.NewIntentClassifier()

	// ORDERING COUPLING: structural is the single parser-enricher — it populates
	// ctx.Parsed for everything after it. semantic, dataflow, and stateful all
	// silently no-op when ctx.Parsed == nil, so structural MUST run before them.
	// intentClassifier and substitution are enrichment-only (produce no findings).
	analyzers := []analyzer.Analyzer{intentClassifier, regex, structural, substitution, semantic, dataflow, stateful, guard}

	// Runtime skill-artifact hash verification (Comply#3029 / #2950). Runs
	// after structural so ctx.Parsed is populated for script-path extraction.
	// Conditional-append like the data-label analyzer: NewArtifactHashAnalyzer
	// returns nil unless AGENTSHIELD_ARTIFACT_MANIFEST names a loadable
	// manifest, so per-command cost is zero when the feature is off.
	if art := analyzer.NewArtifactHashAnalyzer(); art != nil {
		analyzers = append(analyzers, art)
	}

	// Conditionally add data label analyzer (Layer 7) when labels are configured.
	// Zero cost when DataLabels is empty — no analyzer instantiated.
	if len(pol.DataLabels) > 0 {
		dlConfigs := convertDataLabels(pol.DataLabels)
		engine, err := datalabel.NewEngine(dlConfigs)
		if err != nil {
			// Surface the init failure — silent fail-open leaves the customer
			// with zero Layer 7 protection and no actionable error (BUG-DL-007).
			return nil, fmt.Errorf("data label engine init failed: %w", err)
		}
		if engine != nil {
			analyzers = append(analyzers, analyzer.NewDataLabelAnalyzer(engine))
		}
	}

	return analyzer.NewRegistry(
		analyzers,
		analyzer.NewCombiner(analyzer.StrategyMostRestrictive),
	), nil
}

// contextRequireCI extracts the CI-context gate (issue #3291) from a Match for
// the RegexAnalyzer. Returns nil (no gate) when match.context or its ci: field
// is absent, so an ungated rule behaves exactly as before.
func contextRequireCI(m Match) *bool {
	if m.Context == nil {
		return nil
	}
	return m.Context.CI
}

// convertStructuralRule converts a policy.Rule with a StructuralMatch into
// an analyzer.StructuralRule (crossing the package boundary without import cycles).
func convertStructuralRule(r Rule) analyzer.StructuralRule {
	sm := r.Match.Structural
	return analyzer.StructuralRule{
		ID:              r.ID,
		Decision:        string(r.Decision),
		Confidence:      r.Confidence,
		Reason:          r.Reason,
		Taxonomy:        r.Taxonomy,
		Executable:      []string(sm.Executable),
		SubCommand:      sm.SubCommand,
		FlagsAll:        sm.FlagsAll,
		FlagsAny:        sm.FlagsAny,
		FlagsNone:       sm.FlagsNone,
		ArgsAny:         sm.ArgsAny,
		ArgsNone:        sm.ArgsNone,
		HasPipe:         sm.HasPipe,
		PipeTo:          sm.PipeTo,
		PipeToFlagsNone: sm.PipeToFlagsNone,
		PipeFrom:        sm.PipeFrom,
		Negate:          sm.Negate,
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

// convertDataLabels converts policy.DataLabel YAML types to engine-side
// datalabel.DataLabelConfig types (crossing the package boundary).
func convertDataLabels(labels []DataLabel) []datalabel.DataLabelConfig {
	configs := make([]datalabel.DataLabelConfig, len(labels))
	for i, dl := range labels {
		cfg := datalabel.DataLabelConfig{
			ID:         dl.ID,
			Name:       dl.Name,
			Decision:   string(dl.Decision),
			Confidence: dl.Confidence,
			Reason:     dl.Reason,
			Patterns:   make([]datalabel.PatternConfig, len(dl.Patterns)),
		}
		if cfg.Confidence == 0 {
			cfg.Confidence = 0.90
		}
		for j, p := range dl.Patterns {
			cfg.Patterns[j] = datalabel.PatternConfig{
				Regex:         p.Regex,
				Keywords:      p.Keywords,
				CaseSensitive: p.CaseSensitive,
				Context:       p.Context,
				Validator:     p.Validator,
			}
		}
		if dl.ScanScope != nil {
			cfg.ScanScope = datalabel.ScanScopeConfig{
				Tools:        dl.ScanScope.Tools,
				Directions:   dl.ScanScope.Directions,
				MaxScanBytes: dl.ScanScope.MaxScanBytes,
				Shell:        dl.ScanScope.Shell,
			}
		}
		configs[i] = cfg
	}
	return configs
}

// NewEngineWithAnalyzers creates an engine with the full analyzer pipeline enabled.
func NewEngineWithAnalyzers(p *Policy, maxParseDepth int) (*Engine, error) {
	engine, err := NewEngine(p)
	if err != nil {
		return nil, err
	}
	registry, err := BuildAnalyzerPipeline(p, maxParseDepth)
	if err != nil {
		return nil, err
	}
	engine.SetRegistry(registry)
	return engine, nil
}
