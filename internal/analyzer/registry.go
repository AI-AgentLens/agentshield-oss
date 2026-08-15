package analyzer

// Registry is an ordered collection of analyzers that runs them in sequence,
// threading the AnalysisContext through each layer. Each analyzer enriches
// the context and produces findings. The Combiner merges all findings into
// a final CombinedResult.
type Registry struct {
	analyzers []Analyzer
	combiner  *Combiner
}

// NewRegistry creates an analyzer registry with the given analyzers and combiner.
// Analyzers are executed in the order provided.
func NewRegistry(analyzers []Analyzer, combiner *Combiner) *Registry {
	if combiner == nil {
		combiner = NewCombiner(StrategyMostRestrictive)
	}
	return &Registry{
		analyzers: analyzers,
		combiner:  combiner,
	}
}

// RunAll executes all registered analyzers in order, collects findings,
// and returns the combined result. The defaultDecision is a string (e.g., "AUDIT")
// to avoid importing the policy package.
func (r *Registry) RunAll(ctx *AnalysisContext, defaultDecision string) CombinedResult {
	var allFindings []Finding

	for _, a := range r.analyzers {
		findings := a.Analyze(ctx)
		allFindings = append(allFindings, findings...)
	}

	return r.combiner.Combine(allFindings, defaultDecision)
}

// Analyzers returns the list of registered analyzers (for inspection/testing).
func (r *Registry) Analyzers() []Analyzer {
	return r.analyzers
}
