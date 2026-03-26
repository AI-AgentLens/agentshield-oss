package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/analyzer"
	unicheck "github.com/security-researcher-ca/agentshield/internal/unicode"
)

type Engine struct {
	policy       *Policy
	homeDir      string
	registry     *analyzer.Registry // optional: when set, uses full analyzer pipeline
	regexCache   map[string]*regexp.Regexp
}

func NewEngine(p *Policy) (*Engine, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		homeDir = ""
	}
	e := &Engine{policy: p, homeDir: homeDir, regexCache: make(map[string]*regexp.Regexp)}
	// Pre-compile all rule regexes at initialization
	for _, rule := range p.Rules {
		if rule.Match.CommandRegex != "" {
			if re, err := regexp.Compile(rule.Match.CommandRegex); err == nil {
				e.regexCache[rule.Match.CommandRegex] = re
			}
		}
		excl := expandExcludePattern(rule.Match.CommandRegexExclude)
		if excl != "" {
			if re, err := regexp.Compile(excl); err == nil {
				e.regexCache[excl] = re
			}
		}
	}
	return e, nil
}

// SetRegistry attaches an analyzer pipeline to the engine.
// When set, Evaluate() uses the full pipeline (regex+structural+semantic+combiner)
// instead of the built-in regex-only matching.
func (e *Engine) SetRegistry(r *analyzer.Registry) {
	e.registry = r
}

// Policy returns the engine's policy (for inspection/testing).
func (e *Engine) Policy() *Policy {
	return e.policy
}

func (e *Engine) Evaluate(command string, paths []string) EvalResult {
	return e.EvaluateWithParsed(command, paths, nil)
}

// EvaluateWithParsed is like Evaluate but accepts a pre-parsed command AST
// from the normalizer, avoiding redundant parsing in the structural analyzer.
func (e *Engine) EvaluateWithParsed(command string, paths []string, parsed *analyzer.ParsedCommand) EvalResult {
	result := EvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Built-in: Unicode smuggling detection (runs before all rules)
	uniScan := unicheck.Scan(command)
	if !uniScan.Clean {
		hasBlockLevel := false
		for _, threat := range uniScan.Threats {
			result.TriggeredRules = append(result.TriggeredRules, "unicode-"+threat.Category)
			result.Reasons = append(result.Reasons, threat.Description)
			if threat.Severity == "block" {
				hasBlockLevel = true
			}
		}
		if hasBlockLevel {
			result.Decision = DecisionBlock
		} else {
			result.Decision = DecisionAudit
		}
		result.Explanation = buildExplanation(result)
		return result
	}

	if blocked, rule := e.checkProtectedPaths(paths); blocked {
		result.Decision = DecisionBlock
		result.TriggeredRules = append(result.TriggeredRules, "protected-path")
		result.Reasons = append(result.Reasons, fmt.Sprintf("Access to protected path denied: %s", rule))
		result.Explanation = buildExplanation(result)
		return result
	}

	// If an analyzer registry is set, use the full pipeline.
	// Otherwise, fall back to built-in regex-only matching.
	if e.registry != nil {
		ctx := &analyzer.AnalysisContext{
			RawCommand: command,
			Paths:      paths,
			Parsed:     parsed,
		}
		combined := e.registry.RunAll(ctx, string(e.policy.Defaults.Decision))
		result.Decision = Decision(combined.Decision)
		result.TriggeredRules = combined.TriggeredRules
		result.Reasons = combined.Reasons
		result.Explanation = buildExplanation(result)
		return result
	}

	// Fallback: built-in regex-only matching (backward compatible).
	// Evaluate ALL matching rules and pick the highest severity.
	var bestDecision Decision
	var bestRules []string
	var bestReasons []string
	matched := false

	for _, rule := range e.policy.Rules {
		if e.matchRule(command, rule) {
			if !matched || decisionSeverity(rule.Decision) > decisionSeverity(bestDecision) {
				bestDecision = rule.Decision
				bestRules = []string{rule.ID}
				bestReasons = []string{rule.Reason}
				matched = true
			} else if decisionSeverity(rule.Decision) == decisionSeverity(bestDecision) {
				bestRules = append(bestRules, rule.ID)
				bestReasons = append(bestReasons, rule.Reason)
			}
		}
	}

	if matched {
		result.Decision = bestDecision
		result.TriggeredRules = bestRules
		result.Reasons = bestReasons
	}

	result.Explanation = buildExplanation(result)
	return result
}

// decisionSeverity returns a numeric severity for priority comparison.
// Higher number = more restrictive decision.
func decisionSeverity(d Decision) int {
	switch d {
	case DecisionBlock:
		return 3
	case DecisionAudit:
		return 2
	case DecisionAllow:
		return 1
	default:
		return 0
	}
}

func (e *Engine) matchRule(command string, rule Rule) bool {
	if rule.Match.CommandExact != "" {
		if command == rule.Match.CommandExact {
			return true
		}
	}

	for _, prefix := range rule.Match.CommandPrefix {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}

	if rule.Match.CommandRegex != "" {
		re := e.compiledRegex(rule.Match.CommandRegex)
		if re != nil && re.MatchString(command) {
			excl := expandExcludePattern(rule.Match.CommandRegexExclude)
			if excl != "" {
				reExcl := e.compiledRegex(excl)
				if reExcl != nil && reExcl.MatchString(command) {
					return false
				}
			}
			return true
		}
	}

	return false
}

// compiledRegex returns a pre-compiled regex from cache, or compiles on demand.
func (e *Engine) compiledRegex(pattern string) *regexp.Regexp {
	if re, ok := e.regexCache[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	e.regexCache[pattern] = re
	return re
}

func (e *Engine) checkProtectedPaths(paths []string) (bool, string) {
	for _, path := range paths {
		expandedPath := e.expandPath(path)
		for _, pattern := range e.policy.Defaults.ProtectedPaths {
			expandedPattern := e.expandPath(pattern)
			if matchGlob(expandedPath, expandedPattern) {
				return true, pattern
			}
		}
	}
	return false, ""
}

func (e *Engine) expandPath(path string) string {
	if strings.HasPrefix(path, "~/") && e.homeDir != "" {
		return filepath.Join(e.homeDir, path[2:])
	}
	if strings.HasPrefix(path, "~") && e.homeDir != "" {
		return e.homeDir
	}
	return path
}

func matchGlob(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		if !strings.HasPrefix(path, prefix+"/") {
			return false
		}
		remainder := strings.TrimPrefix(path, prefix+"/")
		return !strings.Contains(remainder, "/")
	}

	matched, _ := filepath.Match(pattern, path)
	return matched
}

func buildExplanation(result EvalResult) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "Decision: %s\n", result.Decision)

	if len(result.TriggeredRules) > 0 {
		fmt.Fprintf(&sb, "Triggered rules: %s\n", strings.Join(result.TriggeredRules, ", "))
	}

	if len(result.Reasons) > 0 {
		sb.WriteString("Reasons:\n")
		for _, reason := range result.Reasons {
			fmt.Fprintf(&sb, "  - %s\n", reason)
		}
	}

	return sb.String()
}
