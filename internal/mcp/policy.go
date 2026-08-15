package mcp

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// regexCache memoizes compiled regexes for MCP rule evaluation. The MCP
// evaluator runs on every tool call and walks ~1250 rules; before this
// cache, each call recompiled the same `ToolNameRegex` / `ArgumentRegexPatterns`
// / `URIRegex` patterns from scratch (4 callsites in this file alone), which
// dominated evaluation cost on the hot path. A sync.Map keyed by the source
// pattern is correct because:
//   - regex patterns are immutable strings; same input → same result
//   - regexp.Regexp is safe for concurrent use after compilation
//   - cache misses cost one extra Compile + Store; subsequent hits are O(1)
//
// We cache the compile error too, so a malformed pattern doesn't get
// re-attempted on every call. Pre-PR-#1987 this was a real per-call
// performance hotspot: 246 ToolNameRegex + 80 ArgumentRegexPatterns sites
// across the shipped packs, each compiled-then-thrown-away on every MCP
// tool call.
var regexCache sync.Map // map[string]*regexpCacheEntry

type regexpCacheEntry struct {
	re  *regexp.Regexp
	err error
}

// cachedRegexp returns the compiled regex for pattern, compiling and
// caching on first use. Safe for concurrent callers. Returns (nil, err)
// for malformed patterns; the error is cached so repeated bad inputs
// don't re-attempt compilation.
func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	if v, ok := regexCache.Load(pattern); ok {
		entry := v.(*regexpCacheEntry)
		return entry.re, entry.err
	}
	re, err := regexp.Compile(pattern)
	entry := &regexpCacheEntry{re: re, err: err}
	// LoadOrStore handles the race where two goroutines compile the same
	// pattern concurrently: only the first Store wins, the second discards
	// its compiled value. Both callers see the same final entry.
	actual, _ := regexCache.LoadOrStore(pattern, entry)
	final := actual.(*regexpCacheEntry)
	return final.re, final.err
}

// MCPPolicy defines MCP-specific security policy loaded from YAML.
type MCPPolicy struct {
	Defaults         MCPDefaults         `yaml:"defaults"`
	BlockedTools     []string            `yaml:"blocked_tools,omitempty"`
	BlockedResources []string            `yaml:"blocked_resources,omitempty"`
	Rules            []MCPRule           `yaml:"rules,omitempty"`
	ResourceRules    []ResourceRule      `yaml:"resource_rules,omitempty"`
	ValueLimits      []ValueLimitRule    `yaml:"value_limits,omitempty"`
	StructuralRules  []MCPStructuralRule `yaml:"structural_rules,omitempty"`
	SemanticRules    []MCPSemanticRule   `yaml:"semantic_rules,omitempty"`
	DataLabels       []policy.DataLabel  `yaml:"data_labels,omitempty"`
}

// MCPDefaults defines the default decision for MCP tool calls.
type MCPDefaults struct {
	Decision policy.Decision `yaml:"decision"`
}

// MCPRule defines a single MCP policy rule.
type MCPRule struct {
	ID         string          `yaml:"id"`
	Match      MCPMatch        `yaml:"match"`
	Decision   policy.Decision `yaml:"decision"`
	Reason     string          `yaml:"reason"`
	Tests      *MCPRuleTest    `yaml:"tests,omitempty"`      // inline TP/TN test cases
	Engine     string          `yaml:"engine,omitempty"`     // sentinel: Go engine name (skip pattern matching)
	Taxonomy   string          `yaml:"taxonomy,omitempty"`   // taxonomy reference
	Suggested  string          `yaml:"suggested,omitempty"`  // remediation guidance for UI
	Confidence float64         `yaml:"confidence,omitempty"` // advisory: author's confidence in this rule's precision (metadata only — not read by the evaluator)
}

// MCPRuleTest holds inline test cases for an MCP rule.
type MCPRuleTest struct {
	TP []MCPTestCase `yaml:"tp"`           // true positives: tool calls that MUST fire the rule
	TN []MCPTestCase `yaml:"tn,omitempty"` // true negatives: tool calls that must NOT fire
}

// MCPTestCase represents a single test tool call.
type MCPTestCase struct {
	Tool string                 `yaml:"tool"`
	Args map[string]interface{} `yaml:"args,omitempty"`
	// ArgsB64 is an opaque base64-of-JSON alternative to Args (issue #2925).
	// It lets detection-rule authors keep raw attack payloads out of the
	// session transcript — when an AI agent authors a dense batch of TP/TN
	// fixtures inline, the accumulated attack phrasing trips Claude Code's
	// session safety-classifier and blocks local `go` verification. Storing
	// the payload as an opaque blob removes that trigger at the source.
	// Mutually exclusive with Args. TEST-ONLY: runtime tool-call arguments
	// come from the MCP proxy, never from a rule's Tests.
	ArgsB64 string `yaml:"args_b64,omitempty"`
	// Description is an optional human-readable annotation for the test case
	// (advisory only — not read by the test harness).
	Description string `yaml:"description,omitempty"`
	// Result carries a simulated tool call result (content/structuredContent/
	// _meta) for engine-based sentinel rules whose TP/TN fixtures describe a
	// server RESPONSE rather than a tool call argument. These rules are
	// pattern-matched by dedicated Go signal functions with their own direct
	// Go test coverage, not by matchRule, so this field is metadata for
	// documentation/attestation purposes — the test harness skips engine
	// rules rather than executing Result against matchRule.
	Result map[string]interface{} `yaml:"result,omitempty"`
	// ToolsList carries a simulated tools/list response (tool definitions
	// with name/description/outputSchema) for engine-based sentinel rules
	// whose fixtures describe tool *registration* metadata rather than a
	// single tool call. Same skip-by-engine semantics as Result above.
	ToolsList []map[string]interface{} `yaml:"tools_list,omitempty"`
}

// ResolvedArgs returns the test case's arguments, decoding ArgsB64 when set.
// It is the single canonical decode path for fixture indirection (issue #2925)
// so the test harness and any future consumer stay consistent. The result is
// never nil.
//
// ArgsB64 is base64 of a JSON object; numbers therefore decode as float64
// (JSON semantics) rather than int. That is immaterial for the string-valued
// tool arguments (paths, content, URLs) these rules match on — use plain
// inline Args for the rare numeric-argument case.
func (tc MCPTestCase) ResolvedArgs() (map[string]interface{}, error) {
	if tc.ArgsB64 != "" {
		if tc.Args != nil {
			return nil, fmt.Errorf("test case for tool %q sets both args and args_b64 — use exactly one", tc.Tool)
		}
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(tc.ArgsB64))
		if err != nil {
			return nil, fmt.Errorf("args_b64 for tool %q: invalid base64: %w", tc.Tool, err)
		}
		var args map[string]interface{}
		if err := json.Unmarshal(raw, &args); err != nil {
			return nil, fmt.Errorf("args_b64 for tool %q: decoded bytes are not a JSON object: %w", tc.Tool, err)
		}
		if args == nil {
			args = map[string]interface{}{}
		}
		return args, nil
	}
	if tc.Args == nil {
		return map[string]interface{}{}, nil
	}
	return tc.Args, nil
}

// ResourceRule defines a rule for resources/read requests.
type ResourceRule struct {
	ID         string          `yaml:"id"`
	Match      ResourceMatch   `yaml:"match"`
	Decision   policy.Decision `yaml:"decision"`
	Reason     string          `yaml:"reason"`
	Taxonomy   string          `yaml:"taxonomy,omitempty"`   // taxonomy reference (advisory metadata — see issue #2869)
	Tests      *MCPRuleTest    `yaml:"tests,omitempty"`      // inline TP/TN test cases (advisory — no dedicated test harness executes these yet, see issue #2869)
	Confidence float64         `yaml:"confidence,omitempty"` // advisory: author's confidence in this rule's precision
}

// ResourceMatch defines conditions for a resource rule.
type ResourceMatch struct {
	URIPattern string `yaml:"uri_pattern,omitempty"` // glob pattern on URI
	URIRegex   string `yaml:"uri_regex,omitempty"`   // regex on URI
	Scheme     string `yaml:"scheme,omitempty"`      // exact scheme match (file, postgres, etc.)
}

// MCPMatch defines the conditions for an MCP rule to trigger.
type MCPMatch struct {
	ToolName                string              `yaml:"tool_name,omitempty"`                 // exact tool name
	ToolNameRegex           string              `yaml:"tool_name_regex,omitempty"`           // regex on tool name
	ToolNameAny             []string            `yaml:"tool_name_any,omitempty"`             // any of these tool names
	ArgumentPatterns        map[string]string   `yaml:"argument_patterns,omitempty"`         // key=arg name, value=glob pattern on arg value
	ArgumentPatternsAny     map[string][]string `yaml:"argument_patterns_any,omitempty"`     // key=arg name, value=list of glob patterns; rule matches if ANY pattern matches (OR logic)
	ArgumentRegexPatterns   map[string]string   `yaml:"argument_regex_patterns,omitempty"`   // key=arg name, value=regex pattern on arg value (use for non-path text matching)
	ExcludeArgumentPatterns map[string][]string `yaml:"exclude_argument_patterns,omitempty"` // key=arg name, value=list of glob patterns to exclude (if any match, rule does NOT fire)
	ArgumentNotContains     map[string][]string `yaml:"argument_not_contains,omitempty"`     // key=arg name, value=literal substrings (case-insensitive). Negative/absence predicate: rule fires only if the arg value contains NONE of them. Absent arg ⇒ satisfied. Use for "argument does NOT contain marker X" (e.g. AI-disclosure footers) where regexp negative-lookahead and filepath.Match bracket-globs both fail.
	ToolNameNotPrefixAny    []string            `yaml:"tool_name_not_prefix_any,omitempty"`  // negative tool-name predicate: rule fires only if the tool name starts with NONE of these prefixes. Go's regexp has no negative lookahead, so this is the tool-name equivalent of ArgumentNotContains — prefix (not regex) semantics, cheap and immune to RE2 bounded-repetition perf issues. Use to scope a rule to a namespace (e.g. tool_name_regex: "^mcp__") and then exclude a known-good allowlist within it (issue #2816, declared-baseline / capability-drift enforcement).
	Structural              *MCPStructuralMatch `yaml:"structural,omitempty"`                // structural match predicates
	Semantic                *MCPSemanticMatch   `yaml:"semantic,omitempty"`                  // semantic intent match predicates
	Sequence                *MCPSequenceMatch   `yaml:"sequence,omitempty"`                  // cross-call chain match — evaluated against per-session call history (#2493). When set, the rule is a sequence rule and fires iff the history satisfies the chain.
}

// ValueLimitRule enforces numeric thresholds on tool call arguments.
// Designed to prevent uncontrolled resource commitment — e.g., an agent
// accidentally transferring $250K instead of $4 (see: Lobstar Wilde incident).
type ValueLimitRule struct {
	ID            string          `yaml:"id"`
	ToolPattern   string          `yaml:"tool_pattern,omitempty"`    // glob pattern on tool name
	ToolNameRegex string          `yaml:"tool_name_regex,omitempty"` // regex on tool name
	Argument      string          `yaml:"argument"`                  // argument name to check
	Max           *float64        `yaml:"max,omitempty"`             // block if value > max
	Min           *float64        `yaml:"min,omitempty"`             // block if value < min
	Decision      policy.Decision `yaml:"decision"`                  // BLOCK or AUDIT
	Reason        string          `yaml:"reason,omitempty"`
	Taxonomy      string          `yaml:"taxonomy,omitempty"`   // taxonomy reference (advisory metadata — see issue #2869)
	Tests         *MCPRuleTest    `yaml:"tests,omitempty"`      // inline TP/TN test cases (advisory — no dedicated test harness executes these yet, see issue #2869)
	Confidence    float64         `yaml:"confidence,omitempty"` // advisory: author's confidence in this rule's precision
}

// ValueLimitFinding records a value limit violation.
type ValueLimitFinding struct {
	RuleID   string          `json:"rule_id"`
	ArgName  string          `json:"arg_name"`
	Value    float64         `json:"value"`
	Limit    string          `json:"limit"` // e.g., "max=100"
	Decision policy.Decision `json:"decision"`
	Reason   string          `json:"reason"`
}

// ValueLimitResult holds the outcome of checking tool call arguments
// against all configured value limit rules.
type ValueLimitResult struct {
	Blocked  bool                `json:"blocked"`
	Findings []ValueLimitFinding `json:"findings,omitempty"`
}

// MCPEvalResult holds the outcome of evaluating an MCP tool call.
type MCPEvalResult struct {
	Decision       policy.Decision `json:"decision"`
	TriggeredRules []string        `json:"rules,omitempty"`
	Reasons        []string        `json:"reasons,omitempty"`
	// TaxonomyRef links the result to a taxonomy entry (e.g. for Go-implemented intercepts).
	// Empty for YAML-policy-evaluated results — those carry their refs in
	// TaxonomyRefs below (copied off the matched rules).
	TaxonomyRef string `json:"taxonomy,omitempty"`
	// TaxonomyRefs holds the taxonomy node ids of every YAML rule that
	// contributed to the winning decision (deduped, empties dropped). Use
	// AllTaxonomyRefs to read the merged view including TaxonomyRef, which is
	// what the audit wire carries. Issue #3111.
	TaxonomyRefs []string `json:"taxonomy_refs,omitempty"`
	// OriginalDecision is set when audit-only mode (issue #1952) downgrades
	// a BLOCK or REQUIRE_APPROVAL on this tool call to AUDIT. Empty when no
	// downgrade happened.
	OriginalDecision policy.Decision `json:"original_decision,omitempty"`
}

// AllTaxonomyRefs returns the merged taxonomy view for this result: the
// single-valued TaxonomyRef set by Go-implemented intercepts first, then the
// per-rule refs collected from YAML matches. Deduped, empties dropped, always
// non-nil. This is the accessor the audit wire uses — callers must not read
// only one of the two fields, because a composite MCP decision can populate
// either or both. Issue #3111.
func (r MCPEvalResult) AllTaxonomyRefs() []string {
	merged := make([]string, 0, len(r.TaxonomyRefs)+1)
	if r.TaxonomyRef != "" {
		merged = append(merged, r.TaxonomyRef)
	}
	merged = append(merged, r.TaxonomyRefs...)
	return analyzer.NormalizeTaxonomyRefs(merged)
}

// PolicyEvaluator evaluates MCP tool calls against an MCPPolicy.
type PolicyEvaluator struct {
	policy        *MCPPolicy
	SentinelRules map[string]*MCPRule // indexed by Engine name for O(1) lookup
	// mode mirrors policy.Engine.mode for MCP evaluation. "audit-only"
	// downgrades BLOCK/REQUIRE_APPROVAL to AUDIT with OriginalDecision set.
	// Issue #1952.
	mode string
}

// SetMode sets the enforcement mode. See policy.Engine.SetMode for
// semantics. Unknown values are treated as "enforce" (fail-safe).
func (e *PolicyEvaluator) SetMode(mode string) {
	if e == nil {
		return
	}
	e.mode = mode
}

// applyMCPModeDowngrade collapses interrupting decisions to AUDIT in
// audit-only mode and records the original. Mirrors the shell-side
// applyModeDowngrade. Issue #1952.
func applyMCPModeDowngrade(r MCPEvalResult, mode string) MCPEvalResult {
	if mode != "audit-only" {
		return r
	}
	switch r.Decision {
	case policy.DecisionBlock, policy.DecisionRequireApproval:
		r.OriginalDecision = r.Decision
		r.Decision = policy.DecisionAudit
	}
	return r
}

// NewPolicyEvaluator creates a new evaluator from the given MCP policy.
func NewPolicyEvaluator(p *MCPPolicy) *PolicyEvaluator {
	if p == nil {
		p = &MCPPolicy{
			Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		}
	}
	if p.Defaults.Decision == "" {
		p.Defaults.Decision = policy.DecisionAudit
	}
	sentinels := make(map[string]*MCPRule)
	for i := range p.Rules {
		if p.Rules[i].Engine != "" {
			sentinels[p.Rules[i].Engine] = &p.Rules[i]
		}
	}
	return &PolicyEvaluator{policy: p, SentinelRules: sentinels}
}

// LookupSentinel returns the sentinel rule for the given engine name, or nil if not found.
func (e *PolicyEvaluator) LookupSentinel(engine string) *MCPRule {
	if e == nil || e.SentinelRules == nil {
		return nil
	}
	return e.SentinelRules[engine]
}

// EvaluateToolCall checks a tool call against the MCP policy.
// Returns the most restrictive matching decision.
func (e *PolicyEvaluator) EvaluateToolCall(toolName string, arguments map[string]interface{}) MCPEvalResult {
	return e.EvaluateToolCallFull(toolName, arguments, "")
}

// EvaluateToolCallFull checks a tool call against the MCP policy, including
// the tool description for semantic intent classification.
// Returns the most restrictive matching decision.
func (e *PolicyEvaluator) EvaluateToolCallFull(toolName string, arguments map[string]interface{}, toolDescription string) MCPEvalResult {
	return e.evaluate(toolName, arguments, toolDescription, nil)
}

// EvaluateToolCallWithHistory evaluates a tool call with the per-session MCP
// call history available so cross-call sequence rules (#2493) can match a
// multi-step trajectory (e.g. OSINT reads → LLM generation → bulk send).
// history is oldest-first and should include the current call as its last
// element. With nil history, sequence rules never fire — so EvaluateToolCall
// and EvaluateToolCallFull retain their exact prior (stateless) behavior.
func (e *PolicyEvaluator) EvaluateToolCallWithHistory(toolName string, arguments map[string]interface{}, toolDescription string, history []RecordedCall) MCPEvalResult {
	return e.evaluate(toolName, arguments, toolDescription, history)
}

// evaluate is the shared core for the EvaluateToolCall* entry points. history
// (oldest-first, including the current call) enables sequence rules; pass nil
// for stateless evaluation.
func (e *PolicyEvaluator) evaluate(toolName string, arguments map[string]interface{}, toolDescription string, history []RecordedCall) MCPEvalResult {
	result := MCPEvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Check blocked tools list first (highest priority)
	for _, blocked := range e.policy.BlockedTools {
		if matchToolName(toolName, blocked) {
			return applyMCPModeDowngrade(MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"blocked-tool:" + blocked},
				Reasons:        []string{fmt.Sprintf("Tool %q is in the blocked tools list", toolName)},
			}, e.mode)
		}
	}

	// Evaluate rules — collect all matches, pick highest severity. A rule with
	// a Sequence block is a cross-call sequence rule: it fires iff the session
	// history satisfies the chain (matchSequence is false for nil history, so
	// these rules never fire on the stateless entry points).
	for _, rule := range e.policy.Rules {
		var matched bool
		if rule.Match.Sequence != nil {
			matched = matchSequence(rule.Match.Sequence, history)
		} else {
			matched = e.matchRule(toolName, arguments, rule)
		}
		if matched {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
				result.TaxonomyRefs = firstTaxonomy(rule.Taxonomy)
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
				result.TaxonomyRefs = appendTaxonomy(result.TaxonomyRefs, rule.Taxonomy)
			}
		}
	}

	// Evaluate structural rules — check standalone structural_rules
	for _, rule := range e.policy.StructuralRules {
		if matchStructuralRule(toolName, arguments, rule) {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
				result.TaxonomyRefs = firstTaxonomy(rule.Taxonomy)
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
				result.TaxonomyRefs = appendTaxonomy(result.TaxonomyRefs, rule.Taxonomy)
			}
		}
	}

	// Evaluate semantic rules — classify intent and check against semantic_rules
	if len(e.policy.SemanticRules) > 0 {
		_, matchedSemantic := evaluateSemanticRules(toolName, arguments, toolDescription, e.policy.SemanticRules)
		for _, rule := range matchedSemantic {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
				result.TaxonomyRefs = firstTaxonomy(rule.Taxonomy)
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
				result.TaxonomyRefs = appendTaxonomy(result.TaxonomyRefs, rule.Taxonomy)
			}
		}
	}

	dedupeRulesAndReasons(&result)
	result.TaxonomyRefs = analyzer.NormalizeTaxonomyRefs(result.TaxonomyRefs)
	return applyMCPModeDowngrade(result, e.mode)
}

// firstTaxonomy starts a fresh taxonomy set for a rule that outranked
// everything seen so far — the refs collected at the losing severity are
// discarded along with their rule IDs, so the two stay consistent.
func firstTaxonomy(ref string) []string {
	if ref == "" {
		return nil
	}
	return []string{ref}
}

// appendTaxonomy adds a tying rule's taxonomy ref, skipping the empty ref so
// rules without taxonomy contribute nothing rather than a blank entry.
func appendTaxonomy(refs []string, ref string) []string {
	if ref == "" {
		return refs
	}
	return append(refs, ref)
}

// dedupeRulesAndReasons removes duplicate (RuleID, Reason) entries from the
// evaluator output while preserving first-seen order. This is the second line
// of defense against issue #1628: even if two packs with different Names ship
// rules whose RuleID + Reason text collide, the user-visible output stays
// clean. The pack-level dedupe in the loader handles the more common cause
// (legacy disk packs duplicating embedded ones).
func dedupeRulesAndReasons(r *MCPEvalResult) {
	if len(r.TriggeredRules) <= 1 && len(r.Reasons) <= 1 {
		return
	}
	// Pair-aware dedupe: same RuleID + same Reason collapses to one entry.
	// Different RuleIDs (or same ID with different reason text from different
	// pack versions) are preserved so the user can see them.
	seen := make(map[string]bool, len(r.Reasons))
	rules := make([]string, 0, len(r.TriggeredRules))
	reasons := make([]string, 0, len(r.Reasons))
	n := len(r.Reasons)
	if len(r.TriggeredRules) < n {
		n = len(r.TriggeredRules)
	}
	for i := 0; i < n; i++ {
		key := r.TriggeredRules[i] + "\x00" + r.Reasons[i]
		if seen[key] {
			continue
		}
		seen[key] = true
		rules = append(rules, r.TriggeredRules[i])
		reasons = append(reasons, r.Reasons[i])
	}
	// Preserve any trailing entries when the two slices were uneven (defensive;
	// callers should keep them aligned, but never trust the invariant blindly).
	if len(r.TriggeredRules) > n {
		rules = append(rules, r.TriggeredRules[n:]...)
	}
	if len(r.Reasons) > n {
		reasons = append(reasons, r.Reasons[n:]...)
	}
	r.TriggeredRules = rules
	r.Reasons = reasons
}

func (e *PolicyEvaluator) matchRule(toolName string, arguments map[string]interface{}, rule MCPRule) bool {
	// Sentinel rules are claimed by Go engines, not pattern-matched.
	if rule.Engine != "" {
		return false
	}
	m := rule.Match

	// Tool name matching (if any name matcher is specified, at least one must match)
	nameMatched := false
	nameSpecified := false

	if m.ToolName != "" {
		nameSpecified = true
		if matchToolName(toolName, m.ToolName) {
			nameMatched = true
		}
	}

	if m.ToolNameRegex != "" {
		nameSpecified = true
		re, err := cachedRegexp(m.ToolNameRegex)
		if err == nil && re.MatchString(toolName) {
			nameMatched = true
		}
	}

	if len(m.ToolNameAny) > 0 {
		nameSpecified = true
		for _, name := range m.ToolNameAny {
			if matchToolName(toolName, name) {
				nameMatched = true
				break
			}
		}
	}

	if nameSpecified && !nameMatched {
		return false
	}

	// Negative tool-name prefix predicate — independent AND constraint (not
	// part of the positive OR-group above): the rule fires only if the tool
	// name starts with NONE of the listed prefixes. Typically composed with
	// tool_name_regex to scope the namespace (e.g. "^mcp__") and then carve
	// out a known-good allowlist within it.
	if len(m.ToolNameNotPrefixAny) > 0 {
		for _, prefix := range m.ToolNameNotPrefixAny {
			if prefix != "" && strings.HasPrefix(toolName, prefix) {
				return false
			}
		}
	}

	// Argument pattern matching (all specified patterns must match). Batch/bulk
	// tool calls bundle several targets under one plural array argument
	// ("paths" instead of "path") — resolveFieldValues expands that (and falls
	// back to the plural key when the singular is absent) so the rule fires if
	// ANY one bundled target matches, instead of silently missing the whole
	// call (see resolveFieldValues doc comment / issue #3155).
	if len(m.ArgumentPatterns) > 0 {
		for argName, pattern := range m.ArgumentPatterns {
			values, ok := resolveFieldValues(arguments, argName)
			if !ok {
				return false
			}
			matched := false
			for _, valStr := range values {
				if matchGlob(valStr, pattern) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Argument patterns ANY matching — for each argument, at least one of the
	// listed patterns must match (OR within each argument, AND across arguments).
	// Uses the same glob engine as ArgumentPatterns (with filepath.Clean path normalization).
	if len(m.ArgumentPatternsAny) > 0 {
		for argName, patterns := range m.ArgumentPatternsAny {
			values, ok := resolveFieldValues(arguments, argName)
			if !ok {
				return false
			}
			anyMatched := false
			for _, valStr := range values {
				for _, pattern := range patterns {
					if matchGlob(valStr, pattern) {
						anyMatched = true
						break
					}
				}
				if anyMatched {
					break
				}
			}
			if !anyMatched {
				return false
			}
		}
	}

	// Argument regex pattern matching (all specified patterns must match).
	// Use this for free-form text arguments (e.g., `text` in type_text) where path glob
	// semantics break because * does not match /.
	if len(m.ArgumentRegexPatterns) > 0 {
		for argName, pattern := range m.ArgumentRegexPatterns {
			values, ok := resolveFieldValues(arguments, argName)
			if !ok {
				return false
			}
			re, err := cachedRegexp(pattern)
			if err != nil {
				return false
			}
			matched := false
			for _, valStr := range values {
				if re.MatchString(valStr) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}

	// Exclude argument patterns — if any exclusion pattern matches, the rule does NOT fire.
	// Used to carve out known-safe variants from broad glob patterns (e.g., .env.example from **/.env.*).
	if len(m.ExcludeArgumentPatterns) > 0 {
		for argName, patterns := range m.ExcludeArgumentPatterns {
			values, ok := resolveFieldValues(arguments, argName)
			if !ok {
				continue
			}
			for _, valStr := range values {
				for _, excludePattern := range patterns {
					if matchGlob(valStr, excludePattern) {
						return false
					}
				}
			}
		}
	}

	// Argument NOT-contains (negative / absence predicate) — the rule fires only if,
	// for every specified argument, its serialized value contains NONE of the listed
	// literal substrings (case-insensitive). This is the engine's only way to express
	// "argument does NOT contain marker X": Go's regexp has no negative lookahead, and
	// filepath.Match treats bracket-delimited literals (e.g. [AI-generated]) as character
	// classes, so neither argument_regex_patterns nor exclude_argument_patterns can do it.
	// An absent argument trivially contains nothing → predicate satisfied (cannot suppress).
	if len(m.ArgumentNotContains) > 0 {
		for argName, substrings := range m.ArgumentNotContains {
			values, ok := resolveFieldValues(arguments, argName)
			if !ok {
				continue // absent ⇒ contains none of the markers ⇒ satisfied
			}
			for _, valStr := range values {
				valLower := strings.ToLower(valStr)
				for _, sub := range substrings {
					if sub == "" {
						continue
					}
					if strings.Contains(valLower, strings.ToLower(sub)) {
						return false // a marker is present ⇒ rule must NOT fire (e.g. AI authorship disclosed)
					}
				}
			}
		}
	}

	// Structural match — if specified, it must also match
	if m.Structural != nil {
		if !matchStructural(toolName, arguments, *m.Structural) {
			return false
		}
		// Structural match counts as a specification
		return true
	}

	// If we had name matchers and they matched (or no name matchers were specified)
	// AND all argument patterns matched, the rule matches.
	return nameSpecified || len(m.ArgumentPatterns) > 0 || len(m.ArgumentPatternsAny) > 0 || len(m.ArgumentRegexPatterns) > 0 || len(m.ArgumentNotContains) > 0 || len(m.ToolNameNotPrefixAny) > 0
}

// matchToolName checks if a tool name matches a pattern.
// Supports exact match and simple glob (* suffix).
func matchToolName(name, pattern string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, name)
		return matched
	}
	return name == pattern
}

// matchGlob matches a value against a glob pattern.
// Supports ** for recursive path matching and * for single-level.
//
// Common patterns:
//
//	/etc/**          — matches anything under /etc/
//	**/.ssh/**       — matches any path containing a .ssh directory
//	/home/*/.aws/**  — matches .aws under any user in /home
func matchGlob(value, pattern string) bool {
	if !strings.Contains(pattern, "**") {
		matched, _ := filepath.Match(pattern, value)
		return matched
	}

	// Split both into path components and use recursive matching.
	vParts := splitPath(value)
	pParts := splitPathPattern(pattern)

	return globMatch(vParts, pParts)
}

// globMatch recursively matches value parts against pattern parts.
// "**" in pattern parts matches zero or more path components.
func globMatch(value, pattern []string) bool {
	vi, pi := 0, 0
	for pi < len(pattern) {
		if pattern[pi] == "**" {
			pi++
			// ** at end of pattern matches everything remaining
			if pi >= len(pattern) {
				return true
			}
			// Try matching the rest of the pattern at every position in value
			for vi <= len(value) {
				if globMatch(value[vi:], pattern[pi:]) {
					return true
				}
				vi++
			}
			return false
		}

		if vi >= len(value) {
			return false
		}

		matched, _ := filepath.Match(pattern[pi], value[vi])
		if !matched {
			return false
		}
		vi++
		pi++
	}

	return vi == len(value)
}

// splitPath splits a file path into its directory components.
func splitPath(p string) []string {
	p = filepath.Clean(p)
	if p == "/" || p == "." {
		return nil
	}
	var parts []string
	for {
		dir, file := filepath.Split(p)
		if file != "" {
			parts = append([]string{file}, parts...)
		}
		dir = filepath.Clean(dir)
		if dir == p { // no more progress (reached root or .)
			break
		}
		p = dir
	}
	return parts
}

// splitPathPattern splits a glob pattern into components, preserving "**".
func splitPathPattern(pattern string) []string {
	pattern = strings.TrimPrefix(pattern, "/")
	if pattern == "" {
		return nil
	}
	return strings.Split(pattern, "/")
}

// EvaluateResourceRead checks a resources/read URI against the MCP policy.
func (e *PolicyEvaluator) EvaluateResourceRead(uri string) MCPEvalResult {
	result := MCPEvalResult{
		Decision:       e.policy.Defaults.Decision,
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// Check blocked resources list
	for _, blocked := range e.policy.BlockedResources {
		if matchResourceURI(uri, blocked) {
			return applyMCPModeDowngrade(MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"blocked-resource:" + blocked},
				Reasons:        []string{fmt.Sprintf("Resource URI %q matches blocked pattern %q", uri, blocked)},
			}, e.mode)
		}
	}

	// Evaluate resource rules
	for _, rule := range e.policy.ResourceRules {
		if matchResourceRule(uri, rule) {
			if decisionSeverity(rule.Decision) > decisionSeverity(result.Decision) {
				result.Decision = rule.Decision
				result.TriggeredRules = []string{rule.ID}
				result.Reasons = []string{rule.Reason}
			} else if decisionSeverity(rule.Decision) == decisionSeverity(result.Decision) {
				result.TriggeredRules = append(result.TriggeredRules, rule.ID)
				result.Reasons = append(result.Reasons, rule.Reason)
			}
		}
	}

	// Check config guard on file:// URIs
	if strings.HasPrefix(uri, "file://") {
		path := strings.TrimPrefix(uri, "file://")
		// Use config guard to check if the resource path is protected
		guardResult := CheckConfigGuard("resources/read", map[string]interface{}{"path": path})
		if guardResult.Blocked {
			result.Decision = policy.DecisionBlock
			result.TriggeredRules = append(result.TriggeredRules, "config-file-guard")
			for _, f := range guardResult.Findings {
				result.Reasons = append(result.Reasons, "["+f.Category+"] "+f.Reason)
			}
		}
	}

	return applyMCPModeDowngrade(result, e.mode)
}

// matchResourceURI checks if a URI matches a blocked resource pattern.
func matchResourceURI(uri, pattern string) bool {
	if strings.Contains(pattern, "*") {
		matched, _ := filepath.Match(pattern, uri)
		if matched {
			return true
		}
		// Also try glob matching on the path portion
		if strings.Contains(pattern, "**") {
			uriPath, patternPath := stripURIScheme(uri, pattern)
			vParts := splitPath(uriPath)
			pParts := splitPathPattern(patternPath)
			return globMatch(vParts, pParts)
		}
		return false
	}
	return uri == pattern
}

// stripURIScheme removes a shared "scheme://" prefix (e.g. "file://") from
// both a URI and its glob pattern before path-component splitting.
// splitPath/splitPathPattern assume a filesystem-style absolute path
// ("/a/b/c"); fed a scheme-prefixed URI directly ("file:///a/b/c"),
// filepath.Clean does not recognize "file:" as a root and collapses the
// triple slash unevenly, producing component counts that only happen to
// align for single-segment paths (e.g. "file:///root/.aws/config" matches
// "file:///**/.aws/**" by accident) while silently failing to match the far
// more common multi-segment form ("file:///home/user/.aws/credentials",
// "file:///Users/dev/.aws/credentials") — a real bypass of every uri_pattern
// resource rule, found while authoring inline tests for issue #2941.
// Stripping the scheme first leaves a proper absolute path on both sides so
// splitPath/splitPathPattern behave as they already do for plain filesystem
// argument_patterns.
func stripURIScheme(uri, pattern string) (string, string) {
	idx := strings.Index(pattern, "://")
	if idx < 0 {
		return uri, pattern
	}
	scheme := pattern[:idx+3]
	if !strings.HasPrefix(uri, scheme) {
		return uri, pattern
	}
	return uri[len(scheme):], pattern[len(scheme):]
}

// matchResourceRule checks if a URI matches a resource rule.
func matchResourceRule(uri string, rule ResourceRule) bool {
	m := rule.Match
	matched := false
	specified := false

	if m.URIPattern != "" {
		specified = true
		if matchResourceURI(uri, m.URIPattern) {
			matched = true
		}
	}

	if m.URIRegex != "" {
		specified = true
		re, err := cachedRegexp(m.URIRegex)
		if err == nil && re.MatchString(uri) {
			matched = true
		}
	}

	if m.Scheme != "" {
		specified = true
		if strings.HasPrefix(uri, m.Scheme+"://") {
			matched = true
		}
	}

	if !specified {
		return false
	}
	return matched
}

// CheckValueLimits evaluates tool call arguments against configured value limit
// rules. Returns findings for any arguments that exceed the thresholds.
func (e *PolicyEvaluator) CheckValueLimits(toolName string, arguments map[string]interface{}) ValueLimitResult {
	result := ValueLimitResult{}

	for _, rule := range e.policy.ValueLimits {
		if !matchValueLimitTool(toolName, rule) {
			continue
		}

		numVal, ok := extractNumericArg(arguments, rule.Argument)
		if !ok {
			continue
		}

		violated := false
		limitDesc := ""

		if rule.Max != nil && numVal > *rule.Max {
			violated = true
			limitDesc = fmt.Sprintf("max=%.2f", *rule.Max)
		}
		if rule.Min != nil && numVal < *rule.Min {
			violated = true
			limitDesc = fmt.Sprintf("min=%.2f", *rule.Min)
		}

		if violated {
			reason := rule.Reason
			if reason == "" {
				reason = fmt.Sprintf("Value limit exceeded: %s=%v (%s)", rule.Argument, numVal, limitDesc)
			}
			finding := ValueLimitFinding{
				RuleID:   rule.ID,
				ArgName:  rule.Argument,
				Value:    numVal,
				Limit:    limitDesc,
				Decision: rule.Decision,
				Reason:   reason,
			}
			result.Findings = append(result.Findings, finding)
			if rule.Decision == policy.DecisionBlock {
				result.Blocked = true
			}
		}
	}

	return result
}

// matchValueLimitTool checks if a tool name matches a ValueLimitRule's tool filter.
func matchValueLimitTool(toolName string, rule ValueLimitRule) bool {
	if rule.ToolPattern != "" {
		if matchToolName(toolName, rule.ToolPattern) {
			return true
		}
	}
	if rule.ToolNameRegex != "" {
		re, err := cachedRegexp(rule.ToolNameRegex)
		if err == nil && re.MatchString(toolName) {
			return true
		}
	}
	// If no tool filter specified, rule applies to all tools
	return rule.ToolPattern == "" && rule.ToolNameRegex == ""
}

// extractNumericArg extracts a float64 from a tool call argument by name.
// Supports top-level arguments; returns (value, true) if found and numeric.
//
// Financial/crypto MCP tools (transfer, mint, payment amounts) commonly
// encode numeric values as JSON strings rather than numbers — e.g. to avoid
// float64 precision loss on large token/wei quantities. A value_limits rule
// that only recognized json.Number/float64/int silently never fires against
// this string-typed form, letting an unbounded-transfer BLOCK be bypassed by
// nothing more than the arg's JSON type (issue #2869 test-harness gap
// surfaced this: every mcp-fin-cap-*/mcp-fin-block-negative-* rule's own
// authored TP fixtures used string amounts and were failing silently).
func extractNumericArg(arguments map[string]interface{}, argName string) (float64, bool) {
	val, ok := arguments[argName]
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// EvaluateRootsList checks the roots declared in a roots/list response for
// sensitive filesystem paths. A malicious MCP server may elicit roots that
// encompass credential directories (~/.ssh, ~/.aws, etc.) or the home directory,
// enabling it to read secrets through subsequent tool calls.
//
// BLOCK: root is a known credential directory or its ancestor covers it.
// AUDIT: root is a broad directory (home or system root) that encompasses creds.
//
// Detection is pattern-based (not tied to the current user's HOME) so that it
// works across user accounts and in test environments.
func (e *PolicyEvaluator) EvaluateRootsList(roots []RootInfo) MCPEvalResult {
	result := MCPEvalResult{
		Decision:       policy.DecisionAllow, // roots/list is not subject to the default AUDIT
		TriggeredRules: []string{},
		Reasons:        []string{},
	}

	// sensitiveCredDirNames: final path component names that are credential directories.
	// A root whose last component matches one of these is a direct credential exposure.
	sensitiveCredDirNames := map[string]string{
		".ssh":    "SSH credential directory",
		".aws":    "AWS credential directory",
		".gnupg":  "GPG key directory (~/.gnupg)",
		".kube":   "Kubernetes credential directory",
		".vault":  "HashiCorp Vault credential directory",
		".docker": "Docker credential directory (~/.docker)",
	}

	// sensitiveCredSuffixes: multi-component path suffixes for nested credential dirs.
	// A root whose path ends with one of these is a credential directory.
	sensitiveCredSuffixes := []string{
		"/.config/gcloud",
		"/.config/op",
		"/.config/helm",
	}

	// broadDirs: directories that encompass credential dirs without being one themselves.
	// These are AUDITED rather than blocked.
	broadDirs := []string{
		"/",
		"/home",
		"/Users", // macOS user homes parent
		"/root",  // root account home
		"/etc",   // system configuration
	}

	// Also audit /home/<anything> and /Users/<anything> — user home directories.
	// A home dir encompasses .ssh, .aws, etc. without being a cred dir itself.
	isUserHomeDir := func(p string) bool {
		for _, prefix := range []string{"/home/", "/Users/"} {
			if strings.HasPrefix(p, prefix) {
				// Exactly one more path component (the username), no further slashes
				rest := strings.TrimPrefix(p, prefix)
				if rest != "" && !strings.Contains(rest, "/") {
					return true
				}
			}
		}
		return false
	}

	for _, root := range roots {
		uri := root.URI
		// Normalize: strip file:// prefix and trailing slashes (but preserve "/" root)
		p := strings.TrimPrefix(uri, "file://")
		if p != "/" {
			p = strings.TrimRight(p, "/")
		}
		if p == "" {
			p = "/"
		}

		base := filepath.Base(p)

		// BLOCK: final component is a known credential directory name
		if desc, ok := sensitiveCredDirNames[base]; ok {
			return applyMCPModeDowngrade(MCPEvalResult{
				Decision:       policy.DecisionBlock,
				TriggeredRules: []string{"mcp-roots-block-sensitive-cred-dir"},
				Reasons: []string{
					fmt.Sprintf("MCP root %q is a %s — credential theft via roots privilege escalation (MITRE T1078, T1083, OWASP LLM08).", uri, desc),
				},
				TaxonomyRef: "unauthorized-execution/agentic-attacks/mcp-roots-privilege-escalation",
			}, e.mode)
		}

		// BLOCK: path ends with a sensitive multi-component credential suffix
		for _, suffix := range sensitiveCredSuffixes {
			if strings.HasSuffix(p, suffix) {
				return applyMCPModeDowngrade(MCPEvalResult{
					Decision:       policy.DecisionBlock,
					TriggeredRules: []string{"mcp-roots-block-sensitive-cred-dir"},
					Reasons: []string{
						fmt.Sprintf("MCP root %q ends with credential path %q — potential credential theft via roots privilege escalation (MITRE T1078, T1083, OWASP LLM08).", uri, suffix),
					},
					TaxonomyRef: "unauthorized-execution/agentic-attacks/mcp-roots-privilege-escalation",
				}, e.mode)
			}
		}

		// BLOCK: path is inside a credential directory (path contains /.ssh/ etc.)
		for name := range sensitiveCredDirNames {
			if strings.Contains(p, "/"+name+"/") {
				return applyMCPModeDowngrade(MCPEvalResult{
					Decision:       policy.DecisionBlock,
					TriggeredRules: []string{"mcp-roots-block-sensitive-cred-dir"},
					Reasons: []string{
						fmt.Sprintf("MCP root %q is inside credential directory %q — direct credential access via roots (MITRE T1078, OWASP LLM08).", uri, name),
					},
					TaxonomyRef: "unauthorized-execution/agentic-attacks/mcp-roots-privilege-escalation",
				}, e.mode)
			}
		}

		// AUDIT: broad parent directories that encompass credential dirs
		isBroad := false
		for _, broad := range broadDirs {
			if p == broad {
				isBroad = true
				break
			}
		}
		if !isBroad && isUserHomeDir(p) {
			isBroad = true
		}

		if isBroad && decisionSeverity(policy.DecisionAudit) > decisionSeverity(result.Decision) {
			result.Decision = policy.DecisionAudit
			result.TriggeredRules = []string{"mcp-roots-audit-broad-dir"}
			result.Reasons = []string{
				fmt.Sprintf("MCP root %q is a broad directory that encompasses credential paths — review whether this scope is necessary (OWASP LLM08).", uri),
			}
			result.TaxonomyRef = "unauthorized-execution/agentic-attacks/mcp-roots-privilege-escalation"
		}
	}

	return applyMCPModeDowngrade(result, e.mode)
}

// decisionSeverity mirrors the shell engine's ordering. REQUIRE_APPROVAL slots
// between AUDIT and BLOCK; see internal/policy/engine.go for the rationale.
// Kept in sync because issue #1952's audit-only downgrade treats both BLOCK
// and REQUIRE_APPROVAL the same way.
func decisionSeverity(d policy.Decision) int {
	switch d {
	case policy.DecisionBlock:
		return 4
	case policy.DecisionRequireApproval:
		return 3
	case policy.DecisionAudit:
		return 2
	case policy.DecisionAllow:
		return 1
	default:
		return 0
	}
}
