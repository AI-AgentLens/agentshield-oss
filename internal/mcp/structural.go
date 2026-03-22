package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/security-researcher-ca/agentshield/internal/policy"
)

// MCPStructuralMatch defines a structural match on MCP tool calls.
// Unlike regex matching, structural matching operates on the tool name
// and individual argument fields with typed predicates.
type MCPStructuralMatch struct {
	// Tool name predicates (case-insensitive matching)
	ToolNameAny   []string `yaml:"tool_name_any,omitempty"`   // any of these tool names (exact or glob)
	ToolNameRegex string   `yaml:"tool_name_regex,omitempty"` // regex on tool name

	// Argument field predicates — keyed by argument name (supports dot notation for nesting)
	ArgsMatch map[string]ArgFieldMatch `yaml:"args_match,omitempty"`

	// Exclusion predicates — if any specified field matches, the rule does NOT fire.
	// If the field does not exist in the tool call, the exclusion is skipped (rule may still fire).
	// Used to carve out known-safe contexts, e.g. exclude writes to taxonomy/ documentation files
	// from content-pattern rules that detect K8s/Docker security misconfigs.
	ExcludeArgsMatch map[string]ArgFieldMatch `yaml:"exclude_args_match,omitempty"`
}

// ArgFieldMatch defines match criteria for a single argument field.
type ArgFieldMatch struct {
	// String pattern matching on argument value (converted to string)
	PatternAny []string `yaml:"pattern_any,omitempty"` // any of these regex patterns match
	PatternAll []string `yaml:"pattern_all,omitempty"` // all patterns must match
	PatternNot []string `yaml:"pattern_not,omitempty"` // none of these patterns should match

	// Existence check
	Exists *bool `yaml:"exists,omitempty"` // argument field must/must not exist

	// Numeric comparison
	ValueGT *float64 `yaml:"value_gt,omitempty"` // value > threshold
	ValueLT *float64 `yaml:"value_lt,omitempty"` // value < threshold
}

// MCPStructuralRule is a complete structural rule including decision metadata.
type MCPStructuralRule struct {
	ID         string          `yaml:"id"`
	Match      MCPStructuralMatch `yaml:"match"`
	Decision   policy.Decision `yaml:"decision"`
	Reason     string          `yaml:"reason"`
	Confidence float64         `yaml:"confidence,omitempty"`
}

// matchStructuralRule checks if a tool call matches a structural rule.
func matchStructuralRule(toolName string, arguments map[string]interface{}, rule MCPStructuralRule) bool {
	m := rule.Match
	return matchStructural(toolName, arguments, m)
}

// matchStructural checks if a tool call matches a structural match definition.
func matchStructural(toolName string, arguments map[string]interface{}, m MCPStructuralMatch) bool {
	// Tool name matching (case-insensitive)
	nameMatched := false
	nameSpecified := false
	lowerToolName := strings.ToLower(toolName)

	if len(m.ToolNameAny) > 0 {
		nameSpecified = true
		for _, pattern := range m.ToolNameAny {
			if matchToolNameCaseInsensitive(lowerToolName, strings.ToLower(pattern)) {
				nameMatched = true
				break
			}
		}
	}

	if m.ToolNameRegex != "" {
		nameSpecified = true
		re, err := regexp.Compile("(?i)" + m.ToolNameRegex)
		if err == nil && re.MatchString(toolName) {
			nameMatched = true
		}
	}

	if nameSpecified && !nameMatched {
		return false
	}

	// Exclusion predicates — if the field exists and matches, the rule does NOT fire.
	// Non-existent fields are skipped (exclusion only applies when the field is present).
	for fieldName, fieldMatch := range m.ExcludeArgsMatch {
		if matchArgField(arguments, fieldName, fieldMatch) {
			return false
		}
	}

	// Argument field matching — all specified fields must match
	if len(m.ArgsMatch) > 0 {
		for fieldName, fieldMatch := range m.ArgsMatch {
			if !matchArgField(arguments, fieldName, fieldMatch) {
				return false
			}
		}
	}

	// Must have specified at least one predicate
	return nameSpecified || len(m.ArgsMatch) > 0
}

// matchToolNameCaseInsensitive matches a lowercase tool name against a lowercase pattern.
// Supports exact match and glob matching (*, ?).
func matchToolNameCaseInsensitive(lowerName, lowerPattern string) bool {
	if strings.ContainsAny(lowerPattern, "*?") {
		return globMatchSimple(lowerName, lowerPattern)
	}
	return lowerName == lowerPattern
}

// globMatchSimple implements basic glob matching for tool names.
// Supports * (match any sequence) and ? (match one character).
func globMatchSimple(s, pattern string) bool {
	return globMatchRec(s, pattern, 0, 0)
}

func globMatchRec(s, p string, si, pi int) bool {
	for pi < len(p) {
		if p[pi] == '*' {
			pi++
			// * matches zero or more characters
			for si <= len(s) {
				if globMatchRec(s, p, si, pi) {
					return true
				}
				si++
			}
			return false
		}
		if si >= len(s) {
			return false
		}
		if p[pi] == '?' || p[pi] == s[si] {
			si++
			pi++
		} else {
			return false
		}
	}
	return si == len(s)
}

// matchArgField checks if an argument field matches the given criteria.
// Supports dot notation for nested fields (e.g., "config.path").
func matchArgField(arguments map[string]interface{}, fieldName string, fm ArgFieldMatch) bool {
	val, exists := resolveField(arguments, fieldName)

	// Existence check
	if fm.Exists != nil {
		if *fm.Exists && !exists {
			return false
		}
		if !*fm.Exists && exists {
			return false
		}
		// If only existence was checked (no pattern/numeric), return true
		if len(fm.PatternAny) == 0 && len(fm.PatternAll) == 0 && len(fm.PatternNot) == 0 && fm.ValueGT == nil && fm.ValueLT == nil {
			return true
		}
	}

	if !exists {
		// Field doesn't exist — can't match patterns or numeric checks
		return false
	}

	valStr := valueToString(val)

	// PatternAny: at least one pattern must match
	if len(fm.PatternAny) > 0 {
		anyMatch := false
		for _, p := range fm.PatternAny {
			re, err := regexp.Compile(p)
			if err == nil && re.MatchString(valStr) {
				anyMatch = true
				break
			}
		}
		if !anyMatch {
			return false
		}
	}

	// PatternAll: all patterns must match
	if len(fm.PatternAll) > 0 {
		for _, p := range fm.PatternAll {
			re, err := regexp.Compile(p)
			if err != nil || !re.MatchString(valStr) {
				return false
			}
		}
	}

	// PatternNot: none of these patterns should match
	if len(fm.PatternNot) > 0 {
		for _, p := range fm.PatternNot {
			re, err := regexp.Compile(p)
			if err == nil && re.MatchString(valStr) {
				return false
			}
		}
	}

	// Numeric comparisons
	if fm.ValueGT != nil || fm.ValueLT != nil {
		numVal, ok := extractNumericVal(val)
		if !ok {
			return false
		}
		if fm.ValueGT != nil && numVal <= *fm.ValueGT {
			return false
		}
		if fm.ValueLT != nil && numVal >= *fm.ValueLT {
			return false
		}
	}

	return true
}

// resolveField extracts a value from a map using dot notation.
// "path" returns arguments["path"].
// "config.path" returns arguments["config"]["path"] if config is a map.
func resolveField(arguments map[string]interface{}, fieldName string) (interface{}, bool) {
	if arguments == nil {
		return nil, false
	}

	parts := strings.Split(fieldName, ".")
	var current interface{} = arguments

	for _, part := range parts {
		switch m := current.(type) {
		case map[string]interface{}:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}

	return current, true
}

// valueToString converts an argument value to its string representation.
func valueToString(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

// extractNumericVal extracts a float64 from an argument value.
func extractNumericVal(val interface{}) (float64, bool) {
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
	default:
		return 0, false
	}
}
