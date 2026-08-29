package mcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/policy"
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
	ID         string             `yaml:"id"`
	Taxonomy   string             `yaml:"taxonomy,omitempty"`
	Match      MCPStructuralMatch `yaml:"match"`
	Decision   policy.Decision    `yaml:"decision"`
	Reason     string             `yaml:"reason"`
	Confidence float64            `yaml:"confidence,omitempty"`
	// Tests holds inline TP/TN test cases. Same shape as MCPRuleTest so the
	// rule_yaml_test runner can validate structural-rule packs as well as
	// flat-pattern rules. Without this field, YAML `tests:` blocks under a
	// structural rule are silently ignored — see FN-MCP-011 / issue #1155.
	Tests *MCPRuleTest `yaml:"tests,omitempty"`
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

	// HTTP-method inference (issue #1152 fix).
	//
	// Many MCP HTTP tools encode the method in the tool name (http_post,
	// http_put, http_delete, http_patch, post_request, put_request, ...).
	// When such a tool is called, callers do NOT pass a separate `method`
	// argument — the method is implicit in the tool name. Rules that require
	// both a URL match AND an `args_match.method` filter would silently
	// fail-negative on these typed tools, because matchArgField returns
	// false when a required field is missing.
	//
	// To close this attacker bypass, synthesize a `method` argument from
	// the tool name when: (a) the rule has a method filter, (b) the call
	// does not already carry a method, and (c) the tool name encodes a
	// recognizable HTTP method. This is a read-only synthesis — the
	// caller's arguments map is not mutated.
	if _, hasMethodRule := m.ArgsMatch["method"]; hasMethodRule {
		if _, hasMethodArg := arguments["method"]; !hasMethodArg {
			if inferred := inferMethodFromToolName(toolName); inferred != "" {
				newArgs := make(map[string]interface{}, len(arguments)+1)
				for k, v := range arguments {
					newArgs[k] = v
				}
				newArgs["method"] = inferred
				arguments = newArgs
			}
		}
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

// inferMethodFromToolName returns the HTTP method encoded in a tool name,
// or empty if the tool name does not encode a recognizable method. The
// tool name is split on underscores, hyphens, and dots, and each word is
// checked against the set of HTTP methods. This catches conventions like
// http_post, http_delete, post_request, put-request, do.patch, etc.
//
// Generic tool names (http_request, network_request, fetch_url, make_request,
// send_request, api_request) return empty — for those, callers must pass
// an explicit `method` argument and the rule's method filter applies as
// configured.
func inferMethodFromToolName(toolName string) string {
	lower := strings.ToLower(toolName)
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	for _, part := range parts {
		switch part {
		case "post":
			return "POST"
		case "put":
			return "PUT"
		case "delete":
			return "DELETE"
		case "patch":
			return "PATCH"
		case "get":
			return "GET"
		case "head":
			return "HEAD"
		case "options":
			return "OPTIONS"
		}
	}
	return ""
}

// matchToolNameCaseInsensitive matches a lowercase tool name against a lowercase pattern.
// Supports exact match and glob matching (*, ?).
func matchToolNameCaseInsensitive(lowerName, lowerPattern string) bool {
	if strings.ContainsAny(lowerPattern, "*?") {
		if globMatchSimple(lowerName, lowerPattern) {
			return true
		}
		// Naming-convention fallback (issue #3443): see normalizeSeparators.
		return globMatchSimple(normalizeSeparators(lowerName), normalizeSeparators(lowerPattern))
	}
	if lowerName == lowerPattern {
		return true
	}
	return normalizeSeparators(lowerName) == normalizeSeparators(lowerPattern)
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
	values, valuesExist := resolveFieldValues(arguments, fieldName)
	exists = exists || valuesExist

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

	// Numeric comparisons apply to the single resolved value — a batched
	// numeric argument isn't part of the batch-argument threat model this
	// function's array/plural handling targets (see resolveFieldValues).
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

	if len(fm.PatternAny) == 0 && len(fm.PatternAll) == 0 && len(fm.PatternNot) == 0 {
		return true
	}

	// Pattern predicates: a batch/bulk tool call bundles several targets under
	// one argument (see resolveFieldValues) — the rule fires if ANY one of
	// them, individually, satisfies every specified pattern predicate.
	for _, valStr := range values {
		if matchArgPatterns(valStr, fm) {
			return true
		}
	}
	return false
}

// matchArgPatterns evaluates PatternAny/PatternAll/PatternNot against a
// single candidate string.
func matchArgPatterns(valStr string, fm ArgFieldMatch) bool {
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
				// Case-insensitive fallback: some MCP tools mirror raw vendor
				// SDK parameter casing (e.g. boto3's Bucket/Key/Body) instead
				// of the lowercase/snake_case convention most rules are
				// authored against. Exact match stays the fast path and wins
				// on collision; this only fires when the exact key is absent.
				for k, v := range m {
					if strings.EqualFold(k, part) {
						val, ok = v, true
						break
					}
				}
			}
			if !ok {
				// Naming-convention fallback (issue #3443): a rule field name
				// is authored against one MCP server's convention
				// (branch_name) — a camelCase server (branchName) is
				// otherwise invisible even though it is the same field.
				// Only reached once both the exact and case-insensitive
				// lookups above have failed.
				normPart := normalizeFieldName(part)
				for k, v := range m {
					if normalizeFieldName(k) == normPart {
						val, ok = v, true
						break
					}
				}
			}
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

// resolveFieldValues resolves fieldName to every string value a
// pattern-matching predicate should be checked against. Every existing
// path/URL-matching rule in the corpus is authored against a singular scalar
// field ("path", "url", "file") holding one string. A batch/bulk MCP tool
// exposes the identical operation over several targets at once under a
// plural array field instead ("paths", "urls", "files") — naively
// stringifying that array (Go's fmt.Sprintf("%v", ...) on a []interface{}
// produces "[/a /b]", which no anchored glob or exact-match regex written
// against a single path was ever meant to parse) silently drops every rule
// keyed on the singular name. Fixed once here rather than per-rule so it
// covers the whole corpus, mirroring how NormalizeExecName/normalizeTargetPath
// centralized the shell-side quote-splice fix (issue #2813) instead of
// patching each call site.
//
// Resolution order:
//  1. fieldName itself, if present. An array value expands to one string per
//     element PLUS the original whole-array stringification (Go's
//     fmt.Sprintf("%v", ...), the pre-fix behavior) as one extra candidate —
//     additive, never weakening, so a rule that was deliberately written
//     against the joined form (an aggregate property like "3+ recipients", or
//     a pattern spanning two elements of the same array, e.g. a flag and its
//     payload) keeps matching exactly as before, while a rule looking for one
//     bad element among several now also sees each element on its own. A
//     scalar wraps to a single-element slice.
//  2. fieldName+"s", if fieldName itself is absent AND the plural key holds
//     an array — the batch-argument case above. Only applies to undotted
//     (top-level) names; nested dot-notation paths are out of scope.
//  3. Any top-level argument whose value is an array of objects, regardless
//     of that container's key name — pulling fieldName out of each object
//     (issue #3156). Real batch tool schemas commonly wrap each item as a
//     request object under a container name that has no naming relationship
//     to the field itself: {"entries": [{"path": "...", "content": "..."}]},
//     {"operations": [{"path": "..."}]}. Forms 1 and 2 only look for the
//     plural of fieldName as the container's own name, so an unrelated
//     container name defeats them even though the sensitive value is present
//     one level down. Additive to 1/2, never replacing them.
//  4. Any top-level argument whose value is a single object (not wrapped in
//     an array), regardless of that container's key name — pulling
//     fieldName out of it (issue #3177). The singular sibling of form 3:
//     REST-style single-item tool schemas commonly wrap their arguments
//     under a request-envelope key with no naming relationship to the field
//     itself: {"request": {"path": "..."}}, {"input": {"path": "..."}},
//     {"body": {"path": "...", "content": "..."}}. Additive to 1-3, never
//     replacing them.
//  5. Any top-level argument whose value is a STRING that itself decodes as
//     JSON, holding fieldName either directly (a JSON object) or one level
//     inside each element of a JSON array (issue #3179). Forms 2-4 only
//     recurse into values the JSON-RPC decoder already produced as a native
//     Go map/array; a generic API-passthrough tool that accepts a raw JSON
//     body as a single string parameter ({"payload": "{\"path\": \"...\"}"})
//     defeats all of them even though the sensitive value is present, just
//     serialized rather than nested. One level of string-JSON unwrapping
//     only — the parsed value is not recursively re-run through forms 1-5.
//     Additive to 1-4, never replacing them.
//
// ok is false only when none of the five forms produced a value.
func resolveFieldValues(arguments map[string]interface{}, fieldName string) ([]string, bool) {
	var out []string
	found := false

	if val, ok := resolveField(arguments, fieldName); ok {
		out = append(out, flattenArgValue(val)...)
		found = true
	}

	if !strings.Contains(fieldName, ".") {
		// Plural argument key: a rule written against `path` must also see
		// `paths`, `file` must see `files`, and so on for every structural
		// rule — not just the credential-path ones.
		//
		// This deliberately does NOT require the plural value to be an array.
		// It used to, and that restriction was the whole of issue #3312: a
		// tool declaring `paths` as `string | string[]` and passed a single
		// string fell straight through, so Shield emitted AUDIT for a call
		// that read an SSH private key. An AUDIT record affirmatively attests
		// "no violation" for an action our own rules say to block, which
		// falsifies the attestation rather than merely missing a detection.
		//
		// #3312 reported the gap as "the plural key bypasses every
		// credential-path rule" and prescribed adding seven plural keys to
		// packs/premium/mcp/mcp-alt-path-arg-credential-access.yaml. Measured
		// against the deployed binary, that diagnosis was wrong in a way worth
		// recording: plural key + ARRAY already blocked here, via this very
		// fallback. The issue's repro used `mcp-eval --arg`, which stores
		// values as plain strings and never parses JSON, so `--arg
		// 'paths=["..."]'` tested a string that merely looked like an array.
		// Under `--json` the array case blocks and only the scalar case fails.
		//
		// Fixing it here rather than in the pack is what makes the fix
		// complete: the pack change would have added ~500 lines duplicating
		// one pattern list across seven keys, covered only those seven, and
		// helped no other structural rule. One line covers every singular key
		// any rule is written against, present and future.
		if val, ok := resolveField(arguments, fieldName+"s"); ok {
			out = append(out, flattenArgValue(val)...)
			found = true
		}

		if vals, ok := resolveNestedArrayObjectField(arguments, fieldName); ok {
			out = append(out, vals...)
			found = true
		}

		if vals, ok := resolveNestedObjectField(arguments, fieldName); ok {
			out = append(out, vals...)
			found = true
		}

		if vals, ok := resolveStringEncodedJSONField(arguments, fieldName); ok {
			out = append(out, vals...)
			found = true
		}
	}

	return out, found
}

// resolveNestedArrayObjectField scans every top-level argument whose value is
// an array of objects (map[string]interface{}) and collects fieldName from
// each object that carries it, one nesting level deep. See resolveFieldValues
// form 3 / issue #3156: a batch container key (items, entries, operations,
// requests, ...) carries no naming relationship to fieldName, so it is
// invisible to the exact-key and plural-key resolution above.
func resolveNestedArrayObjectField(arguments map[string]interface{}, fieldName string) ([]string, bool) {
	var out []string
	for _, v := range arguments {
		arr, isArr := v.([]interface{})
		if !isArr {
			continue
		}
		for _, item := range arr {
			obj, isObj := item.(map[string]interface{})
			if !isObj {
				continue
			}
			if val, ok := resolveField(obj, fieldName); ok {
				out = append(out, flattenArgValue(val)...)
			}
		}
	}
	return out, len(out) > 0
}

// resolveNestedObjectField scans every top-level argument whose value is a
// single object (map[string]interface{}, NOT wrapped in an array) and
// collects fieldName from it, one nesting level deep. Singular sibling of
// resolveNestedArrayObjectField (form 3 / #3156) for form 4 / issue #3177: a
// request-envelope container key (request, input, data, body, params) with
// no naming relationship to fieldName is invisible to the exact-key and
// plural-key resolution above, exactly like the array-of-objects case, just
// one item instead of several.
func resolveNestedObjectField(arguments map[string]interface{}, fieldName string) ([]string, bool) {
	var out []string
	for _, v := range arguments {
		obj, isObj := v.(map[string]interface{})
		if !isObj {
			continue
		}
		if val, ok := resolveField(obj, fieldName); ok {
			out = append(out, flattenArgValue(val)...)
		}
	}
	return out, len(out) > 0
}

// contentPayloadArgKeys are argument names that conventionally carry the
// literal file/message body being written or sent by the tool call, not a
// structured envelope of parameters describing the call itself (see the
// Write tool family in CLAUDE.md: content is the payload argument shared by
// write_file, create_file, edit_file, append_file, str_replace_editor,
// write_to_file; text is its common alias for message/comment-style tools).
// resolveStringEncodedJSONField must not recurse into these: a write_file
// call whose content happens to itself be JSON-shaped text (writing a JSON
// config, or an AI tool-history log entry recording a *different* past
// operation's path) is data being carried, not a parameter of *this*
// operation — scanning inside it conflates "the payload mentions X" with
// "this call targets/sets X". Confirmed by two real corpus regressions
// caught by TestMCPScenarios when this exclusion was absent: MCP-TP-743 (a
// governance log entry's embedded "path" field wrongly matched a
// credential-path rule) and MCP-TP-1928-003 (a context file's embedded
// "system" field wrongly matched an LLM system-prompt-override rule meant
// for tools that take a literal "system" call parameter). See issue #3179.
var contentPayloadArgKeys = map[string]bool{
	"content": true,
	"text":    true,
}

// resolveStringEncodedJSONField scans every top-level argument whose value
// is a string that itself decodes as JSON, and collects fieldName from the
// decoded value — either directly (a JSON object) or one level inside each
// element of a JSON array. Sibling of resolveNestedObjectField / form 4 and
// resolveNestedArrayObjectField / form 3 for form 5 / issue #3179: a
// generic passthrough tool that accepts a raw JSON body as a single string
// parameter (payload, body, request_body) serializes the sensitive value
// rather than nesting it as a native Go type, which forms 2-4 never see
// because they only type-switch on []interface{}/map[string]interface{}
// (the JSON-RPC decoder's own native output) — a string never matches
// either. Guarded by a cheap first-byte check before attempting to unmarshal
// so ordinary non-JSON string arguments are not parsed on every call, and by
// contentPayloadArgKeys so literal file/message payloads are never
// misread as call parameters.
func resolveStringEncodedJSONField(arguments map[string]interface{}, fieldName string) ([]string, bool) {
	var out []string
	for key, v := range arguments {
		if contentPayloadArgKeys[key] {
			continue
		}
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		trimmed := strings.TrimSpace(s)
		if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
			continue
		}
		var parsed interface{}
		if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
			continue
		}
		switch pv := parsed.(type) {
		case map[string]interface{}:
			if val, ok := resolveField(pv, fieldName); ok {
				out = append(out, flattenArgValue(val)...)
			}
		case []interface{}:
			for _, item := range pv {
				if obj, isObj := item.(map[string]interface{}); isObj {
					if val, ok := resolveField(obj, fieldName); ok {
						out = append(out, flattenArgValue(val)...)
					}
				}
			}
		}
	}
	return out, len(out) > 0
}

// flattenArgValue expands an array value into one string per element plus
// the original aggregate stringification (see resolveFieldValues); anything
// else stringifies to a single-element slice.
func flattenArgValue(val interface{}) []string {
	arr, ok := val.([]interface{})
	if !ok {
		return []string{valueToString(val)}
	}
	out := make([]string, 0, len(arr)+1)
	for _, item := range arr {
		out = append(out, valueToString(item))
	}
	out = append(out, fmt.Sprintf("%v", arr))
	return out
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
