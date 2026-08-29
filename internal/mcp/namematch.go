package mcp

import "strings"

// normalizeSeparators lowercases and collapses '-' to '_' so hyphenated and
// underscored spellings of the same tool name compare equal — "git_checkout"
// and "git-checkout" both normalize to "git_checkout".
//
// Deliberately does NOT strip separators (contrast normalizeFieldName): a
// wildcard tool_name_any pattern like "*pay_*" relies on '_' as a literal
// word-boundary character to avoid matching "get_payload"/"payroll"/etc.
// Stripping it would widen the pattern to "*pay*", which then does match
// those — a real regression caught by TestPremiumMCPStructuralRuleYAMLTests
// while building this fix. Collapsing the two separator spellings to one
// preserves the boundary while still closing the vendor-naming-convention
// gap (issue #3443): a rule authored against a snake_case reference MCP
// server (git_checkout) still fires against a hyphenated JS/TS server
// (git-checkout).
func normalizeSeparators(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

// normalizeFieldName additionally strips separators entirely, collapsing
// snake_case, kebab-case, and camelCase argument names into one comparable
// form: "branch_name", "branchName", and "branch-name" all normalize to
// "branchname".
//
// Safe here in a way normalizeSeparators is not: MCP argument field names
// are always literal map keys, never glob/wildcard patterns, so there is no
// boundary-character semantics to preserve. Use this for argument field name
// resolution (resolveField); use normalizeSeparators for tool names, which
// may carry '*'/'?' wildcards.
func normalizeFieldName(s string) string {
	s = strings.ToLower(s)
	if !strings.ContainsAny(s, "_-") {
		return s
	}
	return strings.NewReplacer("_", "", "-", "").Replace(s)
}
