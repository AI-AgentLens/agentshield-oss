package mcp

import (
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestArgumentValueRegexAny_MatchesUnnamedKey is the direct repro of the
// issue #3576 motivating gap: a homoglyph-host detection authored against a
// named `url` key is invisible to a tool that calls the same parameter
// `repo_url` (or endpoint/href/source_url/...). argument_value_regex_any
// takes no key at all, so it must fire regardless of which argument carries
// the value.
func TestArgumentValueRegexAny_MatchesUnnamedKey(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID: "test-any-arg-value-homoglyph",
		Match: MCPMatch{
			ArgumentValueRegexAny: []string{`https?://[^/\s]*[^\x00-\x7F]`},
		},
		Decision: policy.DecisionBlock,
	}

	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		fire bool
	}{
		{
			name: "git_clone repo_url — the exact #3574/#3576 gap",
			tool: "git_clone",
			args: map[string]interface{}{"repo_url": homoglyphHost("https://github.com/legit-org/repo.git")},
			fire: true,
		},
		{
			name: "webhook endpoint key",
			tool: "register_webhook",
			args: map[string]interface{}{"endpoint": homoglyphHost("https://api.example.com/hook")},
			fire: true,
		},
		{
			name: "the originally-covered url key still fires",
			tool: "fetch",
			args: map[string]interface{}{"url": homoglyphHost("https://github.com/x")},
			fire: true,
		},
		{
			name: "ascii-only host does not fire",
			tool: "git_clone",
			args: map[string]interface{}{"repo_url": "https://github.com/legit-org/repo.git"},
			fire: false,
		},
		{
			name: "no arguments at all",
			tool: "noop",
			args: map[string]interface{}{},
			fire: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.matchRule(tc.tool, tc.args, rule)
			if got != tc.fire {
				t.Errorf("matchRule(%q, %v) = %v, want %v", tc.tool, tc.args, got, tc.fire)
			}
		})
	}
}

// TestArgumentValueRegexAny_NestedEnvelope confirms the recursive walk
// reaches values wrapped in a batch array or a request-envelope object, not
// just top-level scalar arguments — the same shape resolveFieldValues covers
// for named-field lookups (forms 3/4 in its doc comment), but this predicate
// has no field name to anchor the walk, so it must descend unconditionally.
func TestArgumentValueRegexAny_NestedEnvelope(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID:       "test-any-arg-value-nested",
		Match:    MCPMatch{ArgumentValueRegexAny: []string{`secret-token-\d+`}},
		Decision: policy.DecisionBlock,
	}

	cases := []struct {
		name string
		args map[string]interface{}
		fire bool
	}{
		{
			name: "value inside a request envelope object",
			args: map[string]interface{}{"request": map[string]interface{}{"auth": "secret-token-42"}},
			fire: true,
		},
		{
			name: "value inside a batch array of objects",
			args: map[string]interface{}{"items": []interface{}{
				map[string]interface{}{"note": "fine"},
				map[string]interface{}{"note": "secret-token-99"},
			}},
			fire: true,
		},
		{
			name: "value nested two levels deep",
			args: map[string]interface{}{"outer": map[string]interface{}{"inner": map[string]interface{}{"v": "secret-token-7"}}},
			fire: true,
		},
		{
			name: "no matching value anywhere",
			args: map[string]interface{}{"items": []interface{}{map[string]interface{}{"note": "fine"}}},
			fire: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.matchRule("any_tool", tc.args, rule)
			if got != tc.fire {
				t.Errorf("matchRule(%v) = %v, want %v", tc.args, got, tc.fire)
			}
		})
	}
}

// TestArgumentValueRegexAny_BoundedScan confirms an oversized single argument
// value is truncated before the regex pass rather than scanned in full —
// the ReDoS guard the issue explicitly asked for. A pathological pattern
// placed just past the cutoff must not fire.
func TestArgumentValueRegexAny_BoundedScan(t *testing.T) {
	rule := MCPRule{
		ID:       "test-any-arg-value-bound",
		Match:    MCPMatch{ArgumentValueRegexAny: []string{"NEEDLE"}},
		Decision: policy.DecisionBlock,
	}
	e := &PolicyEvaluator{}

	padding := strings.Repeat("a", maxAnyArgumentValueScanBytes)
	beyondCutoff := padding + "NEEDLE"
	if e.matchRule("t", map[string]interface{}{"content": beyondCutoff}, rule) {
		t.Error("expected the needle past maxAnyArgumentValueScanBytes to be truncated away")
	}

	withinCutoff := "NEEDLE" + strings.Repeat("a", maxAnyArgumentValueScanBytes-6)
	if !e.matchRule("t", map[string]interface{}{"content": withinCutoff}, rule) {
		t.Error("expected the needle within maxAnyArgumentValueScanBytes to still match")
	}
}

// TestArgumentValueRegexAny_OnlyPredicateStillCountsAsSpecified mirrors
// TestToolNameNotPrefixAny_OnlyPredicateStillCountsAsSpecified: a rule using
// ONLY argument_value_regex_any (no tool name, no other argument predicate)
// must still evaluate — exercising the final nameSpecified OR-list fallback
// in matchRule. Without this the field would be silently inert on any rule
// that doesn't also specify a name matcher.
func TestArgumentValueRegexAny_OnlyPredicateStillCountsAsSpecified(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID:       "test-bare-any-arg-value",
		Match:    MCPMatch{ArgumentValueRegexAny: []string{"BOOM"}},
		Decision: policy.DecisionAudit,
	}

	if !e.matchRule("literally_any_tool", map[string]interface{}{"whatever_key": "BOOM"}, rule) {
		t.Error("expected fire: the only predicate specified matched")
	}
	if e.matchRule("literally_any_tool", map[string]interface{}{"whatever_key": "fine"}, rule) {
		t.Error("expected no fire: nothing matched")
	}
}

// TestArgumentValueRegexAny_ParityMatchRuleVsStructural is the parity test
// issue #3576 explicitly asks for: matchRule (MCPMatch, flat `rules:`
// entries) and matchStructural (MCPStructuralMatch, `structural_rules:`
// entries) are two independent evaluation paths sharing no code except
// matchAnyArgumentValueRegex — wiring the field into one and not the other
// is exactly the "most-repeated latent trap" (#3232/#3234) this test guards
// against. Same tool calls must produce the same verdict on both paths.
func TestArgumentValueRegexAny_ParityMatchRuleVsStructural(t *testing.T) {
	patterns := []string{`https?://[^/\s]*[^\x00-\x7F]`}
	flatRule := MCPRule{
		ID:       "test-parity-flat",
		Match:    MCPMatch{ArgumentValueRegexAny: patterns},
		Decision: policy.DecisionBlock,
	}
	structuralMatch := MCPStructuralMatch{ArgumentValueRegexAny: patterns}

	e := &PolicyEvaluator{}
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		want bool
	}{
		{"unnamed key fires on both", "git_clone", map[string]interface{}{"repo_url": homoglyphHost("https://github.com/x")}, true},
		{"nested envelope fires on both", "call", map[string]interface{}{"req": map[string]interface{}{"href": homoglyphHost("https://github.com/x")}}, true},
		{"ascii host fires on neither", "git_clone", map[string]interface{}{"repo_url": "https://github.com/x"}, false},
		{"no args fires on neither", "noop", map[string]interface{}{}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotFlat := e.matchRule(tc.tool, tc.args, flatRule)
			gotStructural := matchStructural(tc.tool, tc.args, structuralMatch)
			if gotFlat != tc.want {
				t.Errorf("matchRule(%q) = %v, want %v", tc.tool, gotFlat, tc.want)
			}
			if gotStructural != tc.want {
				t.Errorf("matchStructural(%q) = %v, want %v", tc.tool, gotStructural, tc.want)
			}
			if gotFlat != gotStructural {
				t.Errorf("evaluation-path parity broken: matchRule=%v matchStructural=%v for %v", gotFlat, gotStructural, tc.args)
			}
		})
	}
}

// TestArgumentValueRegexAny_StructuralOnlyPredicateStillCountsAsSpecified is
// the MCPStructuralMatch sibling of the matchRule bare-predicate test above.
func TestArgumentValueRegexAny_StructuralOnlyPredicateStillCountsAsSpecified(t *testing.T) {
	m := MCPStructuralMatch{ArgumentValueRegexAny: []string{"BOOM"}}

	if !matchStructural("literally_any_tool", map[string]interface{}{"whatever_key": "BOOM"}, m) {
		t.Error("expected fire: the only predicate specified matched")
	}
	if matchStructural("literally_any_tool", map[string]interface{}{"whatever_key": "fine"}, m) {
		t.Error("expected no fire: nothing matched")
	}
}

// TestArgumentValueRegexAny_MalformedPatternDoesNotPanic confirms an
// unparseable regex in the list is skipped (via cachedRegexp's cached error)
// rather than panicking the evaluator — fail-safe per CLAUDE.md's "policy
// evaluation must never panic" rule.
func TestArgumentValueRegexAny_MalformedPatternDoesNotPanic(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID: "test-malformed-pattern",
		Match: MCPMatch{
			ArgumentValueRegexAny: []string{"(unclosed", "BOOM"},
		},
		Decision: policy.DecisionBlock,
	}

	if !e.matchRule("t", map[string]interface{}{"k": "BOOM"}, rule) {
		t.Error("expected the valid pattern to still fire despite a malformed sibling pattern")
	}
	if e.matchRule("t", map[string]interface{}{"k": "fine"}, rule) {
		t.Error("expected no fire when nothing matches")
	}
}
