package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// tool_name_regex_exclude (#4241) is the regex twin of tool_name_not_prefix_any
// on flat `rules:` entries. These tests pin the contract the matcher comment
// promises: the carve-out wins over the positive pattern, it sees the wire name
// behind a namespace prefix, and every failure mode (non-ASCII name, invalid
// regex) falls toward the finding, never away from it.

func excludeRule(exclude string) MCPRule {
	return MCPRule{
		ID: "test-name-regex-exclude",
		Match: MCPMatch{
			ToolNameRegex:        "send_",
			ToolNameRegexExclude: exclude,
		},
		Decision: policy.DecisionAudit,
	}
}

func TestToolNameRegexExclude_CarveOutWinsOverPositive(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := excludeRule(`(^|_)send_messages?([_-]|$)`)
	if e.matchRule("send_message", nil, rule) {
		t.Error("send_message matches the exclude; the rule must not fire")
	}
	if !e.matchRule("send_payment", nil, rule) {
		t.Error("send_payment is outside the exclude; the positive pattern must still fire")
	}
	// Segment-anchored: an object merely STARTING with an excluded word is not excluded.
	if !e.matchRule("send_messagebird_payout", nil, rule) {
		t.Error("send_messagebird_payout is not the excluded object; the rule must fire")
	}
}

func TestToolNameRegexExclude_ReachesPastNamespacePrefix(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := excludeRule(`(^|_)send_messages?([_-]|$)`)
	// The Claude Code / Codex hook hands the evaluator mcp__<server>__<tool>;
	// a prefix test (tool_name_not_prefix_any) cannot see the tool here.
	if e.matchRule("mcp__slack__send_message", nil, rule) {
		t.Error("mcp__slack__send_message must be carved out")
	}
	if !e.matchRule("mcp__goat-evm__send_token", nil, rule) {
		t.Error("mcp__goat-evm__send_token must still fire")
	}
}

func TestToolNameRegexExclude_NonASCIINameSkipsCarveOut(t *testing.T) {
	e := &PolicyEvaluator{}
	// (?i) folds U+017F (long s) to 's', so without the ASCII gate this
	// spelling would satisfy the carve-out and switch the rule off (#3771).
	rule := MCPRule{
		ID: "test-name-regex-exclude-fold",
		Match: MCPMatch{
			ToolNameRegex:        "(?i)end_",
			ToolNameRegexExclude: `(?i)send_message`,
		},
		Decision: policy.DecisionAudit,
	}
	if e.matchRule("send_message", nil, rule) {
		t.Fatal("control: the ASCII spelling must be carved out")
	}
	if !e.matchRule("ſend_message", nil, rule) {
		t.Error("a non-ASCII spelling must skip the carve-out and fire (fail toward the finding)")
	}
}

func TestToolNameRegexExclude_InvalidRegexDisablesOnlyTheCarveOut(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := excludeRule(`(unclosed`)
	if !e.matchRule("send_message", nil, rule) {
		t.Error("an exclude that fails to compile must not suppress the rule")
	}
}

func TestToolNameRegexExclude_DoesNotWidenThePositive(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := excludeRule(`(^|_)send_messages?([_-]|$)`)
	if e.matchRule("read_file", nil, rule) {
		t.Error("a name the positive pattern rejects must not fire because of the exclude")
	}
}

// Mirrors TestToolNameNotPrefixAny_OnlyPredicateStillCountsAsSpecified: an
// exclude-only rule ("every tool except these") must evaluate, not be inert.
func TestToolNameRegexExclude_OnlyPredicateStillCountsAsSpecified(t *testing.T) {
	e := &PolicyEvaluator{}
	rule := MCPRule{
		ID:       "test-bare-name-regex-exclude",
		Match:    MCPMatch{ToolNameRegexExclude: `^safe_`},
		Decision: policy.DecisionAudit,
	}
	if !e.matchRule("any_tool", nil, rule) {
		t.Error("expected fire: nothing excluded")
	}
	if e.matchRule("safe_read", nil, rule) {
		t.Error("expected no fire: excluded")
	}
}
