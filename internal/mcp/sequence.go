package mcp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/seqmatch"
)

// MCPSequenceMatch expresses a cross-call chain condition: an ordered
// subsequence of recorded MCP tool calls. It is the MCP-side analogue of the
// shell pipeline's `stateful.chain` schema, evaluated against per-session call
// history (#2493) rather than against segments of a single compound command.
//
// Example (the #2468 "Rule C" OSINT → generation → bulk-send chain):
//
//	sequence:
//	  steps:
//	    - tool_name_regex: "^(web_search|fetch)"
//	      min_count: 3
//	    - tool_name_regex: "(generate|complete|chat)"
//	    - tool_name_regex: "send_email"
//	      argument_regex_patterns: { to: '^\[' }       # array recipients
//	      argument_not_contains:   { body: ["ai-generated", "automated message"] }
//	  within_calls: 20
//
// Steps only expresses presence — an ordered subsequence that must occur.
// Some threat patterns are the inverse: a high-impact action fired WITHOUT a
// companion call immediately before it (#2785 perceive-act TOCTOU — a
// browser/computer-use agent acts on page state with no fresh
// screenshot/DOM/accessibility read to confirm the state didn't change out
// from under it). ActionStep/PrecheckStep express that negative-lookback
// case; they are mutually exclusive with Steps:
//
//	sequence:
//	  action_step:
//	    tool_name_any: ["click", "computer_use"]
//	    argument_regex_patterns: { text: "(?i)confirm|transfer" }
//	  precheck_step:
//	    tool_name_any: ["screenshot", "get_dom_snapshot"]
//	  precheck_within_calls: 2
type MCPSequenceMatch struct {
	Steps       []MCPSequenceStep `yaml:"steps,omitempty"`
	WithinCalls int               `yaml:"within_calls,omitempty"` // only consider the last N recorded calls (0 = all history)

	// ActionStep/PrecheckStep implement the negative-lookback pattern: the
	// rule fires iff the triggering call (the last entry in history) matches
	// ActionStep AND none of the PrecheckWithinCalls calls immediately
	// preceding it match PrecheckStep. When ActionStep is set, Steps is
	// ignored.
	ActionStep          *MCPSequenceStep `yaml:"action_step,omitempty"`
	PrecheckStep        *MCPSequenceStep `yaml:"precheck_step,omitempty"`
	PrecheckWithinCalls int              `yaml:"precheck_within_calls,omitempty"` // how many calls immediately before the action to search for a precheck (default 1)
}

// MCPSequenceStep is one step in a sequence. A step matches a recorded call
// when its tool-name predicate AND all argument predicates hold. MinCount
// requires the step to match at least N calls (gaps permitted) before the
// sequence advances to the next step (default 1).
type MCPSequenceStep struct {
	ToolName              string              `yaml:"tool_name,omitempty"`
	ToolNameRegex         string              `yaml:"tool_name_regex,omitempty"`
	ToolNameAny           []string            `yaml:"tool_name_any,omitempty"`
	MinCount              int                 `yaml:"min_count,omitempty"`
	ArgumentRegexPatterns map[string]string   `yaml:"argument_regex_patterns,omitempty"`
	ArgumentNotContains   map[string][]string `yaml:"argument_not_contains,omitempty"`
}

// matchSequence reports whether history satisfies seq as an ordered
// subsequence. history is oldest-first and should include the triggering call
// as its last element. Calls that do not match the current step are skipped
// (gaps are allowed). A step with MinCount=N must match N calls before the
// sequence advances. Matching is greedy left-to-right (seqmatch.Match) —
// precision-first and shared with the shell-side stateful chain matcher.
func matchSequence(seq *MCPSequenceMatch, history []RecordedCall) bool {
	if seq == nil {
		return false
	}
	if seq.ActionStep != nil {
		return matchActionWithoutPrecheck(seq, history)
	}
	if len(seq.Steps) == 0 {
		return false
	}
	calls := history
	if seq.WithinCalls > 0 && len(calls) > seq.WithinCalls {
		calls = calls[len(calls)-seq.WithinCalls:]
	}

	return seqmatch.Match(seq.Steps, calls, stepMinCount,
		func(step MCPSequenceStep, _ int, call RecordedCall, _, _ int) seqmatch.Outcome {
			if stepMatches(step, call) {
				return seqmatch.Matched
			}
			return seqmatch.Skip
		})
}

// matchActionWithoutPrecheck reports whether the triggering call (the last
// entry in history) matches seq.ActionStep and none of the
// seq.PrecheckWithinCalls calls immediately preceding it match
// seq.PrecheckStep. This is the negative-lookback complement to the
// steps-based ordered-subsequence match above.
func matchActionWithoutPrecheck(seq *MCPSequenceMatch, history []RecordedCall) bool {
	if len(history) == 0 || seq.PrecheckStep == nil {
		return false
	}
	trigger := history[len(history)-1]
	if !stepMatches(*seq.ActionStep, trigger) {
		return false
	}

	lookback := seq.PrecheckWithinCalls
	if lookback <= 0 {
		lookback = 1
	}
	prior := history[:len(history)-1]
	if len(prior) > lookback {
		prior = prior[len(prior)-lookback:]
	}
	for _, call := range prior {
		if stepMatches(*seq.PrecheckStep, call) {
			return false // a fresh precheck was found — no violation
		}
	}
	return true
}

// stepMinCount returns the effective minimum match count for a step (≥1).
func stepMinCount(s MCPSequenceStep) int {
	if s.MinCount > 1 {
		return s.MinCount
	}
	return 1
}

// stepMatches reports whether a single recorded call satisfies a step. A step
// with no tool-name predicate never matches (a sequence step must name a tool).
func stepMatches(s MCPSequenceStep, call RecordedCall) bool {
	if s.ToolName == "" && s.ToolNameRegex == "" && len(s.ToolNameAny) == 0 {
		return false
	}
	if s.ToolName != "" && call.ToolName != s.ToolName {
		return false
	}
	if s.ToolNameRegex != "" {
		re, err := regexp.Compile(s.ToolNameRegex)
		if err != nil || !re.MatchString(call.ToolName) {
			return false
		}
	}
	if len(s.ToolNameAny) > 0 {
		found := false
		for _, n := range s.ToolNameAny {
			if call.ToolName == n {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Argument regex predicates — all must hold against the (stringified) arg.
	for arg, pat := range s.ArgumentRegexPatterns {
		re, err := regexp.Compile(pat)
		if err != nil || !re.MatchString(argString(call.Args, arg)) {
			return false
		}
	}

	// Argument-absence predicates — the arg must contain NONE of the substrings
	// (case-insensitive). An absent arg is satisfied. Mirrors MCPMatch's
	// ArgumentNotContains semantics.
	for arg, subs := range s.ArgumentNotContains {
		v, ok := call.Args[arg]
		if !ok {
			continue
		}
		hay := strings.ToLower(fmt.Sprintf("%v", v))
		for _, sub := range subs {
			if strings.Contains(hay, strings.ToLower(sub)) {
				return false
			}
		}
	}
	return true
}

// argString returns the stringified value of args[key], or "" if absent.
func argString(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	if v, ok := args[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
