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
		if err != nil || !toolNameRegexMatches(re, call.ToolName) {
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
		if err != nil || !argRegexMatches(re, call.Args, arg) {
			return false
		}
	}

	// Argument-absence predicates — the arg must contain NONE of the substrings
	// (case-insensitive). An absent arg is satisfied. Mirrors MCPMatch's
	// ArgumentNotContains semantics.
	for arg, subs := range s.ArgumentNotContains {
		// argmaplookup:allow NEGATIVE predicate — folding an exclusion widens
		// it. Resolving a respelled key here would make the "must contain
		// none of" test match more often, which switches the RULE off; the
		// raw index can only leave the predicate satisfied, i.e. leave the
		// rule live. Same inversion toolNameForms documents for
		// ToolNameRegexExclude / ToolNameNotPrefixAny.
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

// argString returns the stringified value of the rule-supplied key in args,
// or "" if absent.
//
// Resolution goes through argFieldRecovered (exact-then-render-recovery), NOT a
// raw map index and NOT the full resolveField ladder (#3691/#3712/#3720/#3727).
// This is the fail-OPEN direction of the class and the reason it matters most
// here: an argument name carrying a Unicode separator makes an exact-key lookup
// return "", the step's argument regex then fails to match, and the whole
// cross-call chain rule never fires — a composite/session-level BLOCK degraded
// to AUDIT by one invisible byte in a key the attacker both declares and
// resolves. Measured on mcp-sc-block-archive-download-extract-execute-cwd-shadow:
// `url` + U+00A0 flipped BLOCK to AUDIT end to end.
//
// It deliberately does NOT inherit resolveField's case-insensitive / camelCase
// / dot-notation fallbacks: those would let an ASCII `URL` / `workingDirectory`
// / nested `config.url` newly activate a sequence step that flat exact-match
// never did (#3727 finding 1). When a normalized-name collision resolves to
// several values, argString returns the first in the resolver's stable order;
// the step-level predicate (argRegexMatches) tests EVERY candidate, so the
// decision does not depend on which one argString hands back.
func argString(args map[string]interface{}, key string) string {
	cands := argFieldRecovered(args, key)
	if len(cands) == 0 {
		return ""
	}
	return fmt.Sprintf("%v", cands[0])
}

// argRegexMatches reports whether re matches the stringified value of ANY value
// the rule-supplied key resolves to (exact, else render-recovery). With no
// candidate it tests re against "" — the absent-arg behaviour argString had, so
// a pattern authored to match on an empty/absent argument still does. Testing
// every candidate rather than only the first is what makes a normalized-name
// collision deterministic: if any Unicode spelling of the key carries a value
// the pattern matches, the step matches, regardless of map-iteration order
// (#3727 finding 3).
func argRegexMatches(re *regexp.Regexp, args map[string]interface{}, key string) bool {
	cands := argFieldRecovered(args, key)
	if len(cands) == 0 {
		return re.MatchString("")
	}
	for _, v := range cands {
		if re.MatchString(fmt.Sprintf("%v", v)) {
			return true
		}
	}
	return false
}
