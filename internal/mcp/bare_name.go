package mcp

import (
	"strings"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// BareToolName returns <tool> for a Claude Code namespaced MCP tool name
// mcp__<server>__<tool>. The server is the first segment: server names carry
// single underscores at most, so the first "__" after the prefix ends it.
func BareToolName(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "mcp__")
	if !ok {
		return "", false
	}
	i := strings.Index(rest, "__")
	if i <= 0 || i+2 >= len(rest) {
		return "", false
	}
	return rest[i+2:], true
}

// PreferBlockingBareResult chooses between the evaluation of a namespaced
// tool's wire name and the evaluation of its bare name (#4351). Pack rules are
// authored against the bare name (write_file, read_file, ...), so the wire
// name alone misses them. The bare reading is kept only when it blocks, or
// would block in enforce mode, and the wire reading does not. It is also kept
// when both readings decide the same and only the bare one matched a rule (#4379). Audit-only
// records "would block" as OriginalDecision; without that half, an audit-only
// install recorded no rule for the call at all. The result can only gain a
// block, or the record of one: it never lowers a decision.
//
// Every surface that evaluates a Claude Code MCP tool call goes through this:
// the hook and shield-server, which the enterprise gateway calls.
func PreferBlockingBareResult(wire, bare MCPEvalResult) MCPEvalResult {
	if blocksOrWouldBlock(bare) && !blocksOrWouldBlock(wire) {
		return bare
	}
	// Same decision, but only the bare reading names a rule: keep it, so the
	// receipt carries the rule and its taxonomy node (#4379). The decision is
	// identical, so nothing is raised or lowered.
	if bare.Decision == wire.Decision && bare.OriginalDecision == wire.OriginalDecision &&
		len(bare.TriggeredRules) > 0 && len(wire.TriggeredRules) == 0 {
		return bare
	}
	return wire
}

func blocksOrWouldBlock(r MCPEvalResult) bool {
	return r.Decision == policy.DecisionBlock || r.OriginalDecision == policy.DecisionBlock
}
