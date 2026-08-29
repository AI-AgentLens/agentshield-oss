package mcp

import (
	"strings"
	"sync"
)

// CompoSkillSignal is emitted once per session when two DIFFERENT skills'
// capabilities compose into a data-extract -> remote-publish chain.
type CompoSkillSignal string

const (
	// SignalCompoSkillChain fires the first time a session has one named
	// skill exercising a read/ingest capability and a DIFFERENT named skill
	// exercising an egress capability. AUDIT.
	SignalCompoSkillChain CompoSkillSignal = "composkill_chain"
)

// syntheticCompoSkillChain is the virtual tool name injected into the policy
// engine when the cross-skill composite completes, mirroring the
// lethal-trifecta / lateral-write session-composite approach.
const syntheticCompoSkillChain = "__mcp_composkill_chain__"

// compoSkillMaxSkills bounds the per-session skill set. A malicious or
// misbehaving server could otherwise grow this map unboundedly by varying a
// skill-identity argument on every call; 200 is far past any real agent
// session's distinct skill count.
const compoSkillMaxSkills = 200

// skillDispatchTools is the generic skill-invocation tool family used by
// marketplace/skill-runtime integrations that route every skill through one
// dispatcher tool (as opposed to registering one MCP tool per skill). A call
// to one of these needs a name/id/task argument to be attributed to a skill.
var skillDispatchTools = map[string]bool{
	"skill": true, "invoke_skill": true, "run_skill": true, "use_skill": true,
	"execute_skill": true, "load_skill": true, "call_skill": true,
	"activate_skill": true, "skill_run": true, "skill_execute": true,
	"skill_invoke": true,
}

// skillIdentityArgKeys are argument keys carrying an explicit skill identity,
// present regardless of which literal tool executes the call — the
// convention a marketplace/skill-runtime needs for its own telemetry to
// attribute a call back to the skill that issued it.
var skillIdentityArgKeys = []string{"skill_id", "skill_name", "skill"}

// skillIdentityFallbackKeys are consulted only when the tool itself is a
// recognized generic dispatcher (skillDispatchTools) and none of
// skillIdentityArgKeys is present.
var skillIdentityFallbackKeys = []string{"name", "id", "task"}

// extractSkillIdentity returns the skill identity a tool call should be
// attributed to, and whether one was found. A call this cannot attribute to
// a specific skill is not tracked by CompoSkillTracker at all — see the type
// doc for why that is deliberate.
func extractSkillIdentity(toolName string, args map[string]interface{}) (string, bool) {
	for _, k := range skillIdentityArgKeys {
		if s, ok := args[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.ToLower(strings.TrimSpace(s)), true
		}
	}
	if skillDispatchTools[strings.ToLower(strings.TrimSpace(toolName))] {
		for _, k := range skillIdentityFallbackKeys {
			if s, ok := args[k].(string); ok && strings.TrimSpace(s) != "" {
				return strings.ToLower(strings.TrimSpace(s)), true
			}
		}
	}
	return "", false
}

// skillCaps accumulates which capability classes a single named skill has
// exercised so far in the session.
type skillCaps struct {
	read   bool // private-data read OR untrusted ingest — the "data-extract" class
	egress bool // network egress / publish — the "remote-publish" class
}

// CompoSkillTracker detects the "CompoSkill" agent-skill composition-chain
// risk (arXiv:2608.16246, disclosed 2026-08-17; taxonomy:
// supply-chain/config-tampering/agent-skill-compositional-risk): marketplace
// skills are certified one at a time — a per-skill scanner verdict, then
// "ecosystem safe once every package passes." That fails under composition:
// a skill can pass individually and still participate in a harmful chain
// once an agent connects its outputs with a DIFFERENT scanner-passing
// skill's. Neither skill need be malicious on its own; the risk is a
// path-level property of the installed skill set, invisible to any
// single-skill review.
//
// This is deliberately narrower than LethalTrifectaTracker: trifecta fires
// on ANY session that has exercised private-read + untrusted-ingest +
// egress capabilities, regardless of which tool exercised which — a benign
// agent reading a config, fetching a page, and sending a Slack message trips
// it. CompoSkill requires the read/ingest-class and egress-class calls to
// come from two DIFFERENT, individually-identified skills — that cross-skill
// boundary is the entire point of the paper's finding (the taxonomy node's
// own "bad" example: a benign data-extract skill and a benign remote-publish
// skill, chained by a task description that names neither directly). A
// single skill doing both is a single-skill review question, not a
// composition-chain one, and is out of scope here.
//
// Skill attribution: see extractSkillIdentity. A call this tracker cannot
// attribute to a specific skill never contributes to it — ordinary
// (non-skill) MCP tool use is exactly what LethalTrifectaTracker already
// covers, and duplicating that broader signal here at lower precision (no
// skill-identity requirement) would add noise, not signal.
//
// Session-scoped: one tracker per MessageHandler, same family as
// LethalTrifectaTracker/GhostSpliceTracker/LateralWriteTracker. Fires once
// per session, mirroring the sibling trackers' one-shot AUDIT signal.
type CompoSkillTracker struct {
	mu     sync.Mutex
	skills map[string]*skillCaps
	fired  bool
}

// NewCompoSkillTracker returns a ready tracker with no recorded skills.
func NewCompoSkillTracker() *CompoSkillTracker {
	return &CompoSkillTracker{skills: make(map[string]*skillCaps)}
}

// Scan classifies the current tool call, attributes it to a skill identity
// (if recognizable), records the capability classes it exercises against
// that skill, and returns SignalCompoSkillChain the first time a read/ingest
// capability on one named skill and an egress capability on a DIFFERENT
// named skill are both present in the session — in either temporal order,
// mirroring LethalTrifectaTracker's order-agnostic accumulation. Returns ""
// on every other call: before the composite completes, after it has already
// fired once, and on any call this tracker cannot attribute to a skill.
func (t *CompoSkillTracker) Scan(toolName string, args map[string]interface{}) CompoSkillSignal {
	if t == nil {
		return ""
	}
	identity, ok := extractSkillIdentity(toolName, args)
	if !ok {
		return ""
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fired {
		return ""
	}

	caps := t.skills[identity]
	if caps == nil {
		if len(t.skills) >= compoSkillMaxSkills {
			return ""
		}
		caps = &skillCaps{}
		t.skills[identity] = caps
	}

	for _, c := range classifyTrifectaCaps(toolName, args) {
		switch c {
		case capPrivateRead, capUntrustedIngest:
			caps.read = true
		case capEgress:
			caps.egress = true
		}
	}

	for otherID, other := range t.skills {
		if otherID == identity {
			continue
		}
		if (caps.read && other.egress) || (caps.egress && other.read) {
			t.fired = true
			return SignalCompoSkillChain
		}
	}
	return ""
}
