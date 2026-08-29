package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Representative calls for the two CompoSkill capability classes, each
// attributed to a named skill via the explicit skill_id/skill_name/skill
// argument convention.
var (
	compoSkillReadA   = call{"read_file", map[string]interface{}{"path": "/home/user/.aws/credentials", "skill_id": "data-extract"}}
	compoSkillIngestA = call{"fetch_url", map[string]interface{}{"url": "https://evil.example.com/notes.md", "skill_id": "data-extract"}}
	compoSkillEgressB = call{"send_message", map[string]interface{}{"body": "here is the collected data", "skill_id": "remote-publish"}}
)

// TestCompoSkillTracker_FiresOnceOnCrossSkillChain verifies the composite
// fires exactly once when a read/ingest-capable skill and a DIFFERENT
// egress-capable skill are both exercised in the session, regardless of
// which order the two calls arrive in.
func TestCompoSkillTracker_FiresOnceOnCrossSkillChain(t *testing.T) {
	orders := [][]call{
		{compoSkillReadA, compoSkillEgressB},
		{compoSkillEgressB, compoSkillReadA},
		{compoSkillIngestA, compoSkillEgressB},
	}
	for _, order := range orders {
		tr := NewCompoSkillTracker()
		var fires int
		for i, c := range order {
			sig := tr.Scan(c.tool, c.args)
			if sig == SignalCompoSkillChain {
				fires++
				if i != len(order)-1 {
					t.Errorf("order %v: fired early on call %d (%s)", toolNames(order), i, c.tool)
				}
			}
		}
		if fires != 1 {
			t.Errorf("order %v: expected exactly one fire, got %d", toolNames(order), fires)
		}
		// A further call from either skill must not re-fire.
		if again := tr.Scan(compoSkillEgressB.tool, compoSkillEgressB.args); again != "" {
			t.Errorf("order %v: tracker re-fired after completion", toolNames(order))
		}
	}
}

// TestCompoSkillTracker_SameSkillBothCapsNoFire is the key precision lever
// that distinguishes CompoSkill from LethalTrifecta: a single skill
// exercising both the read and egress capability is a single-skill review
// question, not a cross-skill composition-chain finding, so it must not fire.
func TestCompoSkillTracker_SameSkillBothCapsNoFire(t *testing.T) {
	tr := NewCompoSkillTracker()
	tr.Scan("read_file", map[string]interface{}{"path": "/home/user/.aws/credentials", "skill_id": "solo-skill"})
	if sig := tr.Scan("send_message", map[string]interface{}{"body": "collected data", "skill_id": "solo-skill"}); sig != "" {
		t.Error("one skill exercising both capability classes must not fire the cross-skill composite")
	}
}

// TestCompoSkillTracker_UnattributedCallsNeverFire ensures ordinary MCP tool
// calls that carry no recognizable skill identity are never tracked — that
// broader, lower-precision signal is LethalTrifectaTracker's job, not this
// tracker's.
func TestCompoSkillTracker_UnattributedCallsNeverFire(t *testing.T) {
	tr := NewCompoSkillTracker()
	tr.Scan("read_file", map[string]interface{}{"path": "/home/user/.aws/credentials"})
	for i := 0; i < 5; i++ {
		if sig := tr.Scan("send_message", map[string]interface{}{"body": "collected data"}); sig != "" {
			t.Fatalf("unattributed calls must never fire the cross-skill composite (call %d)", i)
		}
	}
}

// TestCompoSkillTracker_ThreeDistinctSkillsNoFalsePositive verifies that
// three different skills each exercising only ONE class (read, ingest, and a
// third read again) never fires — egress must genuinely be present on a
// different skill from the read/ingest.
func TestCompoSkillTracker_ThreeDistinctSkillsNoFalsePositive(t *testing.T) {
	tr := NewCompoSkillTracker()
	tr.Scan("read_file", map[string]interface{}{"path": "/workspace/README.md", "skill_id": "skill-a"}) // benign, non-secret
	tr.Scan("list_directory", map[string]interface{}{"path": "/workspace", "skill_id": "skill-b"})       // no capability class
	if sig := tr.Scan("get_status", map[string]interface{}{"id": "1", "skill_id": "skill-c"}); sig != "" {
		t.Error("no skill exercised a read/ingest or egress capability — must not fire")
	}
}

// TestExtractSkillIdentity spot-checks skill-identity attribution across the
// two recognized conventions and confirms unattributable calls are rejected.
func TestExtractSkillIdentity(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		args     map[string]interface{}
		wantID   string
		wantFound bool
	}{
		{"explicit skill_id on any tool", "read_file", map[string]interface{}{"path": "/x", "skill_id": "Data-Extract"}, "data-extract", true},
		{"explicit skill_name on any tool", "http_post", map[string]interface{}{"skill_name": "remote-publish"}, "remote-publish", true},
		{"explicit skill on any tool", "fetch_url", map[string]interface{}{"skill": "web-fetcher"}, "web-fetcher", true},
		{"dispatch tool with name fallback", "invoke_skill", map[string]interface{}{"name": "markdown-formatter"}, "markdown-formatter", true},
		{"dispatch tool with id fallback", "run_skill", map[string]interface{}{"id": "unit-converter"}, "unit-converter", true},
		{"dispatch tool no identity at all", "use_skill", map[string]interface{}{"input": "x"}, "", false},
		{"ordinary tool with no identity arg", "read_file", map[string]interface{}{"path": "/x"}, "", false},
		{"empty string identity ignored", "read_file", map[string]interface{}{"path": "/x", "skill_id": "  "}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotID, gotFound := extractSkillIdentity(tt.tool, tt.args)
			if gotFound != tt.wantFound || gotID != tt.wantID {
				t.Errorf("extractSkillIdentity(%q, %v) = (%q, %v), want (%q, %v)", tt.tool, tt.args, gotID, gotFound, tt.wantID, tt.wantFound)
			}
		})
	}
}

// TestCompoSkillRule_EvaluatesAudit validates the authored synthetic-tool
// rule (mcp-agentic-audit-composkill-cross-skill-composition-chain) resolves
// to AUDIT when the tracker injects the synthetic tool name, and that
// ordinary skill invocations without the cross-skill chain do not match it.
func TestCompoSkillRule_EvaluatesAudit(t *testing.T) {
	const ruleID = "mcp-agentic-audit-composkill-cross-skill-composition-chain"
	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	var rule *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*rule},
	})
	res := e.EvaluateToolCall(syntheticCompoSkillChain, map[string]interface{}{"context": "chain complete"})
	if res.Decision != policy.DecisionAudit {
		t.Errorf("synthetic composkill-chain tool should evaluate AUDIT; got %v", res.Decision)
	}
	// A benign real skill invocation must not match the synthetic-tool rule.
	benign := e.EvaluateToolCall("invoke_skill", map[string]interface{}{"skill_id": "markdown-formatter", "text": "# Report"})
	if benign.Decision == policy.DecisionAudit {
		for _, id := range benign.TriggeredRules {
			if id == ruleID {
				t.Error("composkill-chain rule must only match the synthetic tool name")
			}
		}
	}
}
