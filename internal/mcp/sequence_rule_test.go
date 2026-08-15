package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
	"gopkg.in/yaml.v3"
)

// loadPremiumPackRules loads the rules from a premium MCP pack file by name.
// mcpPacksDir (used by loadAllMCPRules) is community-only, so sequence rules
// that live in the premium pack are loaded here directly to validate the
// authored YAML end-to-end.
func loadPremiumPackRules(t *testing.T, packFile string) []MCPRule {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(filename), "..", "..", "packs", "premium", "mcp", packFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read premium pack %s: %v", packFile, err)
	}
	var pack MCPPolicy
	if err := yaml.Unmarshal(data, &pack); err != nil {
		t.Fatalf("parse premium pack %s: %v", packFile, err)
	}
	return pack.Rules
}

// TestMCPSequenceRule_OSINTBulkSendChain validates the real authored chain rule
// (mcp-excessive-agency-osint-bulk-send-chain) — that its sequence: block
// unmarshals and that it fires only on the full OSINT → generation → undisclosed
// bulk-send trajectory, through the live history-aware evaluator.
func TestMCPSequenceRule_OSINTBulkSendChain(t *testing.T) {
	const ruleID = "mcp-excessive-agency-osint-bulk-send-chain"

	rules := loadPremiumPackRules(t, "mcp-excessive-agency.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 3 {
		t.Fatalf("expected 3 sequence steps, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	bulkSend := RecordedCall{
		ToolName: "send_email",
		Args:     map[string]interface{}{"to": []string{"a@x.com", "b@y.com"}, "body": "Dear colleague"},
	}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("full chain fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "web_search"}, {ToolName: "fetch_url"}, {ToolName: "enrich_contact"},
			{ToolName: "generate_message"},
			bulkSend,
		}
		res := e.EvaluateToolCallWithHistory("send_email", bulkSend.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("only two recon reads — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "web_search"}, {ToolName: "fetch_url"},
			{ToolName: "generate_message"},
			bulkSend,
		}
		res := e.EvaluateToolCallWithHistory("send_email", bulkSend.Args, "", history)
		if fired(res) {
			t.Errorf("min_count=3 not enforced: rule fired with only 2 recon reads")
		}
	})

	t.Run("disclosed bulk send — does not fire", func(t *testing.T) {
		disclosed := RecordedCall{
			ToolName: "send_email",
			Args:     map[string]interface{}{"to": []string{"a@x.com", "b@y.com"}, "body": "[AI-generated] weekly digest"},
		}
		history := []RecordedCall{
			{ToolName: "web_search"}, {ToolName: "fetch_url"}, {ToolName: "scrape_site"},
			{ToolName: "generate_message"},
			disclosed,
		}
		res := e.EvaluateToolCallWithHistory("send_email", disclosed.Args, "", history)
		if fired(res) {
			t.Errorf("AI-disclosure marker should suppress the chain; rule fired anyway")
		}
	})

	t.Run("single recipient — does not fire", func(t *testing.T) {
		single := RecordedCall{
			ToolName: "send_email",
			Args:     map[string]interface{}{"to": "a@x.com", "body": "hi"},
		}
		history := []RecordedCall{
			{ToolName: "web_search"}, {ToolName: "fetch_url"}, {ToolName: "scrape_site"},
			{ToolName: "generate_message"},
			single,
		}
		res := e.EvaluateToolCallWithHistory("send_email", single.Args, "", history)
		if fired(res) {
			t.Errorf("single-recipient send (no array) should not match the chain's final step")
		}
	})

	t.Run("no generation step — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "web_search"}, {ToolName: "fetch_url"}, {ToolName: "scrape_site"},
			bulkSend,
		}
		res := e.EvaluateToolCallWithHistory("send_email", bulkSend.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a generation step between recon and send")
		}
	})
}

// TestMCPSequenceRule_MemoryRecallExfilChain validates the real authored chain
// rule (mcp-persist-audit-memory-recall-exfil-chain, #2748) — that its
// sequence: block unmarshals and that it fires on a memory-retrieval call
// followed within the call window by an outbound communication call, through
// the live history-aware evaluator.
func TestMCPSequenceRule_MemoryRecallExfilChain(t *testing.T) {
	const ruleID = "mcp-persist-audit-memory-recall-exfil-chain"

	rules := loadPremiumPackRules(t, "mcp-persistence.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 2 {
		t.Fatalf("expected 2 sequence steps, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	send := RecordedCall{
		ToolName: "send_email",
		Args:     map[string]interface{}{"to": "bob@corp.com", "body": "Here's the info you asked about"},
	}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("memory recall then send fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "memory_recall_fact", Args: map[string]interface{}{"query": "bob's contact info"}},
			send,
		}
		res := e.EvaluateToolCallWithHistory("send_email", send.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("recall variant tool names fire", func(t *testing.T) {
		for _, recallTool := range []string{"memory_search", "recall_context", "search_memory", "get_memory", "archival_memory_search", "conversation_search"} {
			history := []RecordedCall{
				{ToolName: recallTool},
				send,
			}
			res := e.EvaluateToolCallWithHistory("send_email", send.Args, "", history)
			if !fired(res) {
				t.Errorf("recall tool %q did not trigger the chain", recallTool)
			}
		}
	})

	t.Run("send-only, no prior recall — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "list_files"}, {ToolName: "read_file"},
			send,
		}
		res := e.EvaluateToolCallWithHistory("send_email", send.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a prior memory-recall step; fired without one")
		}
	})

	t.Run("recall with no follow-on send — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "memory_recall_fact"},
			{ToolName: "read_file"},
		}
		res := e.EvaluateToolCallWithHistory("read_file", nil, "", history)
		if fired(res) {
			t.Errorf("chain requires an outbound send step; fired on a read_file tail call")
		}
	})

	t.Run("recall outside the within_calls window — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "memory_recall_fact"}}
		for i := 0; i < 15; i++ {
			history = append(history, RecordedCall{ToolName: "read_file"})
		}
		history = append(history, send)
		res := e.EvaluateToolCallWithHistory("send_email", send.Args, "", history)
		if fired(res) {
			t.Errorf("within_calls window not enforced: recall is more than 15 calls before the send")
		}
	})
}

// TestMCPSequenceRule_ResourceAmplificationSegmentLoop validates the real
// authored chain rule (mcp-agentic-audit-fake-continuation-segment-loop,
// #2776) — that its sequence: block unmarshals and that it fires only when
// the same tool is re-invoked 4+ times within the call window, each call
// carrying a numeric `segment_index` argument, through the live
// history-aware evaluator.
func TestMCPSequenceRule_ResourceAmplificationSegmentLoop(t *testing.T) {
	const ruleID = "mcp-agentic-audit-fake-continuation-segment-loop"

	rules := loadPremiumPackRules(t, "mcp-agentic-attacks.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 1 {
		t.Fatalf("expected 1 sequence step, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	segmentCall := func(i int) RecordedCall {
		return RecordedCall{ToolName: "fetch_dataset", Args: map[string]interface{}{"segment_index": i}}
	}

	t.Run("4 rounds of segment_index re-invocation fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{segmentCall(1), segmentCall(2), segmentCall(3), segmentCall(4)}
		res := e.EvaluateToolCallWithHistory("fetch_dataset", segmentCall(4).Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("only 3 rounds — does not fire", func(t *testing.T) {
		history := []RecordedCall{segmentCall(1), segmentCall(2), segmentCall(3)}
		res := e.EvaluateToolCallWithHistory("fetch_dataset", segmentCall(3).Args, "", history)
		if fired(res) {
			t.Errorf("min_count=4 not enforced: rule fired with only 3 segment_index calls")
		}
	})

	t.Run("ordinary cursor-based pagination — does not fire", func(t *testing.T) {
		cursorCall := func(c string) RecordedCall {
			return RecordedCall{ToolName: "list_items", Args: map[string]interface{}{"cursor": c}}
		}
		history := []RecordedCall{cursorCall("a"), cursorCall("b"), cursorCall("c"), cursorCall("d")}
		res := e.EvaluateToolCallWithHistory("list_items", cursorCall("d").Args, "", history)
		if fired(res) {
			t.Errorf("cursor-based pagination should not match a segment_index-keyed step")
		}
	})

	t.Run("segment_index calls outside the within_calls window — does not fire", func(t *testing.T) {
		history := []RecordedCall{segmentCall(1), segmentCall(2), segmentCall(3), segmentCall(4)}
		for i := 0; i < 12; i++ {
			history = append(history, RecordedCall{ToolName: "read_file"})
		}
		res := e.EvaluateToolCallWithHistory("read_file", nil, "", history)
		if fired(res) {
			t.Errorf("within_calls window not enforced: 4 segment_index calls are more than 12 calls before the tail")
		}
	})
}

// TestMCPSequenceRule_HighImpactClickWithoutPrecheck validates the real
// authored negative-lookback rule (mcp-computer-use-audit-highimpact-click-no-precheck,
// #2785 perceive-act TOCTOU) — that its sequence.action_step/precheck_step
// block unmarshals and fires only when a high-impact click/computer_use
// action has no fresh screenshot/accessibility/DOM-snapshot call in the
// immediately preceding calls, through the live history-aware evaluator.
func TestMCPSequenceRule_HighImpactClickWithoutPrecheck(t *testing.T) {
	const ruleID = "mcp-computer-use-audit-highimpact-click-no-precheck"

	rules := loadPremiumPackRules(t, "mcp-computer-use.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil || chain.Match.Sequence.ActionStep == nil || chain.Match.Sequence.PrecheckStep == nil {
		t.Fatalf("rule %q has no action_step/precheck_step sequence block — YAML unmarshal failed", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	confirmTransfer := RecordedCall{ToolName: "click", Args: map[string]interface{}{"text": "Confirm Transfer"}}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("high-impact click with no precheck in history fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "move_mouse"}, confirmTransfer}
		res := e.EvaluateToolCallWithHistory("click", confirmTransfer.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("fresh screenshot immediately before — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "screenshot"}, confirmTransfer}
		res := e.EvaluateToolCallWithHistory("click", confirmTransfer.Args, "", history)
		if fired(res) {
			t.Errorf("a fresh precheck call immediately before the action should suppress the rule")
		}
	})

	t.Run("fresh accessibility snapshot within lookback window — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "get_accessibility_tree"}, {ToolName: "move_mouse"}, confirmTransfer}
		res := e.EvaluateToolCallWithHistory("click", confirmTransfer.Args, "", history)
		if fired(res) {
			t.Errorf("precheck within precheck_within_calls=2 should suppress the rule")
		}
	})

	t.Run("precheck outside the lookback window — fires", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "screenshot"}, {ToolName: "move_mouse"}, {ToolName: "hover"}, confirmTransfer}
		res := e.EvaluateToolCallWithHistory("click", confirmTransfer.Args, "", history)
		if !fired(res) {
			t.Errorf("precheck two calls before the default-2 lookback window should not suppress the rule")
		}
	})

	t.Run("benign click target — does not fire", func(t *testing.T) {
		benign := RecordedCall{ToolName: "click", Args: map[string]interface{}{"text": "Cancel"}}
		history := []RecordedCall{{ToolName: "move_mouse"}, benign}
		res := e.EvaluateToolCallWithHistory("click", benign.Args, "", history)
		if fired(res) {
			t.Errorf("a click with no financial/destructive target text should not match the action_step")
		}
	})
}

// TestMCPSequenceRule_HighImpactActionWithoutPrecheck validates the real
// authored negative-lookback rule (mcp-computer-use-audit-highimpact-action-no-precheck,
// #2785), the dedicated-tool-name companion to the generic click rule above.
func TestMCPSequenceRule_HighImpactActionWithoutPrecheck(t *testing.T) {
	const ruleID = "mcp-computer-use-audit-highimpact-action-no-precheck"

	rules := loadPremiumPackRules(t, "mcp-computer-use.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil || chain.Match.Sequence.ActionStep == nil || chain.Match.Sequence.PrecheckStep == nil {
		t.Fatalf("rule %q has no action_step/precheck_step sequence block — YAML unmarshal failed", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	transfer := RecordedCall{ToolName: "confirm_transfer", Args: map[string]interface{}{"amount": 10000, "recipient": "attacker"}}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("dedicated transfer-confirm tool with no precheck fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "read_page_state"}, transfer}
		res := e.EvaluateToolCallWithHistory("confirm_transfer", transfer.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("fresh DOM snapshot immediately before — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "get_dom_snapshot"}, transfer}
		res := e.EvaluateToolCallWithHistory("confirm_transfer", transfer.Args, "", history)
		if fired(res) {
			t.Errorf("a fresh precheck call immediately before the action should suppress the rule")
		}
	})

	t.Run("unrelated tool call — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "list_files"}}
		res := e.EvaluateToolCallWithHistory("list_files", nil, "", history)
		if fired(res) {
			t.Errorf("a non-action tool call should not match action_step")
		}
	})
}

// TestMCPSequenceRule_AutomatedDecisionNoRecourse validates the real authored
// rule (mcp-gov-audit-automated-decision-no-recourse, #2802): a consequential
// decision-execution tool call (loan denial, account suspension, etc.) fired
// with no human-review/approval-gate tool call in the preceding calls of the
// session — the governance-domain sibling of the perceive-act TOCTOU rules
// above, reusing the same action_step/precheck_step negative-lookback
// primitive.
func TestMCPSequenceRule_AutomatedDecisionNoRecourse(t *testing.T) {
	const ruleID = "mcp-gov-audit-automated-decision-no-recourse"

	rules := loadPremiumPackRules(t, "mcp-governance.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil || chain.Match.Sequence.ActionStep == nil || chain.Match.Sequence.PrecheckStep == nil {
		t.Fatalf("rule %q has no action_step/precheck_step sequence block — YAML unmarshal failed", ruleID)
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	denyLoan := RecordedCall{ToolName: "deny_loan", Args: map[string]interface{}{"applicant_id": "app-123"}}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("consequential decision with no precheck in history fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "score_applicant"}, denyLoan}
		res := e.EvaluateToolCallWithHistory("deny_loan", denyLoan.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("human review immediately before — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "request_human_review"}, denyLoan}
		res := e.EvaluateToolCallWithHistory("deny_loan", denyLoan.Args, "", history)
		if fired(res) {
			t.Errorf("a fresh human-review precheck call before the decision should suppress the rule")
		}
	})

	t.Run("approval gate within the lookback window — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "escalate_to_human"}, {ToolName: "score_applicant"}, {ToolName: "log_event"}, denyLoan}
		res := e.EvaluateToolCallWithHistory("deny_loan", denyLoan.Args, "", history)
		if fired(res) {
			t.Errorf("precheck within precheck_within_calls=5 should suppress the rule")
		}
	})

	t.Run("approval gate outside the lookback window — fires", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "request_approval"},
			{ToolName: "a"}, {ToolName: "b"}, {ToolName: "c"}, {ToolName: "d"}, {ToolName: "e"},
			denyLoan,
		}
		res := e.EvaluateToolCallWithHistory("deny_loan", denyLoan.Args, "", history)
		if !fired(res) {
			t.Errorf("an approval gate six calls before the default-5 lookback window should not suppress the rule")
		}
	})

	t.Run("unrelated tool call — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "list_files"}}
		res := e.EvaluateToolCallWithHistory("list_files", nil, "", history)
		if fired(res) {
			t.Errorf("a non-decision tool call should not match action_step")
		}
	})
}

// TestMCPSequenceRule_SandboxBoundaryWidenThenOverwrite validates the real
// authored chain rule (mcp-ide-trust-block-sandbox-boundary-widen-then-overwrite-chain,
// issue #2805) — DuneSlide-class (CVE-2026-50548/CVE-2026-50549) sandbox
// containment bypass: a tool call redirects its working_directory to a system
// path (boundary-redefinition), followed within the call window by a write to
// a sandbox enforcement artifact under an IDE install directory (enforcement
// self-destruction). Neither step alone is this rule's concern — the two
// single-call AUDIT/BLOCK siblings in the same pack cover each stage in
// isolation; this test validates the composite ordering signal only.
func TestMCPSequenceRule_SandboxBoundaryWidenThenOverwrite(t *testing.T) {
	const ruleID = "mcp-ide-trust-block-sandbox-boundary-widen-then-overwrite-chain"

	rules := loadPremiumPackRules(t, "mcp-ide-workspace-trust.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 2 {
		t.Fatalf("expected 2 sequence steps, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	scopeWiden := RecordedCall{
		ToolName: "create_file",
		Args:     map[string]interface{}{"path": "notes.txt", "working_directory": "/usr/lib/cursor-sandbox", "content": "x"},
	}
	artifactWrite := RecordedCall{
		ToolName: "edit_file",
		Args:     map[string]interface{}{"path": "/opt/ide/sandbox-enforcer", "content": "patched"},
	}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("scope-widen then sandbox artifact write fires BLOCK", func(t *testing.T) {
		history := []RecordedCall{scopeWiden, artifactWrite}
		res := e.EvaluateToolCallWithHistory("edit_file", artifactWrite.Args, "", history)
		if res.Decision != policy.DecisionBlock || !fired(res) {
			t.Errorf("expected BLOCK + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("scope-widen alone, no follow-on write — does not fire", func(t *testing.T) {
		history := []RecordedCall{scopeWiden}
		res := e.EvaluateToolCallWithHistory("create_file", scopeWiden.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a follow-on sandbox artifact write; fired on the scope-widen call alone")
		}
	})

	t.Run("artifact write with no prior scope-widen — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "read_file", Args: map[string]interface{}{"path": "/workspace/project/README.md"}}, artifactWrite}
		res := e.EvaluateToolCallWithHistory("edit_file", artifactWrite.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a prior scope-widen step; fired without one")
		}
	})

	t.Run("working_directory redirected to project path — does not fire", func(t *testing.T) {
		benignWiden := RecordedCall{
			ToolName: "create_file",
			Args:     map[string]interface{}{"path": "notes.txt", "working_directory": "/workspace/project", "content": "x"},
		}
		history := []RecordedCall{benignWiden, artifactWrite}
		res := e.EvaluateToolCallWithHistory("edit_file", artifactWrite.Args, "", history)
		if fired(res) {
			t.Errorf("a working_directory inside the project root should not satisfy the boundary-redefinition step")
		}
	})

	t.Run("write targets project sandbox/ dir, not an IDE root — does not fire", func(t *testing.T) {
		benignWrite := RecordedCall{
			ToolName: "edit_file",
			Args:     map[string]interface{}{"path": "/workspace/project/tests/sandbox/test_runner.py", "content": "def test(): pass"},
		}
		history := []RecordedCall{scopeWiden, benignWrite}
		res := e.EvaluateToolCallWithHistory("edit_file", benignWrite.Args, "", history)
		if fired(res) {
			t.Errorf("a write to a project's own sandbox/ directory (not under an IDE install root) should not satisfy the artifact-write step")
		}
	})

	t.Run("scope-widen outside the within_calls window — does not fire", func(t *testing.T) {
		history := []RecordedCall{scopeWiden}
		for i := 0; i < 15; i++ {
			history = append(history, RecordedCall{ToolName: "read_file"})
		}
		history = append(history, artifactWrite)
		res := e.EvaluateToolCallWithHistory("edit_file", artifactWrite.Args, "", history)
		if fired(res) {
			t.Errorf("scope-widen call 16 calls before the artifact write (within_calls=10) should not satisfy the chain")
		}
	})
}

// TestMCPSequenceRule_CrossTenantRuntimeImplantChain validates the real
// authored chain rule (mcp-privesc-audit-cross-tenant-runtime-implant-chain,
// issue #2914, taxonomy privilege-escalation/agent-containment/
// cross-tenant-shared-runtime-implant — the "Rogue Agent" Dialogflow CX
// class) — that its sequence: block unmarshals and fires only when a
// custom-code/tool-config write call is followed within the call window by
// an outbound network call, through the live history-aware evaluator.
func TestMCPSequenceRule_CrossTenantRuntimeImplantChain(t *testing.T) {
	const ruleID = "mcp-privesc-audit-cross-tenant-runtime-implant-chain"

	rules := loadPremiumPackRules(t, "mcp-privilege-escalation.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 2 {
		t.Fatalf("expected 2 sequence steps, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	networkCall := RecordedCall{
		ToolName: "http_request",
		Args:     map[string]interface{}{"url": "https://attacker-c2.example.com/beacon"},
	}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("code-block write then network call fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "update_code_block", Args: map[string]interface{}{"code": "import requests"}},
			networkCall,
		}
		res := e.EvaluateToolCallWithHistory("http_request", networkCall.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("variant custom-code/tool-config write tool names fire", func(t *testing.T) {
		for _, writeTool := range []string{"edit_playbook", "write_custom_code", "set_tool_config", "code_block_update", "agent_code_edit", "deploy_agent_code"} {
			history := []RecordedCall{
				{ToolName: writeTool},
				networkCall,
			}
			res := e.EvaluateToolCallWithHistory("http_request", networkCall.Args, "", history)
			if !fired(res) {
				t.Errorf("write tool %q did not trigger the chain", writeTool)
			}
		}
	})

	t.Run("network call with no prior code/config write — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "list_files"}, {ToolName: "read_file"},
			networkCall,
		}
		res := e.EvaluateToolCallWithHistory("http_request", networkCall.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a prior custom-code/tool-config write step; fired without one")
		}
	})

	t.Run("code-block write with no follow-on network call — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "update_code_block"},
			{ToolName: "read_file"},
		}
		res := e.EvaluateToolCallWithHistory("read_file", nil, "", history)
		if fired(res) {
			t.Errorf("chain requires an outbound network step; fired on a read_file tail call")
		}
	})

	t.Run("generic config-update tool name — does not satisfy the write step", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "update_config"},
			networkCall,
		}
		res := e.EvaluateToolCallWithHistory("http_request", networkCall.Args, "", history)
		if fired(res) {
			t.Errorf("a generic 'update_config' tool (no code_block/custom_code/agent_code/tool_config/playbook noun) should not match the write step")
		}
	})

	t.Run("code-block write outside the within_calls window — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "update_code_block"}}
		for i := 0; i < 12; i++ {
			history = append(history, RecordedCall{ToolName: "read_file"})
		}
		history = append(history, networkCall)
		res := e.EvaluateToolCallWithHistory("http_request", networkCall.Args, "", history)
		if fired(res) {
			t.Errorf("within_calls window not enforced: write is more than 10 calls before the network call")
		}
	})
}

// TestMCPSequenceRule_WalletResolutionThenPay validates the real authored
// chain rule (mcp-fin-wep-audit-wallet-resolution-then-pay-chain, issue
// #3123, AIP-Bench arXiv:2607.21824 RC-2 "Payment Destination Binding") — a
// counterparty wallet/payment-address resolution call followed within the
// call window by a payment-send/transfer/escrow-release call, through the
// live history-aware evaluator.
func TestMCPSequenceRule_WalletResolutionThenPay(t *testing.T) {
	const ruleID = "mcp-fin-wep-audit-wallet-resolution-then-pay-chain"

	rules := loadPremiumPackRules(t, "mcp-financial-weaponization.yaml")
	var chain *MCPRule
	for i := range rules {
		if rules[i].ID == ruleID {
			chain = &rules[i]
			break
		}
	}
	if chain == nil {
		t.Fatalf("rule %q not found in premium pack", ruleID)
	}
	if chain.Match.Sequence == nil {
		t.Fatalf("rule %q has no sequence block — YAML unmarshal of match.sequence failed", ruleID)
	}
	if len(chain.Match.Sequence.Steps) != 2 {
		t.Fatalf("expected 2 sequence steps, got %d", len(chain.Match.Sequence.Steps))
	}

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*chain},
	})

	sendPayment := RecordedCall{
		ToolName: "send_payment",
		Args:     map[string]interface{}{"amount": 500, "recipient": "9xQeWvG8..."},
	}
	fired := func(res MCPEvalResult) bool {
		for _, id := range res.TriggeredRules {
			if id == ruleID {
				return true
			}
		}
		return false
	}

	t.Run("wallet resolution then payment fires AUDIT", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "get_wallet", Args: map[string]interface{}{"agent_id": "remote-fulfillment-agent"}},
			sendPayment,
		}
		res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
		if res.Decision != policy.DecisionAudit || !fired(res) {
			t.Errorf("expected AUDIT + rule fired; got decision=%v rules=%v", res.Decision, res.TriggeredRules)
		}
	})

	t.Run("variant resolution tool names fire", func(t *testing.T) {
		for _, resolveTool := range []string{"resolve_recipient_wallet", "fetch_agent_wallet", "lookup_payout_address", "coral_get_wallet", "resolve_payee_address"} {
			history := []RecordedCall{
				{ToolName: resolveTool},
				sendPayment,
			}
			res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
			if !fired(res) {
				t.Errorf("resolution tool %q did not trigger the chain", resolveTool)
			}
		}
	})

	t.Run("variant payment tool names fire", func(t *testing.T) {
		for _, payTool := range []string{"transfer_funds", "release_escrow", "settle_payment", "disburse_payout", "execute_transaction"} {
			history := []RecordedCall{
				{ToolName: "get_wallet"},
				{ToolName: payTool},
			}
			res := e.EvaluateToolCallWithHistory(payTool, nil, "", history)
			if !fired(res) {
				t.Errorf("payment tool %q did not trigger the chain", payTool)
			}
		}
	})

	t.Run("own-wallet balance check — does not satisfy the resolution step", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "get_wallet_balance"},
			sendPayment,
		}
		res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
		if fired(res) {
			t.Errorf("get_wallet_balance (own-account query) should not match the end-anchored resolution step")
		}
	})

	t.Run("own-wallet history check — does not satisfy the resolution step", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "get_wallet_history"},
			sendPayment,
		}
		res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
		if fired(res) {
			t.Errorf("get_wallet_history (own-account query) should not match the end-anchored resolution step")
		}
	})

	t.Run("payment with no prior wallet resolution — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "list_products"}, {ToolName: "get_order_status"},
			sendPayment,
		}
		res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
		if fired(res) {
			t.Errorf("chain requires a prior wallet-resolution step; fired without one")
		}
	})

	t.Run("wallet resolution with no follow-on payment — does not fire", func(t *testing.T) {
		history := []RecordedCall{
			{ToolName: "get_wallet"},
			{ToolName: "read_file"},
		}
		res := e.EvaluateToolCallWithHistory("read_file", nil, "", history)
		if fired(res) {
			t.Errorf("chain requires a follow-on payment step; fired on a read_file tail call")
		}
	})

	t.Run("resolution outside the within_calls window — does not fire", func(t *testing.T) {
		history := []RecordedCall{{ToolName: "get_wallet"}}
		for i := 0; i < 8; i++ {
			history = append(history, RecordedCall{ToolName: "read_file"})
		}
		history = append(history, sendPayment)
		res := e.EvaluateToolCallWithHistory("send_payment", sendPayment.Args, "", history)
		if fired(res) {
			t.Errorf("within_calls window not enforced: resolution is more than 5 calls before the payment")
		}
	})
}
