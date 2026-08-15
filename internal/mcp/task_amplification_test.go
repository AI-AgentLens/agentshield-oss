package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// --- IsTaskAugmented ---

func TestIsTaskAugmented(t *testing.T) {
	tests := []struct {
		name string
		task json.RawMessage
		want bool
	}{
		{"absent", nil, false},
		{"empty", json.RawMessage(""), false},
		{"null", json.RawMessage("null"), false},
		{"false", json.RawMessage("false"), false},
		{"true", json.RawMessage("true"), true},
		{"object", json.RawMessage(`{"ttl":3600}`), true},
		{"whitespace-padded true", json.RawMessage(" true "), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsTaskAugmented(tt.task); got != tt.want {
				t.Errorf("IsTaskAugmented(%q) = %v, want %v", tt.task, got, tt.want)
			}
		})
	}
}

// --- TaskAmplificationTracker ---

// TestTaskAmplificationTracker_BurstFiresAtThreshold verifies the composite
// signal fires exactly on the call that reaches the burst threshold (5
// task-augmented creates in the window), not before.
func TestTaskAmplificationTracker_BurstFiresAtThreshold(t *testing.T) {
	tr := NewTaskAmplificationTracker()
	var fires int
	for i := 0; i < taskAmplificationBurstThreshold; i++ {
		sig := tr.ScanCreate()
		tr.RecordCreate()
		if sig == SignalTaskAmplificationUnpolledBurst {
			fires++
			if i != taskAmplificationBurstThreshold-1 {
				t.Errorf("fired early on create %d (want fire only on create %d)", i, taskAmplificationBurstThreshold-1)
			}
		}
	}
	if fires != 1 {
		t.Errorf("expected exactly one fire at threshold, got %d", fires)
	}
}

// TestTaskAmplificationTracker_PollSuppressesBurst verifies that a single
// tasks/get or tasks/result poll within the window suppresses the burst
// signal even when create volume alone would otherwise trip it — the
// discriminator between a fire-and-forget fan-out and normal async usage.
func TestTaskAmplificationTracker_PollSuppressesBurst(t *testing.T) {
	tr := NewTaskAmplificationTracker()
	tr.RecordCreate()
	tr.RecordCreate()
	tr.RecordPoll() // client retrieves a result mid-burst
	tr.RecordCreate()
	tr.RecordCreate()
	if sig := tr.ScanCreate(); sig != "" {
		t.Errorf("expected no signal with a poll present in the window, got %q", sig)
	}
}

// TestTaskAmplificationTracker_BelowThresholdNoFire ensures ordinary
// occasional task usage (well under the burst threshold) never fires.
func TestTaskAmplificationTracker_BelowThresholdNoFire(t *testing.T) {
	tr := NewTaskAmplificationTracker()
	for i := 0; i < taskAmplificationBurstThreshold-2; i++ {
		if sig := tr.ScanCreate(); sig != "" {
			t.Fatalf("create %d: unexpected signal %q below threshold", i, sig)
		}
		tr.RecordCreate()
	}
}

// --- Authored YAML rule resolution ---

// TestTaskAmplificationBurstRule_EvaluatesAudit validates the authored
// synthetic-tool rule (mcp-agentic-audit-task-amplification-unpolled-burst)
// resolves to AUDIT for the tracker's synthetic tool name, and does not
// match an unrelated real tool call.
func TestTaskAmplificationBurstRule_EvaluatesAudit(t *testing.T) {
	const ruleID = "mcp-agentic-audit-task-amplification-unpolled-burst"
	rule := findRuleByID(t, loadPremiumPackRules(t, "mcp-agentic-attacks.yaml"), ruleID)

	e := NewPolicyEvaluator(&MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules:    []MCPRule{*rule},
	})
	res := e.EvaluateToolCall(syntheticTaskAmplificationBurst, map[string]interface{}{"context": "burst"})
	if res.Decision != policy.DecisionAudit {
		t.Errorf("synthetic burst tool should evaluate AUDIT; got %v", res.Decision)
	}

	benign := e.EvaluateToolCall("read_file", map[string]interface{}{"path": "/workspace/README.md"})
	for _, id := range benign.TriggeredRules {
		if id == ruleID {
			t.Error("burst rule must only match the synthetic tool name")
		}
	}
}

// TestTaskAmplificationSentinels_ResolveViaLookupSentinel validates both
// engine-backed sentinel rules (mcp-sentinel.yaml) are discoverable through
// LookupSentinel using the exact engine keys HandleToolCall and
// HandleSamplingCreateMessage pass at runtime.
func TestTaskAmplificationSentinels_ResolveViaLookupSentinel(t *testing.T) {
	rules := loadPremiumPackRules(t, "mcp-sentinel.yaml")
	e := NewPolicyEvaluator(&MCPPolicy{Rules: rules})

	for _, engine := range []string{"mcp-task-augmented-expensive-wrap", "mcp-task-augmented-expensive-sampling"} {
		sent := e.LookupSentinel(engine)
		if sent == nil {
			t.Fatalf("LookupSentinel(%q) returned nil — sentinel rule missing from mcp-sentinel.yaml", engine)
		}
		if sent.Taxonomy != "unauthorized-execution/agentic-attacks/mcp-async-task-amplification-dos" {
			t.Errorf("engine %q: unexpected taxonomy %q", engine, sent.Taxonomy)
		}
		if sent.Decision != policy.DecisionAudit {
			t.Errorf("engine %q: expected AUDIT decision, got %v", engine, sent.Decision)
		}
	}
}

// --- End-to-end HandleToolCall / HandleSamplingCreateMessage ---

// newTaskAmplificationTestHandler builds a handler wired with a fresh
// TaskAmplificationTracker plus a minimal policy: a rule that flags
// "expensive_tool" as BLOCK (standing in for any pre-existing rule that
// already flagged the wrapped operation), the two engine sentinels, and the
// burst composite rule loaded from their real authored YAML.
func newTaskAmplificationTestHandler(t *testing.T) (*MessageHandler, *bytes.Buffer) {
	t.Helper()
	sentinelRules := loadPremiumPackRules(t, "mcp-sentinel.yaml")
	wrapSentinel := findRuleByID(t, sentinelRules, "mcp-task-augmented-expensive-wrap-sentinel")
	samplingSentinel := findRuleByID(t, sentinelRules, "mcp-task-augmented-expensive-sampling-sentinel")
	burstRule := findRuleByID(t, loadPremiumPackRules(t, "mcp-agentic-attacks.yaml"), "mcp-agentic-audit-task-amplification-unpolled-burst")

	policyDef := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAllow},
		Rules: []MCPRule{
			{
				ID:       "test-already-flagged",
				Match:    MCPMatch{ToolName: "expensive_tool"},
				Decision: policy.DecisionBlock,
				Reason:   "test: already flagged expensive",
			},
			*wrapSentinel,
			*samplingSentinel,
			*burstRule,
		},
	}

	var buf bytes.Buffer
	return &MessageHandler{
		Evaluator:         NewPolicyEvaluator(policyDef),
		Stderr:            &buf,
		TaskAmplification: NewTaskAmplificationTracker(),
	}, &buf
}

func findRuleByID(t *testing.T, rules []MCPRule, id string) *MCPRule {
	t.Helper()
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	t.Fatalf("rule %q not found", id)
	return nil
}

func toolCallMessage(t *testing.T, name string, args map[string]interface{}, task json.RawMessage) *Message {
	t.Helper()
	return &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name:      name,
			Arguments: args,
			Task:      task,
		}),
	}
}

// TestHandleToolCall_TaskAugmentedExpensiveWrap_Escalates verifies a
// task-augmented call to an already-flagged tool surfaces the expensive-wrap
// sentinel in the audit trail.
func TestHandleToolCall_TaskAugmentedExpensiveWrap_Escalates(t *testing.T) {
	h, buf := newTaskAmplificationTestHandler(t)
	msg := toolCallMessage(t, "expensive_tool", map[string]interface{}{"scope": "entire_dataset"}, json.RawMessage("true"))

	blocked, _ := h.HandleToolCall(msg)
	if !blocked {
		t.Fatal("expensive_tool must still BLOCK on its own merits")
	}
	if !strings.Contains(buf.String(), "task-amplification expensive-wrap") {
		t.Errorf("expected task-amplification expensive-wrap audit line, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_TaskAugmentedAllowedTool_NoEscalation verifies a
// task-augmented call to an otherwise-ALLOW tool does NOT get the
// expensive-wrap treatment — matches taxonomy's own "good" example (a small,
// bounded task-wrapped read stays quiet).
func TestHandleToolCall_TaskAugmentedAllowedTool_NoEscalation(t *testing.T) {
	h, buf := newTaskAmplificationTestHandler(t)
	msg := toolCallMessage(t, "read_file", map[string]interface{}{"path": "/workspace/project/data.csv"}, json.RawMessage("true"))

	blocked, _ := h.HandleToolCall(msg)
	if blocked {
		t.Fatal("a task-wrapped ALLOW call must not be blocked")
	}
	if strings.Contains(buf.String(), "expensive-wrap") {
		t.Errorf("must not escalate a task-wrapped call that wasn't already flagged, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_TaskAmplificationBurst_FiresOnUnpolledVolume drives
// HandleToolCall directly to prove the burst composite fires end-to-end once
// the session opens enough task-augmented calls with no polls, and stays
// quiet when a poll is recorded in between.
func TestHandleToolCall_TaskAmplificationBurst_FiresOnUnpolledVolume(t *testing.T) {
	h, buf := newTaskAmplificationTestHandler(t)

	for i := 0; i < taskAmplificationBurstThreshold-1; i++ {
		msg := toolCallMessage(t, "read_file", map[string]interface{}{"path": "/workspace/data.csv"}, json.RawMessage("true"))
		if blocked, _ := h.HandleToolCall(msg); blocked {
			t.Fatalf("call %d unexpectedly blocked", i)
		}
	}
	if strings.Contains(buf.String(), "unpolled burst") {
		t.Fatalf("burst must not fire before threshold, got:\n%s", buf.String())
	}

	// The call that reaches the threshold must trip the composite.
	final := toolCallMessage(t, "read_file", map[string]interface{}{"path": "/workspace/data.csv"}, json.RawMessage("true"))
	h.HandleToolCall(final)
	if !strings.Contains(buf.String(), "unpolled burst") {
		t.Errorf("expected unpolled-burst audit at threshold, got:\n%s", buf.String())
	}
}

// TestHandleToolCall_TaskAmplificationBurst_SuppressedByPoll verifies a
// tasks/get poll recorded via HandleTaskPollRequest (the real client→server
// dispatch path) suppresses the burst signal even at threshold volume.
func TestHandleToolCall_TaskAmplificationBurst_SuppressedByPoll(t *testing.T) {
	h, buf := newTaskAmplificationTestHandler(t)

	h.HandleTaskPollRequest(&Message{JSONRPC: "2.0", ID: mustRequestID(t), Method: MethodTasksGet})

	for i := 0; i < taskAmplificationBurstThreshold; i++ {
		msg := toolCallMessage(t, "read_file", map[string]interface{}{"path": "/workspace/data.csv"}, json.RawMessage("true"))
		h.HandleToolCall(msg)
	}
	if strings.Contains(buf.String(), "unpolled burst") {
		t.Errorf("a poll in the window must suppress the burst signal, got:\n%s", buf.String())
	}
}

// TestHandleSamplingCreateMessage_TaskAugmentedHighMaxTokens_Audited verifies
// the taxonomy's own worked example: a task-augmented sampling request with a
// very high maxTokens surfaces the expensive-sampling sentinel.
func TestHandleSamplingCreateMessage_TaskAugmentedHighMaxTokens_Audited(t *testing.T) {
	var buf bytes.Buffer
	h := &MessageHandler{
		Evaluator: NewPolicyEvaluator(&MCPPolicy{
			Rules: []MCPRule{*findRuleByID(t, loadPremiumPackRules(t, "mcp-sentinel.yaml"), "mcp-task-augmented-expensive-sampling-sentinel")},
		}),
		Stderr:            &buf,
		TaskAmplification: NewTaskAmplificationTracker(),
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodSamplingCreateMessage,
		Params: mustMarshal(t, SamplingCreateMessageParams{
			Messages:  []SamplingMessage{{Role: "user", Content: SamplingMessageContent{Type: "text", Text: "Summarize this."}}},
			MaxTokens: 200000,
			Task:      json.RawMessage("true"),
		}),
	}

	h.HandleSamplingCreateMessage(msg)
	if !strings.Contains(buf.String(), "expensive sampling wrap") {
		t.Errorf("expected expensive-sampling audit line, got:\n%s", buf.String())
	}
}

// TestHandleSamplingCreateMessage_TaskAugmentedLowMaxTokens_NotFlagged
// ensures an ordinary small task-wrapped completion is not flagged.
func TestHandleSamplingCreateMessage_TaskAugmentedLowMaxTokens_NotFlagged(t *testing.T) {
	var buf bytes.Buffer
	h := &MessageHandler{
		Evaluator: NewPolicyEvaluator(&MCPPolicy{
			Rules: []MCPRule{*findRuleByID(t, loadPremiumPackRules(t, "mcp-sentinel.yaml"), "mcp-task-augmented-expensive-sampling-sentinel")},
		}),
		Stderr:            &buf,
		TaskAmplification: NewTaskAmplificationTracker(),
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodSamplingCreateMessage,
		Params: mustMarshal(t, SamplingCreateMessageParams{
			Messages:  []SamplingMessage{{Role: "user", Content: SamplingMessageContent{Type: "text", Text: "Summarize this."}}},
			MaxTokens: 2048,
			Task:      json.RawMessage("true"),
		}),
	}

	h.HandleSamplingCreateMessage(msg)
	if strings.Contains(buf.String(), "expensive sampling wrap") {
		t.Errorf("must not flag a small task-wrapped completion, got:\n%s", buf.String())
	}
}

// --- Wire-level classification & dispatch ---

// TestClassifyMessage_TasksGetAndResult verifies tasks/get and tasks/result
// requests classify to their dedicated MessageKind rather than falling
// through to KindOtherRequest.
func TestClassifyMessage_TasksGetAndResult(t *testing.T) {
	reqID := json.RawMessage(`1`)
	tests := []struct {
		method string
		want   MessageKind
	}{
		{MethodTasksGet, KindTasksGet},
		{MethodTasksResult, KindTasksResult},
	}
	for _, tt := range tests {
		msg := &Message{JSONRPC: "2.0", ID: &reqID, Method: tt.method}
		if got := ClassifyMessage(msg); got != tt.want {
			t.Errorf("ClassifyMessage(%q) = %v, want %v", tt.method, got, tt.want)
		}
	}
}

// TestHandleTaskPollRequest_RecordsPoll verifies the poll handler records
// into the tracker (and is a no-op when the tracker is nil, matching every
// other optional tracker on MessageHandler).
func TestHandleTaskPollRequest_RecordsPoll(t *testing.T) {
	h := &MessageHandler{Stderr: io.Discard, TaskAmplification: NewTaskAmplificationTracker()}
	for i := 0; i < taskAmplificationBurstThreshold; i++ {
		h.TaskAmplification.RecordCreate()
	}
	h.HandleTaskPollRequest(&Message{Method: MethodTasksGet})
	if sig := h.TaskAmplification.ScanCreate(); sig != "" {
		t.Errorf("poll recorded via HandleTaskPollRequest must suppress the burst signal, got %q", sig)
	}

	// nil tracker must not panic.
	nilHandler := &MessageHandler{Stderr: io.Discard}
	nilHandler.HandleTaskPollRequest(&Message{Method: MethodTasksGet})
}
