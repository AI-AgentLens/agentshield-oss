package mcp

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestClassifyMessage_CompletionComplete — issue #2791, follow-up to #2789.
// Before this change, completion/complete requests fell through to the
// generic KindOtherRequest bucket and received no dedicated handling, so no
// scanner ever saw their `argument.value` field.
func TestClassifyMessage_CompletionComplete(t *testing.T) {
	id := json.RawMessage(`"1"`)
	msg := &Message{
		JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete,
		Params: mustMarshalParams(t, CompletionCompleteParams{
			Ref:      CompletionRef{Type: "ref/prompt", Name: "code_review"},
			Argument: CompletionArgument{Name: "language", Value: "py"},
		}),
	}
	if kind := ClassifyMessage(msg); kind != KindCompletionComplete {
		t.Fatalf("expected KindCompletionComplete, got %v", kind)
	}
}

func TestExtractCompletionCompleteParams(t *testing.T) {
	id := json.RawMessage(`"1"`)

	t.Run("valid params parse", func(t *testing.T) {
		msg := &Message{
			JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete,
			Params: mustMarshalParams(t, CompletionCompleteParams{
				Ref:      CompletionRef{Type: "ref/prompt", Name: "code_review"},
				Argument: CompletionArgument{Name: "language", Value: "security"},
			}),
		}
		params, err := ExtractCompletionCompleteParams(msg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if params.Argument.Name != "language" || params.Argument.Value != "security" {
			t.Fatalf("unexpected params: %+v", params)
		}
	})

	t.Run("wrong method rejected", func(t *testing.T) {
		msg := &Message{
			JSONRPC: "2.0", ID: &id, Method: MethodToolsCall,
			Params: mustMarshalParams(t, CompletionCompleteParams{Argument: CompletionArgument{Name: "x"}}),
		}
		if _, err := ExtractCompletionCompleteParams(msg); err == nil {
			t.Fatal("expected error for non completion/complete method")
		}
	})

	t.Run("missing params rejected", func(t *testing.T) {
		msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete}
		if _, err := ExtractCompletionCompleteParams(msg); err == nil {
			t.Fatal("expected error for missing params")
		}
	})

	t.Run("missing argument name rejected", func(t *testing.T) {
		msg := &Message{
			JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete,
			Params: mustMarshalParams(t, CompletionCompleteParams{}),
		}
		if _, err := ExtractCompletionCompleteParams(msg); err == nil {
			t.Fatal("expected error for missing 'argument.name' field")
		}
	})
}

func newCompletionCompleteTestHandler(pol *MCPPolicy, dl *DataLabelScanner) (*MessageHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	return &MessageHandler{
		Evaluator:        NewPolicyEvaluator(pol),
		DataLabelScanner: dl,
		Stderr:           &buf,
	}, &buf
}

func completionCompleteMsg(t *testing.T, refName, argName, argValue string) *Message {
	t.Helper()
	id := json.RawMessage(`"1"`)
	return &Message{
		JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete,
		Params: mustMarshalParams(t, CompletionCompleteParams{
			Ref:      CompletionRef{Type: "ref/prompt", Name: refName},
			Argument: CompletionArgument{Name: argName, Value: argValue},
		}),
	}
}

// TestHandleCompletionCompleteRequest_BlocksSecretInArgument is the core
// regression test for issue #2791: an SSH private key smuggled through a
// completion/complete argument.value must be blocked by the same outbound
// content scanner that already covers tools/call and prompts/get arguments.
func TestHandleCompletionCompleteRequest_BlocksSecretInArgument(t *testing.T) {
	h, buf := newCompletionCompleteTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	msg := completionCompleteMsg(t, "code_review", "context",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----")

	blocked, resp := h.HandleCompletionCompleteRequest(msg)
	if !blocked {
		t.Fatalf("expected completion/complete with an embedded SSH key to be blocked; stderr=%s", buf.String())
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// TestHandleCompletionCompleteRequest_CleanArgumentPasses confirms benign
// argument values are not blocked (no false positive from the new scanning path).
func TestHandleCompletionCompleteRequest_CleanArgumentPasses(t *testing.T) {
	h, _ := newCompletionCompleteTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	msg := completionCompleteMsg(t, "code_review", "language", "py")

	blocked, _ := h.HandleCompletionCompleteRequest(msg)
	if blocked {
		t.Fatal("expected a clean completion/complete call to pass through")
	}
}

// TestHandleCompletionCompleteRequest_BlocksDataLabelMatch confirms
// customer-defined data labels (e.g. PII) are scanned on completion/complete
// argument.value, not just tools/call and prompts/get arguments.
func TestHandleCompletionCompleteRequest_BlocksDataLabelMatch(t *testing.T) {
	engine, err := datalabel.NewEngine([]datalabel.DataLabelConfig{
		{
			ID:         "pii-ssn",
			Name:       "Social Security Number",
			Decision:   "BLOCK",
			Confidence: 0.95,
			Reason:     "SSN pattern detected",
			Patterns:   []datalabel.PatternConfig{{Regex: `\b\d{3}-\d{2}-\d{4}\b`}},
		},
	})
	if err != nil {
		t.Fatalf("datalabel.NewEngine: %v", err)
	}
	dl := NewDataLabelScanner(engine)

	h, _ := newCompletionCompleteTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, dl)

	msg := completionCompleteMsg(t, "code_review", "context", "Customer SSN: 123-45-6789")

	blocked, resp := h.HandleCompletionCompleteRequest(msg)
	if !blocked {
		t.Fatal("expected completion/complete carrying an SSN data label match to be blocked")
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// TestHandleCompletionCompleteRequest_YAMLRuleMatches confirms
// completion/complete is evaluated through the same policy engine as
// tools/call, so a YAML rule with tool_name_any: ["completion/complete"] can
// also fire — matching the existing prompts/get pattern.
func TestHandleCompletionCompleteRequest_YAMLRuleMatches(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "test-rule-completion-complete",
				Match:    MCPMatch{ToolName: "completion/complete"},
				Decision: policy.DecisionBlock,
				Reason:   "test-block-completion-complete",
			},
		},
	}
	h, _ := newCompletionCompleteTestHandler(pol, nil)

	msg := completionCompleteMsg(t, "anything", "arg", "value")

	blocked, _ := h.HandleCompletionCompleteRequest(msg)
	if !blocked {
		t.Fatal("expected the YAML rule matching tool_name completion/complete to fire")
	}
}

// TestHandleCompletionCompleteRequest_MalformedFailsOpen confirms a message
// that isn't actually a valid completion/complete request is forwarded
// (fail open) rather than crashing the proxy.
func TestHandleCompletionCompleteRequest_MalformedFailsOpen(t *testing.T) {
	h, _ := newCompletionCompleteTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	id := json.RawMessage(`"1"`)
	msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodCompletionComplete} // no params

	blocked, resp := h.HandleCompletionCompleteRequest(msg)
	if blocked || resp != nil {
		t.Fatal("expected fail-open (not blocked) for a malformed completion/complete request")
	}
}
