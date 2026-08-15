package mcp

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// TestClassifyMessage_PromptsGet — issue #2789. Before this change, prompts/get
// requests fell through to the generic KindOtherRequest bucket and received no
// dedicated handling, so no scanner ever saw their `arguments` map.
func TestClassifyMessage_PromptsGet(t *testing.T) {
	id := json.RawMessage(`"1"`)
	msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet, Params: mustMarshalParams(t, GetPromptParams{Name: "summarize"})}
	if kind := ClassifyMessage(msg); kind != KindPromptsGet {
		t.Fatalf("expected KindPromptsGet, got %v", kind)
	}
}

func mustMarshalParams(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func TestExtractGetPromptParams(t *testing.T) {
	id := json.RawMessage(`"1"`)

	t.Run("valid params parse", func(t *testing.T) {
		msg := &Message{
			JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet,
			Params: mustMarshalParams(t, GetPromptParams{
				Name:      "summarize",
				Arguments: map[string]string{"topic": "security"},
			}),
		}
		params, err := ExtractGetPromptParams(msg)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if params.Name != "summarize" || params.Arguments["topic"] != "security" {
			t.Fatalf("unexpected params: %+v", params)
		}
	})

	t.Run("wrong method rejected", func(t *testing.T) {
		msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodToolsCall, Params: mustMarshalParams(t, GetPromptParams{Name: "x"})}
		if _, err := ExtractGetPromptParams(msg); err == nil {
			t.Fatal("expected error for non prompts/get method")
		}
	})

	t.Run("missing params rejected", func(t *testing.T) {
		msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet}
		if _, err := ExtractGetPromptParams(msg); err == nil {
			t.Fatal("expected error for missing params")
		}
	})

	t.Run("missing name rejected", func(t *testing.T) {
		msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet, Params: mustMarshalParams(t, GetPromptParams{})}
		if _, err := ExtractGetPromptParams(msg); err == nil {
			t.Fatal("expected error for missing 'name' field")
		}
	})
}

func newPromptsGetTestHandler(pol *MCPPolicy, dl *DataLabelScanner) (*MessageHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	return &MessageHandler{
		Evaluator:        NewPolicyEvaluator(pol),
		DataLabelScanner: dl,
		Stderr:           &buf,
	}, &buf
}

func promptsGetMsg(t *testing.T, name string, args map[string]string) *Message {
	t.Helper()
	id := json.RawMessage(`"1"`)
	return &Message{
		JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet,
		Params: mustMarshalParams(t, GetPromptParams{Name: name, Arguments: args}),
	}
}

// TestHandlePromptsGetRequest_BlocksSecretInArgument is the core regression
// test for issue #2789: an SSH private key smuggled through a prompts/get
// template argument must be blocked by the same outbound content scanner
// that already covers tools/call arguments.
func TestHandlePromptsGetRequest_BlocksSecretInArgument(t *testing.T) {
	h, buf := newPromptsGetTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	msg := promptsGetMsg(t, "summarize", map[string]string{
		"context": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n-----END OPENSSH PRIVATE KEY-----",
	})

	blocked, resp := h.HandlePromptsGetRequest(msg)
	if !blocked {
		t.Fatalf("expected prompts/get with an embedded SSH key to be blocked; stderr=%s", buf.String())
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// TestHandlePromptsGetRequest_CleanArgumentsPass confirms benign template
// arguments are not blocked (no false positive from the new scanning path).
func TestHandlePromptsGetRequest_CleanArgumentsPass(t *testing.T) {
	h, _ := newPromptsGetTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	msg := promptsGetMsg(t, "summarize", map[string]string{"topic": "quarterly roadmap"})

	blocked, _ := h.HandlePromptsGetRequest(msg)
	if blocked {
		t.Fatal("expected a clean prompts/get call to pass through")
	}
}

// TestHandlePromptsGetRequest_BlocksDataLabelMatch confirms customer-defined
// data labels (e.g. PII) are scanned on prompts/get arguments, not just
// tools/call arguments.
func TestHandlePromptsGetRequest_BlocksDataLabelMatch(t *testing.T) {
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

	h, _ := newPromptsGetTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, dl)

	msg := promptsGetMsg(t, "summarize", map[string]string{"context": "Customer SSN: 123-45-6789"})

	blocked, resp := h.HandlePromptsGetRequest(msg)
	if !blocked {
		t.Fatal("expected prompts/get carrying an SSN data label match to be blocked")
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// TestHandlePromptsGetRequest_YAMLRuleMatches confirms prompts/get is
// evaluated through the same policy engine as tools/call, so a YAML rule
// with tool_name_any: ["prompts/get"] can also fire — matching the existing
// resources/subscribe pattern (HandleResourceSubscribe).
func TestHandlePromptsGetRequest_YAMLRuleMatches(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "test-rule-prompts-get",
				Match:    MCPMatch{ToolName: "prompts/get"},
				Decision: policy.DecisionBlock,
				Reason:   "test-block-prompts-get",
			},
		},
	}
	h, _ := newPromptsGetTestHandler(pol, nil)

	msg := promptsGetMsg(t, "anything", nil)

	blocked, _ := h.HandlePromptsGetRequest(msg)
	if !blocked {
		t.Fatal("expected the YAML rule matching tool_name prompts/get to fire")
	}
}

// TestHandlePromptsGetRequest_MalformedFailsOpen confirms a message that
// isn't actually a valid prompts/get request is forwarded (fail open) rather
// than crashing the proxy.
func TestHandlePromptsGetRequest_MalformedFailsOpen(t *testing.T) {
	h, _ := newPromptsGetTestHandler(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}, nil)

	id := json.RawMessage(`"1"`)
	msg := &Message{JSONRPC: "2.0", ID: &id, Method: MethodPromptsGet} // no params

	blocked, resp := h.HandlePromptsGetRequest(msg)
	if blocked || resp != nil {
		t.Fatal("expected fail-open (not blocked) for a malformed prompts/get request")
	}
}
