package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// hintTestPolicy is a focused MCPPolicy that BLOCKs each of the three message
// kinds we render hints for: tool call, resources/read, resources/subscribe.
//
// We use the simplest matcher available for each path so the test asserts on
// the hint plumbing, not on glob/URI parsing edge cases:
//   - tool call:           BlockedTools (literal name match in EvaluateToolCall)
//   - resources/read:      BlockedResources (literal URI match in EvaluateResourceRead)
//   - resources/subscribe: an MCPRule with ToolName == "resources/subscribe"
//     (the handler routes subscribes through EvaluateToolCall using the method
//     name as the tool name).
func hintTestPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{
			"hint-test-tool",
		},
		BlockedResources: []string{
			"hint-test-resource://blocked",
		},
		Rules: []MCPRule{
			{
				ID: "hint-test-rule-resources-subscribe",
				Match: MCPMatch{
					ToolName: "resources/subscribe",
				},
				Decision: policy.DecisionBlock,
				Reason:   "test-block-resource-subscribe",
			},
		},
	}
}

// newHintTestHandler builds a MessageHandler whose stderr we can read back.
// Returns the handler and the buffer it writes to.
func newHintTestHandler() (*MessageHandler, *bytes.Buffer) {
	var buf bytes.Buffer
	return &MessageHandler{
		Evaluator: NewPolicyEvaluator(hintTestPolicy()),
		Stderr:    &buf,
	}, &buf
}

func mustMarshal(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return b
}

func mustRequestID(t *testing.T) *json.RawMessage {
	t.Helper()
	id := json.RawMessage(`"hint-test-1"`)
	return &id
}

// TestHandleToolCall_BLOCK_RendersDisableHint — issue #1640. When the MCP
// proxy blocks a tool call, the stderr output must include the disable hint
// so a Cursor/Windsurf user has a clear path to unblock a false positive.
// Before this test landed, the BLOCK output went to stderr but had no
// `agentshield rule disable <id>` line — the user had no idea what to type.
func TestHandleToolCall_BLOCK_RendersDisableHint(t *testing.T) {
	h, buf := newHintTestHandler()

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name: "hint-test-tool",
		}),
	}

	blocked, _ := h.HandleToolCall(msg)
	if !blocked {
		t.Fatal("expected the tool call to be blocked (BlockedTools list)")
	}

	out := buf.String()
	if !strings.Contains(out, "BLOCKED tool call") {
		t.Errorf("expected BLOCK header in stderr, got:\n%s", out)
	}
	if !strings.Contains(out, "agentshield rule disable") {
		t.Errorf("expected disable hint in stderr (issue #1640):\n%s", out)
	}
	if strings.Contains(out, "agentshield check --shell") {
		t.Errorf("MCP-proxy hint must NOT include `agentshield check --shell` (no shell command to replay):\n%s", out)
	}
}

// TestHandleResourceRead_BLOCK_RendersDisableHint — second of the three
// BLOCK surfaces in handler.go.
func TestHandleResourceRead_BLOCK_RendersDisableHint(t *testing.T) {
	h, buf := newHintTestHandler()

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodResourcesRead,
		Params: mustMarshal(t, ReadResourceParams{
			URI: "hint-test-resource://blocked",
		}),
	}

	blocked, _ := h.HandleResourceRead(msg)
	if !blocked {
		t.Fatal("expected the resource read to be blocked")
	}

	out := buf.String()
	if !strings.Contains(out, "BLOCKED resource read") {
		t.Errorf("expected BLOCK header in stderr, got:\n%s", out)
	}
	if !strings.Contains(out, "agentshield rule disable") {
		t.Errorf("expected disable hint, got:\n%s", out)
	}
}

// TestHandleResourceSubscribe_BLOCK_RendersDisableHint — third of the three
// BLOCK surfaces. resources/subscribe is the passive-monitoring exfil vector
// and shares the same hint-rendering path.
func TestHandleResourceSubscribe_BLOCK_RendersDisableHint(t *testing.T) {
	h, buf := newHintTestHandler()

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodResourcesSubscribe,
		Params: mustMarshal(t, ReadResourceParams{
			URI: "any://watched/path",
		}),
	}

	blocked, _ := h.HandleResourceSubscribe(msg)
	if !blocked {
		t.Fatal("expected the resource subscribe to be blocked")
	}

	out := buf.String()
	if !strings.Contains(out, "BLOCKED resource subscribe") {
		t.Errorf("expected BLOCK header in stderr, got:\n%s", out)
	}
	if !strings.Contains(out, "agentshield rule disable hint-test-rule-resources-subscribe") {
		t.Errorf("expected disable hint with the triggered rule ID, got:\n%s", out)
	}
}
