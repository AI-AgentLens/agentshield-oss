package mcp

import (
	"encoding/json"
	"testing"
)

// ── ToolDescriptionCache unit tests ────────────────────────────────────────

func TestToolDescriptionCache_GetAfterUpdate(t *testing.T) {
	c := NewToolDescriptionCache()
	c.Update([]ToolDefinition{
		{Name: "handle_ticket", Description: "Reads credential data from the vault."},
		{Name: "write_file"},
	})

	if got := c.Get("handle_ticket"); got != "Reads credential data from the vault." {
		t.Fatalf("expected cached description, got %q", got)
	}
	if got := c.Get("write_file"); got != "" {
		t.Fatalf("write_file has no description, expected \"\", got %q", got)
	}
	if got := c.Get("unknown_tool"); got != "" {
		t.Fatalf("unknown_tool should return \"\", got %q", got)
	}
}

func TestToolDescriptionCache_UpdateOverwrites(t *testing.T) {
	c := NewToolDescriptionCache()
	c.Update([]ToolDefinition{{Name: "tool_a", Description: "does a thing"}})
	// Second update replaces entirely; tool_a should be evicted.
	c.Update([]ToolDefinition{{Name: "tool_b", Description: "does another thing"}})
	if got := c.Get("tool_a"); got != "" {
		t.Fatalf("tool_a should be evicted after second Update, got %q", got)
	}
}

func TestToolDescriptionCache_NilReceiverSafeGet(t *testing.T) {
	// MessageHandler callers guard with `h.DescriptionCache != nil`, but Get on
	// a cache constructed with the zero value (no map) must not panic either —
	// matches ToolAnnotationCache's contract, exercised for symmetry.
	c := &ToolDescriptionCache{}
	if got := c.Get("anything"); got != "" {
		t.Fatalf("expected \"\" from an empty cache, got %q", got)
	}
}

// ── End-to-end integration test through HandleToolCall ─────────────────────

// TestHandleToolCall_DescriptionOnlyBlock_EndToEnd is the regression test for
// #3692: the stdio/HTTP proxies always evaluated tools/call with an empty
// tool description, so any BLOCK rule that depends on classifying the
// description text (mcp-sem-block-process-manage here) never fired on live
// proxy traffic — only in the corpus harness and shield-server's /v1/evaluate,
// which both pass a real description directly.
//
// "handle_ticket" is a deliberately neutral tool name/argument pair (no
// substring or exact-token hit in intentKeywords/argNameSignals for
// process-manage — see internal/mcp/semantic.go) so the ONLY signal that can
// push the process-manage classification over the 0.7 confidence_min is the
// cached description, exercised through the real proxy path:
// FilterToolsListResponse (populates the cache) → HandleToolCall (reads it).
//
// The description is phrased as third-person documentation of the tool's own
// behavior, not as an instruction directed at the agent — a credential-themed
// version of this description trips ScanToolDescription's separate
// tools/list poisoning-removal pass (excessive_capability_declaration /
// credential_harvest), which would hide the tool before it ever reached
// HandleToolCall and defeat the point of this test.
func TestHandleToolCall_DescriptionOnlyBlock_EndToEnd(t *testing.T) {
	h := newTestMCPHandler(t)
	h.DescriptionCache = NewToolDescriptionCache()

	const description = "This utility manages system process lifecycles: it can " +
		"kill process instances, stop process workers, and restart process pools on request."

	listResultJSON, err := json.Marshal(ListToolsResult{
		Tools: []ToolDefinition{
			{Name: "handle_ticket", Description: description},
		},
	})
	if err != nil {
		t.Fatalf("marshal list result: %v", err)
	}
	toolsListMsg, err := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  json.RawMessage(listResultJSON),
	})
	if err != nil {
		t.Fatalf("marshal tools/list message: %v", err)
	}
	if filtered := h.FilterToolsListResponse(toolsListMsg); filtered != nil {
		t.Fatalf("tools/list response for a benign (non-poisoned) description must not be filtered, got: %s", filtered)
	}

	if got := h.DescriptionCache.Get("handle_ticket"); got != description {
		t.Fatalf("expected FilterToolsListResponse to populate DescriptionCache, got %q", got)
	}

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name:      "handle_ticket",
			Arguments: map[string]interface{}{"ticket_id": "T-1"},
		}),
	}

	blocked, resp := h.HandleToolCall(msg)
	if !blocked {
		t.Fatal("handle_ticket with a process-management description must be BLOCKED via the cached tools/list description")
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// TestHandleToolCall_DescriptionCacheNil_EvaluatesEmptyDescription pins the
// fallback: with DescriptionCache unset (nil), a tools/call must evaluate
// exactly as it did before this cache existed — with an empty description —
// rather than erroring or panicking. This is the "compatibility" half of
// #3692: DescriptionCache is additive, not a requirement.
func TestHandleToolCall_DescriptionCacheNil_EvaluatesEmptyDescription(t *testing.T) {
	h := newTestMCPHandler(t)
	h.DescriptionCache = nil

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name:      "handle_ticket",
			Arguments: map[string]interface{}{"ticket_id": "T-1"},
		}),
	}

	blocked, _ := h.HandleToolCall(msg)
	if blocked {
		t.Fatal("neutral tool name/arguments with no cached description must not BLOCK on credential-access classification")
	}
}

// TestHandleToolCall_DescriptionCache_ToolNeverListed pins the other half of
// the fallback: a tool the session never saw in a tools/list response (cache
// populated for OTHER tools, but not this one) must evaluate with "" rather
// than an error.
func TestHandleToolCall_DescriptionCache_ToolNeverListed(t *testing.T) {
	h := newTestMCPHandler(t)
	h.DescriptionCache = NewToolDescriptionCache()
	h.DescriptionCache.Update([]ToolDefinition{
		{Name: "some_other_tool", Description: "fetch secret access secret read credential"},
	})

	msg := &Message{
		JSONRPC: "2.0",
		ID:      mustRequestID(t),
		Method:  MethodToolsCall,
		Params: mustMarshal(t, CallToolParams{
			Name:      "handle_ticket",
			Arguments: map[string]interface{}{"ticket_id": "T-1"},
		}),
	}

	blocked, _ := h.HandleToolCall(msg)
	if blocked {
		t.Fatal("a tool never seen in tools/list must evaluate with an empty description, not another tool's cached one")
	}
}
