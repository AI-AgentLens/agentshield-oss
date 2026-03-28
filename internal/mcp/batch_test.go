package mcp

import (
	"encoding/json"
	"io"
	"testing"
)

// TestIsBatch verifies that IsBatch correctly identifies JSON arrays vs objects.
func TestIsBatch(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "json array is batch",
			data: []byte(`[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`),
			want: true,
		},
		{
			name: "json object is not batch",
			data: []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`),
			want: false,
		},
		{
			name: "leading whitespace before array",
			data: []byte(`  [{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`),
			want: true,
		},
		{
			name: "empty input",
			data: []byte{},
			want: false,
		},
		{
			name: "whitespace only",
			data: []byte("   \n  "),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsBatch(tc.data)
			if got != tc.want {
				t.Errorf("IsBatch(%q) = %v, want %v", string(tc.data), got, tc.want)
			}
		})
	}
}

// TestParseBatch verifies parsing of JSON-RPC batch arrays.
func TestParseBatch(t *testing.T) {
	t.Run("valid batch of two requests", func(t *testing.T) {
		data := []byte(`[
			{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
			{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/README.md"}}}
		]`)
		msgs, err := ParseBatch(data)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(msgs))
		}
		if msgs[0].Method != "tools/list" {
			t.Errorf("expected first method=tools/list, got %q", msgs[0].Method)
		}
		if msgs[1].Method != "tools/call" {
			t.Errorf("expected second method=tools/call, got %q", msgs[1].Method)
		}
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		_, err := ParseBatch([]byte(`[invalid`))
		if err == nil {
			t.Error("expected error for invalid JSON, got nil")
		}
	})

	t.Run("empty batch", func(t *testing.T) {
		msgs, err := ParseBatch([]byte(`[]`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(msgs) != 0 {
			t.Errorf("expected 0 messages, got %d", len(msgs))
		}
	})
}

// TestNewBatchBlockResponse verifies the batch error response format.
func TestNewBatchBlockResponse(t *testing.T) {
	t.Run("two requests produce two error responses", func(t *testing.T) {
		id1 := json.RawMessage(`1`)
		id2 := json.RawMessage(`2`)
		msgs := []*Message{
			{JSONRPC: "2.0", ID: &id1, Method: "tools/list"},
			{JSONRPC: "2.0", ID: &id2, Method: "tools/call"},
		}
		resp, err := NewBatchBlockResponse(msgs, "test reason")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var responses []json.RawMessage
		if err := json.Unmarshal(resp, &responses); err != nil {
			t.Fatalf("response is not a JSON array: %v", err)
		}
		if len(responses) != 2 {
			t.Errorf("expected 2 error responses, got %d", len(responses))
		}
	})

	t.Run("notification (no ID) skipped in response", func(t *testing.T) {
		id1 := json.RawMessage(`1`)
		msgs := []*Message{
			{JSONRPC: "2.0", ID: &id1, Method: "tools/call"},
			{JSONRPC: "2.0", Method: "notifications/message"}, // no ID = notification
		}
		resp, err := NewBatchBlockResponse(msgs, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var responses []json.RawMessage
		if err := json.Unmarshal(resp, &responses); err != nil {
			t.Fatalf("response is not a JSON array: %v", err)
		}
		if len(responses) != 1 {
			t.Errorf("expected 1 response (notification skipped), got %d", len(responses))
		}
	})

	t.Run("all notifications produces empty array", func(t *testing.T) {
		msgs := []*Message{
			{JSONRPC: "2.0", Method: "notifications/message"},
		}
		resp, err := NewBatchBlockResponse(msgs, "test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(resp) != "[]" {
			t.Errorf("expected empty array [], got %q", string(resp))
		}
	})
}

// TestHandleBatch_BlockOnMaliciousItem verifies that a batch containing a malicious
// tool call is blocked even when surrounded by benign calls.
//
// TP: batch with read_file on ~/.ssh/id_rsa hidden among benign calls → BLOCK
func TestHandleBatch_BlockOnMaliciousItem(t *testing.T) {
	handler := newTestMCPHandler(t)

	id1 := json.RawMessage(`1`)
	id2 := json.RawMessage(`2`)
	id3 := json.RawMessage(`3`)

	toolsListParams := json.RawMessage(`{}`)
	maliciousParams := json.RawMessage(`{"name":"read_file","arguments":{"path":"/home/user/.ssh/id_rsa"}}`)
	benignParams := json.RawMessage(`{"name":"read_file","arguments":{"path":"/workspace/README.md"}}`)

	msgs := []*Message{
		{JSONRPC: "2.0", ID: &id1, Method: MethodToolsList, Params: toolsListParams},
		{JSONRPC: "2.0", ID: &id2, Method: MethodToolsCall, Params: maliciousParams},
		{JSONRPC: "2.0", ID: &id3, Method: MethodToolsCall, Params: benignParams},
	}

	blocked, batchResp := handler.HandleBatch(msgs)
	if !blocked {
		t.Fatal("expected batch to be BLOCKED (malicious read_file in second item), but was allowed")
	}
	if batchResp == nil {
		t.Fatal("expected non-nil batch block response")
	}

	// Response must be a JSON array
	var responses []json.RawMessage
	if err := json.Unmarshal(batchResp, &responses); err != nil {
		t.Fatalf("batch block response is not a JSON array: %v", err)
	}
	if len(responses) == 0 {
		t.Error("batch block response array should not be empty")
	}
}

// TestHandleBatch_AllowBenignBatch verifies that a small batch of safe calls passes through.
//
// TN: batch of tools/list and resources/list → ALLOW
func TestHandleBatch_AllowBenignBatch(t *testing.T) {
	handler := newTestMCPHandler(t)

	id1 := json.RawMessage(`1`)
	id2 := json.RawMessage(`2`)

	toolsListParams := json.RawMessage(`{}`)
	resourcesListParams := json.RawMessage(`{}`)

	msgs := []*Message{
		{JSONRPC: "2.0", ID: &id1, Method: MethodToolsList, Params: toolsListParams},
		{JSONRPC: "2.0", ID: &id2, Method: "resources/list", Params: resourcesListParams},
	}

	blocked, _ := handler.HandleBatch(msgs)
	if blocked {
		t.Fatal("expected benign batch (tools/list + resources/list) to be ALLOWED, but was blocked")
	}
}

// TestHandleBatch_LargeBatchAudit verifies that batches over the threshold are audited.
//
// TP (audit): batch with >BatchLargeAuditThreshold items triggers AUDIT log event.
func TestHandleBatch_LargeBatchAudit(t *testing.T) {
	handler := newTestMCPHandler(t)

	var auditedRules []string
	handler.OnAudit = func(entry AuditEntry) {
		auditedRules = append(auditedRules, entry.TriggeredRules...)
	}
	handler.Stderr = io.Discard

	// Build a batch of BatchLargeAuditThreshold+1 benign tools/list requests
	msgs := make([]*Message, BatchLargeAuditThreshold+1)
	for i := range msgs {
		idBytes := json.RawMessage([]byte{byte('1' + i)})
		msgs[i] = &Message{
			JSONRPC: "2.0",
			ID:      &idBytes,
			Method:  MethodToolsList,
			Params:  json.RawMessage(`{}`),
		}
	}

	blocked, _ := handler.HandleBatch(msgs)
	if blocked {
		t.Fatal("large batch of benign calls should not be BLOCKED (only AUDITED)")
	}

	found := false
	for _, rule := range auditedRules {
		if rule == "mcp-batch-large-audit" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected mcp-batch-large-audit rule to be triggered for large batch; got rules: %v", auditedRules)
	}
}

// TestHandleBatch_CredentialReadBlocked verifies that credential path access in a batch is blocked.
//
// TP: batch containing resources/read on ~/.aws/credentials → BLOCK
func TestHandleBatch_CredentialReadBlocked(t *testing.T) {
	handler := newTestMCPHandler(t)

	id1 := json.RawMessage(`1`)
	id2 := json.RawMessage(`2`)

	safeParams := json.RawMessage(`{}`)
	credParams := json.RawMessage(`{"uri":"file:///home/user/.aws/credentials"}`)

	msgs := []*Message{
		{JSONRPC: "2.0", ID: &id1, Method: MethodToolsList, Params: safeParams},
		{JSONRPC: "2.0", ID: &id2, Method: MethodResourcesRead, Params: credParams},
	}

	blocked, _ := handler.HandleBatch(msgs)
	if !blocked {
		t.Fatal("expected batch with credential resources/read to be BLOCKED")
	}
}
