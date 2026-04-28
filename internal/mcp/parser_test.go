package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseMessage_ToolCall(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}`

	msg, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindToolCall {
		t.Errorf("expected KindToolCall, got %v", kind)
	}
	if msg.Method != MethodToolsCall {
		t.Errorf("expected method %q, got %q", MethodToolsCall, msg.Method)
	}
}

func TestParseMessage_ToolList(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

	_, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindToolList {
		t.Errorf("expected KindToolList, got %v", kind)
	}
}

func TestParseMessage_Response(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}],"isError":false}}`

	_, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindResponse {
		t.Errorf("expected KindResponse, got %v", kind)
	}
}

func TestParseMessage_Notification(t *testing.T) {
	input := `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`

	_, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindNotification {
		t.Errorf("expected KindNotification, got %v", kind)
	}
}

func TestParseMessage_ResourceRead(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"file:///tmp/foo"}}`

	_, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindResourceRead {
		t.Errorf("expected KindResourceRead, got %v", kind)
	}
}

func TestParseMessage_OtherRequest(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":6,"method":"prompts/get","params":{"name":"test"}}`

	_, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindOtherRequest {
		t.Errorf("expected KindOtherRequest, got %v", kind)
	}
}

func TestParseMessage_InvalidJSON(t *testing.T) {
	_, _, err := ParseMessage([]byte(`{invalid`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseMessage_EmptyObject(t *testing.T) {
	_, kind, err := ParseMessage([]byte(`{}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindUnknown {
		t.Errorf("expected KindUnknown, got %v", kind)
	}
}

func TestExtractToolCall_Valid(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}`

	msg, _, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	params, err := ExtractToolCall(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.Name != "execute_command" {
		t.Errorf("expected tool name %q, got %q", "execute_command", params.Name)
	}
	cmd, ok := params.Arguments["command"]
	if !ok {
		t.Fatal("expected 'command' argument")
	}
	if cmd != "rm -rf /" {
		t.Errorf("expected argument value %q, got %q", "rm -rf /", cmd)
	}
}

func TestExtractToolCall_NoArguments(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_files"}}`

	msg, _, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	params, err := ExtractToolCall(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.Name != "list_files" {
		t.Errorf("expected tool name %q, got %q", "list_files", params.Name)
	}
	if len(params.Arguments) != 0 {
		t.Errorf("expected no arguments, got %v", params.Arguments)
	}
}

func TestExtractToolCall_WrongMethod(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`

	msg, _, _ := ParseMessage([]byte(input))
	_, err := ExtractToolCall(msg)
	if err == nil {
		t.Fatal("expected error for non-tools/call message")
	}
}

func TestExtractToolCall_MissingName(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`

	msg, _, _ := ParseMessage([]byte(input))
	_, err := ExtractToolCall(msg)
	if err == nil {
		t.Fatal("expected error for missing tool name")
	}
}

func TestExtractToolCall_NoParams(t *testing.T) {
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`

	msg, _, _ := ParseMessage([]byte(input))
	_, err := ExtractToolCall(msg)
	if err == nil {
		t.Fatal("expected error for nil params")
	}
}

func TestNewBlockResponse(t *testing.T) {
	id := json.RawMessage(`1`)
	data, err := NewBlockResponse(&id, "dangerous tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("failed to parse block response: %v", err)
	}
	if msg.JSONRPC != "2.0" {
		t.Errorf("expected jsonrpc 2.0, got %q", msg.JSONRPC)
	}
	if msg.Error == nil {
		t.Fatal("expected error field in block response")
	}
	if msg.Error.Code != RPCInvalidRequest {
		t.Errorf("expected error code %d, got %d", RPCInvalidRequest, msg.Error.Code)
	}
	if msg.Error.Message == "" {
		t.Error("expected non-empty error message")
	}
}

func TestNewBlockResponse_PreservesStringID(t *testing.T) {
	id := json.RawMessage(`"abc-123"`)
	data, err := NewBlockResponse(&id, "blocked")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	var parsedID string
	if err := json.Unmarshal(*msg.ID, &parsedID); err != nil {
		t.Fatalf("failed to parse ID: %v", err)
	}
	if parsedID != "abc-123" {
		t.Errorf("expected ID %q, got %q", "abc-123", parsedID)
	}
}

func TestExtractToolCall_ComplexArguments(t *testing.T) {
	input := `{
		"jsonrpc": "2.0",
		"id": 42,
		"method": "tools/call",
		"params": {
			"name": "write_file",
			"arguments": {
				"path": "/etc/passwd",
				"content": "malicious content",
				"mode": 644
			}
		}
	}`

	msg, kind, err := ParseMessage([]byte(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != KindToolCall {
		t.Fatalf("expected KindToolCall, got %v", kind)
	}

	params, err := ExtractToolCall(msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if params.Name != "write_file" {
		t.Errorf("expected tool name %q, got %q", "write_file", params.Name)
	}
	if params.Arguments["path"] != "/etc/passwd" {
		t.Errorf("expected path /etc/passwd, got %v", params.Arguments["path"])
	}
}

func TestMessageKind_String(t *testing.T) {
	tests := []struct {
		kind MessageKind
		want string
	}{
		{KindToolCall, "tools/call"},
		{KindToolList, "tools/list"},
		{KindNotification, "notification"},
		{KindResponse, "response"},
		{KindOtherRequest, "other-request"},
		{KindUnknown, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.kind.String(); got != tt.want {
			t.Errorf("MessageKind(%d).String() = %q, want %q", tt.kind, got, tt.want)
		}
	}
}
