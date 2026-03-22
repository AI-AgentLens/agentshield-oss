package mcp

import (
	"encoding/json"
	"fmt"
)

// ParseMessage parses a raw JSON byte slice into a Message and classifies it.
func ParseMessage(data []byte) (*Message, MessageKind, error) {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil, KindUnknown, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}

	kind := ClassifyMessage(&msg)
	return &msg, kind, nil
}

// ClassifyMessage determines the MessageKind of an already-parsed Message.
func ClassifyMessage(msg *Message) MessageKind {
	// Response: has id but no method
	if msg.ID != nil && msg.Method == "" {
		return KindResponse
	}

	// Notification: has method but no id
	if msg.ID == nil && msg.Method != "" {
		return KindNotification
	}

	// Request: has both id and method
	if msg.ID != nil && msg.Method != "" {
		switch msg.Method {
		case MethodToolsCall:
			return KindToolCall
		case MethodToolsList:
			return KindToolList
		case MethodResourcesRead:
			return KindResourceRead
		case MethodSamplingCreateMessage:
			return KindSamplingCreateMessage
		default:
			return KindOtherRequest
		}
	}

	return KindUnknown
}

// ExtractToolCall extracts the tool name and arguments from a tools/call request.
// Returns an error if the message is not a tools/call or params are malformed.
func ExtractToolCall(msg *Message) (*CallToolParams, error) {
	if msg.Method != MethodToolsCall {
		return nil, fmt.Errorf("not a tools/call request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("tools/call request has no params")
	}

	var params CallToolParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse tools/call params: %w", err)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("tools/call params missing required field 'name'")
	}
	return &params, nil
}

// ExtractResourceRead extracts the resource URI from a resources/read request.
func ExtractResourceRead(msg *Message) (*ReadResourceParams, error) {
	if msg.Method != MethodResourcesRead {
		return nil, fmt.Errorf("not a resources/read request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("resources/read request has no params")
	}

	var params ReadResourceParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse resources/read params: %w", err)
	}
	if params.URI == "" {
		return nil, fmt.Errorf("resources/read params missing required field 'uri'")
	}
	return &params, nil
}

// ExtractSamplingMessage extracts the messages from a sampling/createMessage request.
func ExtractSamplingMessage(msg *Message) (*SamplingCreateMessageParams, error) {
	if msg.Method != MethodSamplingCreateMessage {
		return nil, fmt.Errorf("not a sampling/createMessage request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("sampling/createMessage request has no params")
	}

	var params SamplingCreateMessageParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse sampling/createMessage params: %w", err)
	}
	return &params, nil
}

// NewBlockResponse creates a JSON-RPC error response that blocks a tool call.
// The ID is copied from the original request so the client can correlate it.
func NewBlockResponse(requestID *json.RawMessage, reason string) ([]byte, error) {
	resp := Message{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &RPCError{
			Code:    RPCInvalidRequest,
			Message: fmt.Sprintf("Blocked by AgentShield: %s", reason),
		},
	}
	return json.Marshal(resp)
}

// NewErrorResponse creates a generic JSON-RPC error response.
func NewErrorResponse(requestID *json.RawMessage, code int, message string) ([]byte, error) {
	resp := Message{
		JSONRPC: "2.0",
		ID:      requestID,
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
	return json.Marshal(resp)
}
