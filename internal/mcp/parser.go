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
		case MethodResourcesSubscribe:
			return KindResourceSubscribe
		case MethodSamplingCreateMessage:
			return KindSamplingCreateMessage
		case MethodElicitationCreate:
			return KindElicitationCreate
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

// ExtractResourceSubscribe extracts the resource URI from a resources/subscribe request.
// The MCP spec uses the same {uri} param structure as resources/read.
func ExtractResourceSubscribe(msg *Message) (*ReadResourceParams, error) {
	if msg.Method != MethodResourcesSubscribe {
		return nil, fmt.Errorf("not a resources/subscribe request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("resources/subscribe request has no params")
	}

	var params ReadResourceParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse resources/subscribe params: %w", err)
	}
	if params.URI == "" {
		return nil, fmt.Errorf("resources/subscribe params missing required field 'uri'")
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

// ExtractElicitationCreate extracts the params from an elicitation/create request.
func ExtractElicitationCreate(msg *Message) (*ElicitationCreateParams, error) {
	if msg.Method != MethodElicitationCreate {
		return nil, fmt.Errorf("not an elicitation/create request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, fmt.Errorf("elicitation/create request has no params")
	}

	var params ElicitationCreateParams
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, fmt.Errorf("failed to parse elicitation/create params: %w", err)
	}
	return &params, nil
}

// IsBatch reports whether data represents a JSON-RPC 2.0 batch request (a JSON array).
// Skips leading whitespace before checking the first non-whitespace byte.
func IsBatch(data []byte) bool {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			continue
		}
		return b == '['
	}
	return false
}

// ParseBatch parses a JSON-RPC 2.0 batch request (JSON array of messages).
// Returns the slice of parsed messages or an error if the JSON is malformed.
func ParseBatch(data []byte) ([]*Message, error) {
	var rawMsgs []json.RawMessage
	if err := json.Unmarshal(data, &rawMsgs); err != nil {
		return nil, fmt.Errorf("invalid JSON-RPC batch: %w", err)
	}
	msgs := make([]*Message, 0, len(rawMsgs))
	for i, raw := range rawMsgs {
		var msg Message
		if err := json.Unmarshal(raw, &msg); err != nil {
			return nil, fmt.Errorf("invalid message at index %d in batch: %w", i, err)
		}
		msgs = append(msgs, &msg)
	}
	return msgs, nil
}

// NewBatchBlockResponse creates a JSON array of error responses for a blocked batch.
// Each request item with an ID gets an error response; notifications (no ID) are skipped
// per JSON-RPC 2.0 spec (notifications require no response).
func NewBatchBlockResponse(msgs []*Message, reason string) ([]byte, error) {
	var responses []json.RawMessage
	for _, msg := range msgs {
		if msg.ID == nil {
			continue // notifications have no response
		}
		resp, err := NewBlockResponse(msg.ID, reason)
		if err != nil {
			continue
		}
		responses = append(responses, resp)
	}
	if len(responses) == 0 {
		// All items were notifications — return empty array per spec
		return []byte("[]"), nil
	}
	return json.Marshal(responses)
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
