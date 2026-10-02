package mcp

import (
	"encoding/json"
	"fmt"
)

// ParseMessage parses a raw JSON byte slice into a Message and classifies it.
//
// The decode is lenient in the same way every other decode in this package is
// (see wire_shape.go). Three envelope fields have concrete Go types a JSON
// value can fail to fit: `jsonrpc` and `method` (strings — a number there is
// a *json.UnmarshalTypeError like any other) and `error` (a struct whose
// `code` is an int). `id`, `params` and `result` are json.RawMessage and
// cannot fail. Only `error.code` fails on a spelling a conforming peer
// actually emits: `"code": -32603.0`, which the reference TypeScript SDK's
// JSONRPCMessageSchema accepts (it rejects a numeric `method` or `jsonrpc`).
// Before this, that spelling failed the WHOLE envelope decode, and every
// caller's `err != nil` branch forwards the raw line unscanned: error.message
// and error.data together, wider than any single scanner (#4081). The
// leniency covers all three fields; when a receipt is recorded (see
// anomalyFromTypeError) it names which one.
func ParseMessage(data []byte) (*Message, MessageKind, error) {
	msg, kind, _, err := parseMessageLenient(data)
	return msg, kind, err
}

// parseMessageLenient is ParseMessage plus the protocol-shape anomaly
// decodeLenient tolerated, for callers that want to record a receipt via
// auditWireShape.
func parseMessageLenient(data []byte) (*Message, MessageKind, *WireShapeAnomaly, error) {
	var msg Message
	shape, err := decodeLenient(data, &msg)
	if err != nil {
		return nil, KindUnknown, nil, fmt.Errorf("invalid JSON-RPC message: %w", err)
	}

	kind := ClassifyMessage(&msg)
	return &msg, kind, shape, nil
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
		case MethodPromptsGet:
			return KindPromptsGet
		case MethodCompletionComplete:
			return KindCompletionComplete
		case MethodTasksGet:
			return KindTasksGet
		case MethodTasksResult:
			return KindTasksResult
		default:
			return KindOtherRequest
		}
	}

	return KindUnknown
}

// extractToolCall extracts the tool name and arguments from a tools/call request,
// together with any protocol-shape anomaly decodeLenient tolerated.
func extractToolCall(msg *Message) (*CallToolParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodToolsCall {
		return nil, nil, fmt.Errorf("not a tools/call request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("tools/call request has no params")
	}

	var params CallToolParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse tools/call params: %w", err)
	}
	if params.Name == "" {
		return nil, nil, fmt.Errorf("tools/call params missing required field 'name'")
	}
	return &params, shape, nil
}

// extractResourceRead extracts the resource URI from a resources/read request.
func extractResourceRead(msg *Message) (*ReadResourceParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodResourcesRead {
		return nil, nil, fmt.Errorf("not a resources/read request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("resources/read request has no params")
	}

	var params ReadResourceParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse resources/read params: %w", err)
	}
	if params.URI == "" {
		return nil, nil, fmt.Errorf("resources/read params missing required field 'uri'")
	}
	return &params, shape, nil
}

// extractResourceSubscribe extracts the resource URI from a resources/subscribe request.
// The MCP spec uses the same {uri} param structure as resources/read.
func extractResourceSubscribe(msg *Message) (*ReadResourceParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodResourcesSubscribe {
		return nil, nil, fmt.Errorf("not a resources/subscribe request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("resources/subscribe request has no params")
	}

	var params ReadResourceParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse resources/subscribe params: %w", err)
	}
	if params.URI == "" {
		return nil, nil, fmt.Errorf("resources/subscribe params missing required field 'uri'")
	}
	return &params, shape, nil
}

// extractGetPromptParams extracts the name and template arguments from a
// prompts/get request (client→server).
func extractGetPromptParams(msg *Message) (*GetPromptParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodPromptsGet {
		return nil, nil, fmt.Errorf("not a prompts/get request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("prompts/get request has no params")
	}

	var params GetPromptParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse prompts/get params: %w", err)
	}
	if params.Name == "" {
		return nil, nil, fmt.Errorf("prompts/get params missing required field 'name'")
	}
	return &params, shape, nil
}

// extractCompletionCompleteParams extracts the ref and argument from a
// completion/complete request (client→server).
func extractCompletionCompleteParams(msg *Message) (*CompletionCompleteParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodCompletionComplete {
		return nil, nil, fmt.Errorf("not a completion/complete request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("completion/complete request has no params")
	}

	var params CompletionCompleteParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse completion/complete params: %w", err)
	}
	if params.Argument.Name == "" {
		return nil, nil, fmt.Errorf("completion/complete params missing required field 'argument.name'")
	}
	return &params, shape, nil
}

// extractSamplingMessage extracts the messages from a sampling/createMessage request.
func extractSamplingMessage(msg *Message) (*SamplingCreateMessageParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodSamplingCreateMessage {
		return nil, nil, fmt.Errorf("not a sampling/createMessage request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("sampling/createMessage request has no params")
	}

	var params SamplingCreateMessageParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse sampling/createMessage params: %w", err)
	}
	return &params, shape, nil
}

// extractElicitationCreate extracts the params from an elicitation/create request.
func extractElicitationCreate(msg *Message) (*ElicitationCreateParams, *WireShapeAnomaly, error) {
	if msg.Method != MethodElicitationCreate {
		return nil, nil, fmt.Errorf("not an elicitation/create request: method=%q", msg.Method)
	}
	if msg.Params == nil {
		return nil, nil, fmt.Errorf("elicitation/create request has no params")
	}

	var params ElicitationCreateParams
	shape, err := decodeLenient(msg.Params, &params)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse elicitation/create params: %w", err)
	}
	return &params, shape, nil
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

// The Extract* wrappers below keep the long-standing two-value signature for
// callers that do not report protocol-shape anomalies. The lower-case variants
// they delegate to also return the *WireShapeAnomaly that decodeLenient
// tolerated, and the MCP handler uses those so a message that was scanned only
// because we declined to fail on its shape still leaves a receipt. See
// wire_shape.go.

// ExtractToolCall extracts the tool name and arguments from a tools/call request.
func ExtractToolCall(msg *Message) (*CallToolParams, error) {
	p, _, err := extractToolCall(msg)
	return p, err
}

// ExtractResourceRead extracts the resource URI from a resources/read request.
func ExtractResourceRead(msg *Message) (*ReadResourceParams, error) {
	p, _, err := extractResourceRead(msg)
	return p, err
}

// ExtractResourceSubscribe extracts the resource URI from a resources/subscribe request.
func ExtractResourceSubscribe(msg *Message) (*ReadResourceParams, error) {
	p, _, err := extractResourceSubscribe(msg)
	return p, err
}

// ExtractGetPromptParams extracts the name and template arguments from a prompts/get request.
func ExtractGetPromptParams(msg *Message) (*GetPromptParams, error) {
	p, _, err := extractGetPromptParams(msg)
	return p, err
}

// ExtractCompletionCompleteParams extracts the ref and argument from a completion/complete request.
func ExtractCompletionCompleteParams(msg *Message) (*CompletionCompleteParams, error) {
	p, _, err := extractCompletionCompleteParams(msg)
	return p, err
}

// ExtractSamplingMessage extracts the messages from a sampling/createMessage request.
func ExtractSamplingMessage(msg *Message) (*SamplingCreateMessageParams, error) {
	p, _, err := extractSamplingMessage(msg)
	return p, err
}

// ExtractElicitationCreate extracts the params from an elicitation/create request.
func ExtractElicitationCreate(msg *Message) (*ElicitationCreateParams, error) {
	p, _, err := extractElicitationCreate(msg)
	return p, err
}
