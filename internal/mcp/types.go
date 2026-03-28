// Package mcp provides types and utilities for intercepting and evaluating
// Model Context Protocol (MCP) JSON-RPC messages. AgentShield uses these to
// mediate tool calls between AI agents and MCP servers.
package mcp

import "encoding/json"

// --- JSON-RPC base types (MCP uses JSON-RPC 2.0) ---

// Message is the top-level envelope for any JSON-RPC 2.0 message.
// We parse into this first, then dispatch based on the Method field.
type Message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`     // present for requests & responses
	Method  string           `json:"method,omitempty"` // present for requests & notifications
	Params  json.RawMessage  `json:"params,omitempty"` // present for requests & notifications
	Result  json.RawMessage  `json:"result,omitempty"` // present for success responses
	Error   *RPCError        `json:"error,omitempty"`  // present for error responses
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// --- MCP tool call types ---

// CallToolParams represents the params of a tools/call request.
type CallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// CallToolResult represents the result of a tools/call response.
type CallToolResult struct {
	Content []ContentItem `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}

// ContentItem is one piece of content in a tool result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// --- MCP tool listing types ---

// ToolAnnotations represents the MCP 2025-03-26 tool annotations object.
// These are informational hints from the server about tool behavior.
// Per the spec, annotations are NOT guaranteed to be accurate — they must
// not be used as a security boundary, and discrepancies are a rug-pull signal.
type ToolAnnotations struct {
	// ReadOnly hints the tool has no side effects on its environment.
	// If true but the tool name contains destructive verbs, this is suspicious.
	ReadOnly *bool `json:"readOnly,omitempty"`
	// Destructive hints the tool may cause irreversible changes.
	Destructive *bool `json:"destructive,omitempty"`
	// Idempotent hints repeated identical calls have the same effect.
	Idempotent *bool `json:"idempotent,omitempty"`
	// OpenWorld hints the tool may interact with external entities.
	// If false/absent but the description mentions egress, this is suspicious.
	OpenWorld *bool `json:"openWorld,omitempty"`
}

// ToolDefinition describes a single tool exposed by an MCP server.
type ToolDefinition struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema,omitempty"`
	Annotations *ToolAnnotations `json:"annotations,omitempty"`
}

// ListToolsResult is the result of a tools/list response.
type ListToolsResult struct {
	Tools      []ToolDefinition `json:"tools"`
	NextCursor string           `json:"nextCursor,omitempty"`
}

// --- Message type classification ---

// MessageKind classifies a parsed JSON-RPC message.
type MessageKind int

const (
	KindUnknown               MessageKind = iota
	KindToolCall                          // tools/call request
	KindToolList                          // tools/list request
	KindResourceRead                      // resources/read request
	KindResourceSubscribe                 // resources/subscribe request
	KindSamplingCreateMessage             // sampling/createMessage request (server→client)
	KindElicitationCreate                 // elicitation/create request (server→client)
	KindNotification                      // any notification (no id)
	KindResponse                          // any response (has id, has result or error)
	KindOtherRequest                      // any other request (has id + method)
)

// String returns a human-readable label for the message kind.
func (k MessageKind) String() string {
	switch k {
	case KindToolCall:
		return "tools/call"
	case KindToolList:
		return "tools/list"
	case KindResourceRead:
		return "resources/read"
	case KindResourceSubscribe:
		return "resources/subscribe"
	case KindSamplingCreateMessage:
		return "sampling/createMessage"
	case KindElicitationCreate:
		return "elicitation/create"
	case KindNotification:
		return "notification"
	case KindResponse:
		return "response"
	case KindOtherRequest:
		return "other-request"
	default:
		return "unknown"
	}
}

// --- Well-known MCP methods ---

const (
	MethodToolsCall              = "tools/call"
	MethodToolsList              = "tools/list"
	MethodResourcesRead          = "resources/read"
	MethodResourcesSubscribe     = "resources/subscribe"
	MethodSamplingCreateMessage  = "sampling/createMessage"
	MethodElicitationCreate      = "elicitation/create"
	MethodRootsList              = "roots/list"
	MethodNotificationsMessage   = "notifications/message"
	MethodPromptsGet             = "prompts/get"
	MethodPromptsList            = "prompts/list"
	MethodCompletionComplete     = "completion/complete"
)

// --- MCP roots types ---

// RootInfo represents a single MCP root entry in a roots/list response.
type RootInfo struct {
	URI  string `json:"uri"`
	Name string `json:"name,omitempty"`
}

// RootsListResult is the JSON-RPC result for roots/list responses.
// The client sends this in response to a server's roots/list request,
// declaring which filesystem paths are accessible to the server.
type RootsListResult struct {
	Roots []RootInfo `json:"roots"`
}

// --- MCP resource types ---

// ReadResourceParams represents the params of a resources/read request.
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// --- MCP sampling types ---

// SamplingMessage is one message in a sampling/createMessage request.
type SamplingMessage struct {
	Role    string                 `json:"role"`    // "user" or "assistant"
	Content SamplingMessageContent `json:"content"` // text or image content
}

// SamplingMessageContent holds either text or image content in a sampling message.
type SamplingMessageContent struct {
	Type string `json:"type"` // "text" or "image"
	Text string `json:"text,omitempty"`
}

// SamplingCreateMessageParams represents the params of a sampling/createMessage request.
// MCP servers send this to request the host LLM to generate a response.
type SamplingCreateMessageParams struct {
	Messages         []SamplingMessage      `json:"messages"`
	MaxTokens        int                    `json:"maxTokens,omitempty"`
	SystemPrompt     string                 `json:"systemPrompt,omitempty"`
	ModelPreferences map[string]interface{} `json:"modelPreferences,omitempty"`
}

// --- MCP elicitation types ---

// ElicitationCreateParams represents the params of an elicitation/create request.
// MCP servers (2025+) send this to request structured user input during tool execution.
type ElicitationCreateParams struct {
	Message         string             `json:"message"`
	RequestedSchema *ElicitationSchema `json:"requestedSchema,omitempty"`
}

// ElicitationSchema is the JSON-schema-like structure that describes the data an
// elicitation request asks the user to provide.
type ElicitationSchema struct {
	Type       string                       `json:"type,omitempty"`
	Title      string                       `json:"title,omitempty"`
	Properties map[string]*SchemaProperty   `json:"properties,omitempty"`
}

// SchemaProperty is one property in an ElicitationSchema.
type SchemaProperty struct {
	Type        string `json:"type,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// --- MCP prompts types ---

// PromptMessage is one message in a prompts/get response.
// A malicious server can embed injection payloads in the text content.
type PromptMessage struct {
	Role    string                `json:"role"`    // "user" or "assistant"
	Content PromptMessageContent  `json:"content"` // text or image content
}

// PromptMessageContent holds one piece of content in a prompt message.
type PromptMessageContent struct {
	Type string `json:"type"`            // "text", "image", or "resource"
	Text string `json:"text,omitempty"`  // for type=="text"
}

// GetPromptResult is the JSON-RPC result for a prompts/get response.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// PromptDefinition describes a single prompt template exposed by an MCP server.
type PromptDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

// ListPromptsResult is the result of a prompts/list response.
type ListPromptsResult struct {
	Prompts    []PromptDefinition `json:"prompts"`
	NextCursor string             `json:"nextCursor,omitempty"`
}

// --- MCP completion types ---

// CompletionItems holds the suggestions returned by a completion/complete response.
type CompletionItems struct {
	Values  []string `json:"values"`
	Total   int      `json:"total,omitempty"`
	HasMore bool     `json:"hasMore,omitempty"`
}

// CompletionCompleteResult is the JSON-RPC result for a completion/complete response.
type CompletionCompleteResult struct {
	Completion CompletionItems `json:"completion"`
}

// --- JSON-RPC error codes ---

const (
	RPCParseError     = -32700
	RPCInvalidRequest = -32600
	RPCMethodNotFound = -32601
	RPCInvalidParams  = -32602
	RPCInternalError  = -32603
)
