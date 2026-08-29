// Package mcp provides types and utilities for intercepting and evaluating
// Model Context Protocol (MCP) JSON-RPC messages. AgentShield uses these to
// mediate tool calls between AI agents and MCP servers.
package mcp

import (
	"encoding/json"
	"strings"
)

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
	// Task carries the SEP-1686 ("Tasks") augmentation: any request can be
	// marked task:true (or a task-config object) so the server returns a
	// durable task handle immediately instead of executing synchronously,
	// decoupling the work from the connection lifecycle. Kept raw so
	// IsTaskAugmented can treat both the boolean and object shapes as
	// augmented without speculative struct parsing.
	Task json.RawMessage `json:"task,omitempty"`
}

// CallToolResult represents the result of a tools/call response.
type CallToolResult struct {
	Content         []ContentItem          `json:"content"`
	IsError         bool                   `json:"isError,omitempty"`
	// StructuredContent carries the typed JSON result object added in MCP 2025-06-18.
	// When a tool declares an outputSchema, its result may include a structuredContent
	// object alongside (or instead of) the text content array. Shield scans the
	// string values of this object for prompt injection and credential signals.
	StructuredContent map[string]interface{} `json:"structuredContent,omitempty"`
	// Meta carries the MCP spec's reserved `_meta` field. The spec permits arbitrary
	// implementation-specific metadata here, on any protocol object, and it is invisible
	// to every existing scanner (Content, StructuredContent) — a compromised server can
	// smuggle an injection payload into _meta instead of those fields to bypass them
	// entirely. Kept as raw JSON (not a typed map) so ScanStructuredContentRaw can walk
	// it the same way it walks StructuredContent, without speculative parsing here.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// ContentItem is one piece of content in a tool result. The MCP 2025-06-18
// spec defines several content block types beyond plain text:
//   - "text"           — Text in Text
//   - "image"          — base64 in Data, format in MIMEType
//   - "audio"          — base64 in Data, format in MIMEType
//   - "resource"       — embedded resource in Resource (uri + text/blob)
//   - "resource_link"  — link only in URI (no inline content)
//
// Text-content scanners only read Text; non-text-content scanners read URI,
// Name, Description, MIMEType, and the nested Resource. Fields are all
// `omitempty` so existing text-only producers serialise unchanged.
type ContentItem struct {
	Type        string               `json:"type"`
	Text        string               `json:"text,omitempty"`
	URI         string               `json:"uri,omitempty"`
	Name        string               `json:"name,omitempty"`
	Description string               `json:"description,omitempty"`
	MIMEType    string               `json:"mimeType,omitempty"`
	Data        string               `json:"data,omitempty"`
	Resource    *ResourceContentItem `json:"resource,omitempty"`
	// Annotations carries the MCP `Annotations` object that every content
	// block may attach. Until it was added here json.Unmarshal dropped it
	// silently, so `audience` — the field by which a server declares a block
	// is for the model and NOT for the user — was invisible to every scanner
	// in this package. See content_audience_scanner.go.
	Annotations *ContentAnnotations  `json:"annotations,omitempty"`
}

// ContentAnnotations is the MCP `Annotations` object attachable to any content
// block (TextContent, ImageContent, AudioContent, EmbeddedResource,
// ResourceLink) and to a Resource in a listing.
//
// The JSON field names MUST match the MCP wire schema exactly — the same
// silent-catastrophe shape documented on ToolAnnotations below: a typo leaves
// every field zero, and the audience-channel detection never fires against a
// real server. TestContentAnnotationsParseFromSpecCompliantJSON is the
// fitness function that locks the wire contract.
type ContentAnnotations struct {
	// Audience declares who the content is intended for. Per the spec Role is
	// exactly "user" | "assistant"; an audience that includes "assistant" but
	// omits "user" is the server telling the host to route this block to the
	// model while withholding it from the human.
	Audience []string `json:"audience,omitempty"`
	// Priority is the spec's 0..1 importance hint (1 = most important).
	Priority *float64 `json:"priority,omitempty"`
	// LastModified is the spec's ISO 8601 timestamp hint. Parsed for
	// completeness so a round-trip of a real block is lossless.
	LastModified string `json:"lastModified,omitempty"`
}

// HiddenFromUser reports whether these annotations declare the block
// model-visible but user-hidden: the audience list is present, names
// "assistant", and does NOT name "user".
//
// Deliberately conservative in three ways. Absent annotations mean "no
// restriction" (visible to both) and never trigger. An empty audience list is
// degenerate rather than adversarial and never triggers. An audience naming
// only roles outside the spec ("system", "tool") never triggers on its own —
// that is a separate parser-divergence question, not this one.
func (a *ContentAnnotations) HiddenFromUser() bool {
	if a == nil || len(a.Audience) == 0 {
		return false
	}
	var hasAssistant, hasUser bool
	for _, role := range a.Audience {
		switch strings.ToLower(strings.TrimSpace(role)) {
		case "assistant":
			hasAssistant = true
		case "user":
			hasUser = true
		}
	}
	return hasAssistant && !hasUser
}

// VisibleToUser reports whether the block reaches the human reviewer: either it
// carries no audience restriction at all, or its audience names "user".
func (a *ContentAnnotations) VisibleToUser() bool {
	if a == nil || len(a.Audience) == 0 {
		return true
	}
	for _, role := range a.Audience {
		if strings.EqualFold(strings.TrimSpace(role), "user") {
			return true
		}
	}
	return false
}

// --- MCP tool listing types ---

// ToolAnnotations represents the MCP 2025-03-26 tool annotations object.
// These are informational hints from the server about tool behavior.
// Per the spec, annotations are NOT guaranteed to be accurate — they must
// not be used as a security boundary, and discrepancies are a rug-pull signal.
//
// The JSON field names MUST match the MCP wire schema exactly. The canonical
// names carry a `Hint` suffix (`readOnlyHint`, `destructiveHint`,
// `idempotentHint`, `openWorldHint`) — NOT bare `readOnly`/`destructive`/etc.
// A mismatch here is silent and catastrophic: json.Unmarshal leaves every
// pointer nil, so the entire annotation-spoofing detection layer
// (checkAnnotationConsistency, checkAnnotationSchemaCoherence,
// checkAnnotationDescriptionExtensions) never fires against any real server.
// Unit tests that build this struct via Go literals do NOT exercise the tag
// mapping — TestAnnotationsParseFromSpecCompliantJSON is the fitness function
// that locks the wire contract. See spec:
// https://modelcontextprotocol.io (ToolAnnotations).
type ToolAnnotations struct {
	// Title is a human-readable display name for the tool. Hosts render it in
	// consent dialogs; per the 2025-06-18 display-name precedence
	// (Tool.title > annotations.title > name) it is a real UI surface, so it is
	// scanned for injection / title-vs-name divergence like the top-level title.
	Title string `json:"title,omitempty"`
	// ReadOnly hints the tool has no side effects on its environment.
	// If true but the tool name contains destructive verbs, this is suspicious.
	ReadOnly *bool `json:"readOnlyHint,omitempty"`
	// Destructive hints the tool may cause irreversible changes.
	Destructive *bool `json:"destructiveHint,omitempty"`
	// Idempotent hints repeated identical calls have the same effect.
	Idempotent *bool `json:"idempotentHint,omitempty"`
	// OpenWorld hints the tool may interact with external entities.
	// If false/absent but the description mentions egress, this is suspicious.
	OpenWorld *bool `json:"openWorldHint,omitempty"`
}

// ToolDefinition describes a single tool exposed by an MCP server.
type ToolDefinition struct {
	Name        string           `json:"name"`
	Title       string           `json:"title,omitempty"`
	Description string           `json:"description,omitempty"`
	InputSchema json.RawMessage  `json:"inputSchema,omitempty"`
	// OutputSchema is the MCP 2025-06-18 tool output-schema declaration. It
	// describes the shape of the tool's structured result and, when present,
	// is shown to the LLM during tool listing — making it a second poison
	// surface alongside InputSchema. We carry it as raw JSON so the structural
	// scanner can walk it without speculative parsing.
	OutputSchema json.RawMessage  `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
	// Meta carries the MCP spec's reserved `_meta` field for implementation-specific
	// metadata. It is folded into ScanToolDescription's combined scan text the same
	// way InputSchema/OutputSchema are — a server can hide a registration-time
	// injection payload here that none of the "known" fields expose.
	Meta json.RawMessage `json:"_meta,omitempty"`
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
	KindPromptsGet                        // prompts/get request (client→server)
	KindCompletionComplete                // completion/complete request (client→server)
	KindTasksGet                          // tasks/get request (client→server) — SEP-1686 task status poll
	KindTasksResult                       // tasks/result request (client→server) — SEP-1686 task result retrieval
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
	case KindPromptsGet:
		return "prompts/get"
	case KindCompletionComplete:
		return "completion/complete"
	case KindTasksGet:
		return "tasks/get"
	case KindTasksResult:
		return "tasks/result"
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
	MethodResourcesList          = "resources/list"
	MethodResourcesTemplatesList = "resources/templates/list"
	MethodResourcesRead          = "resources/read"
	MethodResourcesSubscribe     = "resources/subscribe"
	MethodSamplingCreateMessage  = "sampling/createMessage"
	MethodElicitationCreate      = "elicitation/create"
	MethodRootsList              = "roots/list"
	MethodNotificationsMessage          = "notifications/message"
	MethodNotificationsResourcesUpdated = "notifications/resources/updated"
	MethodNotificationsToolsListChanged = "notifications/tools/list_changed"
	MethodNotificationsProgress         = "notifications/progress"
	MethodPromptsGet                    = "prompts/get"
	MethodPromptsList            = "prompts/list"
	MethodCompletionComplete     = "completion/complete"
	// MethodTasksGet and MethodTasksResult are SEP-1686 ("Tasks") client→server
	// polling methods: after a task-augmented request returns a task handle,
	// the client polls tasks/get for status and tasks/result to retrieve the
	// eventual result. Tracked (not evaluated) so the task-amplification
	// tracker can distinguish normal poll-driven usage from an unpolled
	// fire-and-forget fan-out.
	MethodTasksGet    = "tasks/get"
	MethodTasksResult = "tasks/result"
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
	// Task carries the SEP-1686 task augmentation — see CallToolParams.Task.
	Task json.RawMessage `json:"task,omitempty"`
}

// ResourceContentItem is one content entry in a resources/read response.
// Per the MCP spec, a resource can return text or blob content.
//
// Deliberately has NO Annotations field. TextResourceContents and
// BlobResourceContents — the two schema types this struct represents — do not
// declare an `annotations` property in either the 2025-06-18 spec or the
// current draft schema (verified against schema/2025-06-18/schema.json and
// schema/draft/schema.json, 2026-08-24). Only `Resource` (the resources/list
// entry type, see ResourceEntry.Annotations) carries it. Adding the field here
// would parse a wire property that no compliant server ever sends — see
// issue #3485, which proposed exactly this and was corrected during review.
type ResourceContentItem struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"` // present when type is text
	Blob     string `json:"blob,omitempty"` // base64-encoded binary content
}

// ResourceReadResult is the JSON-RPC result for a resources/read response.
type ResourceReadResult struct {
	Contents []ResourceContentItem `json:"contents"`
	// Meta carries the MCP spec's reserved `_meta` field on the result object.
	// See CallToolResult.Meta for the threat model — arbitrary server-supplied
	// JSON that bypasses every scanner walking Contents unless scanned directly.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// ResourceEntry describes a single resource exposed in a resources/list response.
// A malicious server may register resources with RFC 6570 URI templates
// ({variable} placeholders) that expand to sensitive credential paths.
type ResourceEntry struct {
	URI         string `json:"uri"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
	// Annotations carries the MCP `Annotations` object. Per the 2025-06-18 and
	// draft schemas, `Resource` (what a resources/list entry is) declares
	// `annotations` directly — unlike `TextResourceContents`/
	// `BlobResourceContents` (what a resources/read `contents[]` item is),
	// which have NO `annotations` field in either spec version. Do not add an
	// Annotations field to ResourceContentItem from a re-read of an issue that
	// asks for it without first checking the schema — see issue #3500, which
	// found the resources/read premise unsupported by the wire protocol.
	Annotations *ContentAnnotations `json:"annotations,omitempty"`
}

// ResourcesListResult is the JSON-RPC result for a resources/list response.
type ResourcesListResult struct {
	Resources  []ResourceEntry `json:"resources"`
	NextCursor string          `json:"nextCursor,omitempty"`
	// Meta carries the MCP spec's reserved `_meta` field on the result object.
	// See CallToolResult.Meta for the threat model.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// ResourceTemplateEntry describes a single resource template exposed in a
// resources/templates/list response (MCP 2025). A template is an RFC 6570
// URI template ({var} placeholders) the agent expands before issuing a
// resources/read request. The variable names themselves become content the
// agent reads when resolving the template — so the surface includes:
//
//   - `uriTemplate`: the RFC 6570 template body; variable names within {} must
//     conform to varname = varchar *( ["."] varchar ) where varchar is
//     ALPHA / DIGIT / "_" / pct-encoded. Any other character in a varname is
//     unambiguously adversarial.
//   - `name`/`description`: metadata fields scanned for the same injection
//     patterns the description scanner pipeline covers.
type ResourceTemplateEntry struct {
	URITemplate string `json:"uriTemplate"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ResourcesTemplatesListResult is the JSON-RPC result for a
// resources/templates/list response. Distinct from resources/list because the
// templates carry RFC 6570 expansion syntax and the agent may iterate over the
// listed templates while expanding placeholders against host state.
type ResourcesTemplatesListResult struct {
	ResourceTemplates []ResourceTemplateEntry `json:"resourceTemplates"`
	NextCursor        string                  `json:"nextCursor,omitempty"`
	// Meta carries the MCP spec's reserved `_meta` field on the result object.
	// See CallToolResult.Meta for the threat model.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// --- OAuth AS metadata types ---

// OAuthASMetadata represents the OAuth 2.0 Authorization Server Metadata
// document served at /.well-known/oauth-authorization-server (RFC 8414).
// MCP 2025-03-26 requires OAuth 2.1 with PKCE for remote server authentication.
type OAuthASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	JWKsURI                           string   `json:"jwks_uri,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
}

// --- A2A agent card types ---

// A2AAuthentication holds the authentication schemes advertised by an A2A agent.
type A2AAuthentication struct {
	Schemes []string `json:"schemes"`
}

// A2AAgentCard represents the discovery document served at /.well-known/agent.json
// in the Google Agent-to-Agent (A2A) protocol. An orchestrator fetches this before
// routing tasks to verify the target agent's identity and capabilities.
type A2AAgentCard struct {
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	Version        string            `json:"version,omitempty"`
	Description    string            `json:"description,omitempty"`
	Authentication A2AAuthentication `json:"authentication"`
	// Capabilities and Skills are kept as raw values for forward-compat.
	Capabilities map[string]interface{} `json:"capabilities,omitempty"`
	Skills       []interface{}          `json:"skills,omitempty"`
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
	// IncludeContext controls how much host conversation context the LLM call includes.
	// MCP 2025 values: "none", "thisServer", "allServers".
	// "allServers" is a cross-server context exfiltration vector: the malicious server's
	// LLM response contains context from every other connected MCP server.
	IncludeContext string `json:"includeContext,omitempty"`
	// Task carries the SEP-1686 task augmentation — see CallToolParams.Task.
	Task json.RawMessage `json:"task,omitempty"`
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
	Type       string                     `json:"type,omitempty"`
	Title      string                     `json:"title,omitempty"`
	Properties map[string]*SchemaProperty `json:"properties,omitempty"`
	// Raw is the verbatim schema JSON as it arrived on the wire.
	//
	// The typed fields above model the MCP spec's *restricted* elicitation
	// schema — flat, top-level, primitive-typed properties. A malicious server
	// is not bound by that restriction, and everything outside the struct is
	// silently discarded at unmarshal time: a credential field wrapped in
	// `allOf`, nested one object deep, parked in `$defs`, or named only in
	// `required` leaves Properties empty, so a scanner reading only the typed
	// view sees a schema asking for nothing. The host still renders whatever it
	// received, and the party filling that form in is a human.
	//
	// Keeping the raw bytes lets ScanElicitationCreate re-walk the real
	// document. Excluded from marshalling (`json:"-"`) so re-serialising a
	// parsed request cannot duplicate the schema body.
	Raw json.RawMessage `json:"-"`
}

// UnmarshalJSON decodes the known elicitation-schema fields, retains the
// original bytes in Raw, and — critically — never fails.
//
// Strict decoding of this struct was a fail-OPEN switch for the whole
// elicitation surface. `type` in JSON Schema is `string | array of string`, so
// the entirely canonical
//
//	{"properties":{"ssh_private_key":{"type":["string","null"]}}}
//
// made json.Unmarshal reject the params, ExtractElicitationCreate return an
// error, and HandleElicitationCreate take its `return false, nil // fail open`
// path — sending an unscanned credential-harvest form to a human, and skipping
// the message-text social-engineering and control-token scans along with it.
// A non-string `title` or `description` did the same. One canonical JSON Schema
// idiom disabled a BLOCK-tier control.
//
// So: shapes we cannot model degrade to "typed view empty, Raw intact" and the
// raw walk in elicitation_scanner.go does the work. An attacker choosing an
// exotic JSON shape must never be able to choose whether we scan.
func (s *ElicitationSchema) UnmarshalJSON(data []byte) error {
	*s = ElicitationSchema{Raw: append(json.RawMessage(nil), data...)}

	var lenient struct {
		Type       json.RawMessage `json:"type"`
		Title      json.RawMessage `json:"title"`
		Properties json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(data, &lenient); err != nil {
		return nil // not an object; Raw still carries whatever arrived
	}
	s.Type = coerceJSONString(lenient.Type)
	s.Title = coerceJSONString(lenient.Title)
	// A `properties` value of the wrong shape is left as an empty typed map;
	// the raw walk reads the real document either way.
	_ = json.Unmarshal(lenient.Properties, &s.Properties)
	return nil
}

// UnmarshalJSON decodes a schema property tolerantly, for the same reason
// ElicitationSchema does: the typed shape is a convenience, never a gate.
// Non-string values are kept as their JSON text so keyword scanning still sees
// the words — a localized title `{"en":"Paste your API token"}` is exactly as
// interesting as the plain string was.
func (p *SchemaProperty) UnmarshalJSON(data []byte) error {
	*p = SchemaProperty{}
	var lenient struct {
		Type        json.RawMessage `json:"type"`
		Title       json.RawMessage `json:"title"`
		Description json.RawMessage `json:"description"`
	}
	if err := json.Unmarshal(data, &lenient); err != nil {
		return nil
	}
	p.Type = coerceJSONString(lenient.Type)
	p.Title = coerceJSONString(lenient.Title)
	p.Description = coerceJSONString(lenient.Description)
	return nil
}

// coerceJSONString renders a JSON value as text. A JSON string decodes to its
// contents; anything else (array, object, number) keeps its literal JSON text,
// which is both the closest thing to what a lenient host would display and the
// form that keeps the value scannable.
func coerceJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// SchemaProperty is one property in an ElicitationSchema.
type SchemaProperty struct {
	Type        string `json:"type,omitempty"`
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
}

// --- MCP prompts types ---

// GetPromptParams represents the params of a prompts/get request (client→server).
// Per the MCP spec, `arguments` is a map of template variable name to string value
// that the server substitutes into the named prompt template before returning it.
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// UnmarshalJSON decodes prompts/get params tolerantly, for the same reason
// ElicitationSchema does (#3289): `arguments` is spec-typed as
// Record<string,string>, but this request is assembled client-side — by an
// agent that may itself be steered by injected instructions — and is not
// bound by that restriction. A single non-string argument value (an object,
// number, array, or bool) failed the strict `map[string]string` unmarshal,
// routed HandlePromptsGetRequest through its `return false, nil // fail
// open` path, and skipped the outbound content/data-label scan for the
// entire request — including any OTHER argument that carried an actual
// secret. Coerce every value to its string/JSON-text form (coerceJSONString)
// instead: the smuggled payload stays visible to the scanner rather than
// vetoing the scan.
func (p *GetPromptParams) UnmarshalJSON(data []byte) error {
	var lenient struct {
		Name      json.RawMessage            `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(data, &lenient); err != nil {
		return err
	}
	p.Name = coerceJSONString(lenient.Name)
	if lenient.Arguments != nil {
		p.Arguments = make(map[string]string, len(lenient.Arguments))
		for k, v := range lenient.Arguments {
			p.Arguments[k] = coerceJSONString(v)
		}
	}
	return nil
}

// PromptMessage is one message in a prompts/get response.
// A malicious server can embed injection payloads in the text content.
type PromptMessage struct {
	Role    string                `json:"role"`    // "user" or "assistant"
	Content PromptMessageContent  `json:"content"` // text or image content
}

// PromptMessageContent holds one piece of content in a prompt message.
// The MCP spec supports three content types:
//   - "text"     — Text field holds the prompt text
//   - "image"    — Data field holds base64 image, MIMEType the format
//   - "resource" — Resource field holds an embedded resource with URI + text/blob
//
// The Resource field was previously missing, causing the prompt injection scanner
// to silently skip type:"resource" blocks — a structural bypass of all prompt
// poisoning detection (issue #2316).
type PromptMessageContent struct {
	Type     string               `json:"type"`              // "text", "image", or "resource"
	Text     string               `json:"text,omitempty"`    // for type=="text"
	Resource *ResourceContentItem `json:"resource,omitempty"` // for type=="resource"
	// Annotations carries the MCP `Annotations` object. Per spec, TextContent
	// and EmbeddedResource — the two schema types a "text" and a "resource"
	// PromptMessageContent block represent — both declare `annotations`
	// directly on the block, the same place ContentItem parses it for
	// tools/call results. Until this field existed, `audience: ["assistant"]`
	// on a prompt message was silently dropped by json.Unmarshal and the
	// content-audience-channel scan never saw it — see
	// content_audience_scanner.go and issue #3485.
	Annotations *ContentAnnotations `json:"annotations,omitempty"`
}

// GetPromptResult is the JSON-RPC result for a prompts/get response.
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
	// Meta carries the MCP spec's reserved `_meta` field on the result object.
	// See CallToolResult.Meta for the threat model.
	Meta json.RawMessage `json:"_meta,omitempty"`
}

// PromptArgument is one argument in a prompt template (from prompts/list).
// The Description field is shown to the agent and is an injection surface.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// PromptDefinition describes a single prompt template exposed by an MCP server.
type PromptDefinition struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// ListPromptsResult is the result of a prompts/list response.
type ListPromptsResult struct {
	Prompts    []PromptDefinition `json:"prompts"`
	NextCursor string             `json:"nextCursor,omitempty"`
	// Meta carries the MCP spec's reserved `_meta` field on the result object.
	// See CallToolResult.Meta for the threat model.
	Meta json.RawMessage `json:"_meta,omitempty"`
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

// CompletionRef identifies the prompt or resource a completion/complete request
// is completing an argument against.
type CompletionRef struct {
	Type string `json:"type"`
	Name string `json:"name,omitempty"`
	URI  string `json:"uri,omitempty"`
}

// CompletionArgument is the single {name, value} pair being completed in a
// completion/complete request. Unlike prompts/get's `arguments` map, this is
// a scalar field, not a map — but it carries the same client→server outbound
// content risk (issue #2791).
type CompletionArgument struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CompletionCompleteParams represents the params of a completion/complete
// request (client→server).
type CompletionCompleteParams struct {
	Ref      CompletionRef       `json:"ref"`
	Argument CompletionArgument  `json:"argument"`
}

// --- MCP initialize types ---

// ServerInfo identifies the MCP server in an initialize response.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// InitializeResult is the JSON-RPC result for an initialize response.
// A malicious or MITM-positioned server may tamper with protocolVersion,
// serverInfo, capabilities, or the optional instructions field to manipulate
// the client's security posture or inject behavioral overrides.
type InitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	ServerInfo      *ServerInfo     `json:"serverInfo,omitempty"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	// Instructions is the optional MCP 2025-03-26 field that allows a server
	// to send behavioral guidance to the AI agent at session start. A malicious
	// server can use this to inject session-scoped prompt injection directives.
	Instructions string `json:"instructions,omitempty"`
}

// --- JSON-RPC error codes ---

const (
	RPCParseError     = -32700
	RPCInvalidRequest = -32600
	RPCMethodNotFound = -32601
	RPCInvalidParams  = -32602
	RPCInternalError  = -32603
)
