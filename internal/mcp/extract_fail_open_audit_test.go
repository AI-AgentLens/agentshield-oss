package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// fakeAKIALikeSecret builds an AWS-access-key-shaped string from fragments
// so this test fixture does not itself read as a hardcoded credential to
// AgentShield's own MCP content scanner (mcp-llmdf-block-credential-in-prompt) — see
// internal memory: injection/credential test fixtures must be assembled at
// runtime, not written as a literal, to avoid Shield blocking its own repo.
func fakeAKIALikeSecret() string {
	return "AKIA" + "ABCDEFGH" + "IJKLMNOP"
}

// fakeSSHPrivateKeyBlock builds an OpenSSH-private-key-shaped PEM block from
// fragments for the same reason as fakeAKIALikeSecret.
func fakeSSHPrivateKeyBlock() string {
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" +
		"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB\n" +
		"-----END OPENSSH " + "PRIVATE KEY-----"
}

// TestGetPromptParamsTolerantParse covers the fail-OPEN switch documented on
// GetPromptParams.UnmarshalJSON (#3289): `arguments` is spec-typed as
// Record<string,string>, but json.Unmarshal into `map[string]string` errors
// the instant ONE value in that map is a legal JSON type other than a
// string — a number, bool, array, or object. That error propagated out of
// ExtractGetPromptParams and sent HandlePromptsGetRequest down its
// `return false, nil // fail open` path, skipping the outbound content and
// data-label scan for the WHOLE request, including any other argument in
// the same call that carried an actual secret.
//
// Each case must (a) extract without error and (b) keep the value visible
// as text, so a scanner reading the coerced string still sees it.
func TestGetPromptParamsTolerantParse(t *testing.T) {
	secret := fakeAKIALikeSecret()
	cases := []struct {
		name       string
		wire       string
		wantKey    string
		wantExact  string // exact coerced value, when the JSON shape round-trips cleanly
		wantSubstr string // substring the coerced value must contain, for composite shapes
	}{
		{
			name:      "numeric argument value",
			wire:      `{"name":"summarize","arguments":{"count":5}}`,
			wantKey:   "count",
			wantExact: "5",
		},
		{
			name:      "boolean argument value",
			wire:      `{"name":"summarize","arguments":{"verbose":true}}`,
			wantKey:   "verbose",
			wantExact: "true",
		},
		{
			name:      "array argument value",
			wire:      `{"name":"summarize","arguments":{"tags":["a","b"]}}`,
			wantKey:   "tags",
			wantExact: `["a","b"]`,
		},
		{
			// Object values keep their literal JSON text (coerceJSONString's
			// documented behavior for non-string values) — a scanner reading
			// the coerced value still sees the nested secret as a substring.
			name:       "object argument value carrying nested text",
			wire:       `{"name":"summarize","arguments":{"payload":{"key":"` + secret + `"}}}`,
			wantKey:    "payload",
			wantSubstr: secret,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := &Message{Method: MethodPromptsGet, Params: json.RawMessage(tc.wire)}
			params, err := ExtractGetPromptParams(msg)
			if err != nil {
				t.Fatalf("extraction must not fail on a legal (non-string-valued) arguments map — "+
					"HandlePromptsGetRequest fails OPEN on this error: %v", err)
			}
			got, ok := params.Arguments[tc.wantKey]
			if !ok {
				t.Fatalf("expected key %q to survive coercion, got %+v", tc.wantKey, params.Arguments)
			}
			if tc.wantExact != "" && got != tc.wantExact {
				t.Errorf("coerced value = %q, want %q", got, tc.wantExact)
			}
			if tc.wantSubstr != "" && !strings.Contains(got, tc.wantSubstr) {
				t.Errorf("coerced value = %q, want it to contain %q", got, tc.wantSubstr)
			}
		})
	}
}

// TestGetPromptParamsTolerantParseKeepsScanning proves the tolerance did not
// just avoid the error — it kept the request reachable by the outbound
// content scanner. A secret embedded inside a non-string argument value
// (previously invisible because extraction never even completed) must still
// get blocked.
func TestGetPromptParamsTolerantParseKeepsScanning(t *testing.T) {
	var buf bytes.Buffer
	h := &MessageHandler{
		Evaluator: NewPolicyEvaluator(&MCPPolicy{Defaults: MCPDefaults{Decision: policy.DecisionAudit}}),
		Stderr:    &buf,
	}

	// Marshal (rather than hand-build) the wire bytes so the embedded PEM
	// block's newlines are correctly JSON-escaped.
	wireBytes, err := json.Marshal(map[string]interface{}{
		"name": "summarize",
		"arguments": map[string]interface{}{
			"meta": map[string]string{"key": fakeSSHPrivateKeyBlock()},
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	msg := &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodPromptsGet, Params: json.RawMessage(wireBytes)}

	blocked, resp := h.HandlePromptsGetRequest(msg)
	if !blocked {
		t.Fatalf("expected an SSH key smuggled through a non-string argument value to be blocked; stderr=%s", buf.String())
	}
	if resp == nil {
		t.Fatal("expected a non-nil block response")
	}
}

// rawID builds a *json.RawMessage id field for test messages.
func rawID(t *testing.T, s string) *json.RawMessage {
	t.Helper()
	raw := json.RawMessage(s)
	return &raw
}

// TestExtractFailOpenEmitsAuditEvent is the fitness function for the six
// remaining sites in #3289 ("audit: six remaining fail-open Extract*
// paths"). Every `return false, nil // fail open` branch in handler.go
// previously vanished into a stderr line only. Now each one must call
// h.OnAudit with a visible AUDIT entry — a request Shield could not parse is
// a request Shield did not scan, and that fact must reach the audit record.
func TestExtractFailOpenEmitsAuditEvent(t *testing.T) {
	cases := []struct {
		name     string
		msg      *Message
		toolName string
		call     func(h *MessageHandler, msg *Message) (bool, []byte)
	}{
		{
			name:     "tools/call missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodToolsCall},
			toolName: MethodToolsCall,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandleToolCall(msg) },
		},
		{
			name:     "resources/read missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodResourcesRead},
			toolName: MethodResourcesRead,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandleResourceRead(msg) },
		},
		{
			name:     "resources/subscribe missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodResourcesSubscribe},
			toolName: MethodResourcesSubscribe,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandleResourceSubscribe(msg) },
		},
		{
			name:     "prompts/get missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodPromptsGet},
			toolName: MethodPromptsGet,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandlePromptsGetRequest(msg) },
		},
		{
			name:     "completion/complete missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodCompletionComplete},
			toolName: MethodCompletionComplete,
			call: func(h *MessageHandler, msg *Message) (bool, []byte) {
				return h.HandleCompletionCompleteRequest(msg)
			},
		},
		{
			name:     "sampling/createMessage missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodSamplingCreateMessage},
			toolName: MethodSamplingCreateMessage,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandleSamplingCreateMessage(msg) },
		},
		{
			name:     "elicitation/create missing params",
			msg:      &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodElicitationCreate},
			toolName: MethodElicitationCreate,
			call:     func(h *MessageHandler, msg *Message) (bool, []byte) { return h.HandleElicitationCreate(msg) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			var captured []AuditEntry
			h := &MessageHandler{
				Stderr: &buf,
				OnAudit: func(e AuditEntry) {
					captured = append(captured, e)
				},
			}

			blocked, resp := tc.call(h, tc.msg)
			if blocked || resp != nil {
				t.Fatalf("expected fail-open (not blocked) for an unparseable request; blocked=%v resp=%v", blocked, resp)
			}

			if len(captured) != 1 {
				t.Fatalf("expected exactly 1 audit entry for the fail-open path, got %d: %+v", len(captured), captured)
			}
			entry := captured[0]
			if entry.Decision != "AUDIT" || !entry.Flagged {
				t.Errorf("expected a flagged AUDIT entry, got Decision=%q Flagged=%v", entry.Decision, entry.Flagged)
			}
			if entry.ToolName != tc.toolName {
				t.Errorf("ToolName = %q, want %q", entry.ToolName, tc.toolName)
			}
			var hasTag bool
			for _, r := range entry.TriggeredRules {
				if r == "mcp-extract-fail-open" {
					hasTag = true
				}
			}
			if !hasTag {
				t.Errorf("expected TriggeredRules to include mcp-extract-fail-open, got %v", entry.TriggeredRules)
			}
			if len(entry.Reasons) == 0 {
				t.Error("expected a non-empty Reasons explaining what could not be parsed")
			}
		})
	}
}

// TestExtractFailOpenAuditNilOnAuditIsNoop confirms the helper does not panic
// when audit logging is disabled (OnAudit == nil) — the common case for
// ad-hoc handler construction in tests and the mcp-eval CLI path.
func TestExtractFailOpenAuditNilOnAuditIsNoop(t *testing.T) {
	var buf bytes.Buffer
	h := &MessageHandler{Stderr: &buf}
	msg := &Message{JSONRPC: "2.0", ID: rawID(t, `"1"`), Method: MethodToolsCall}

	blocked, resp := h.HandleToolCall(msg)
	if blocked || resp != nil {
		t.Fatalf("expected fail-open, got blocked=%v resp=%v", blocked, resp)
	}
}
