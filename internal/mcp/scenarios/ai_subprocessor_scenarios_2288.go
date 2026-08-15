// MCP test scenarios for AI subprocessor data-flow visibility rules.
// Issue #2288.
//
// Rules tested:
//   mcp-subprocessor-audit-ai-relay-tool-name — tool name matches AI relay/proxy/router patterns (AUDIT)
//   mcp-subprocessor-audit-llm-api-call-args  — tool args match OpenAI/Anthropic chat API shape (AUDIT)
//
// Attack vector:
//   An MCP tool is itself a relay to a foundation model provider (OpenAI, Anthropic,
//   Mistral, etc.). User and agent data flows to an undisclosed fourth-party
//   subprocessor. These AUDIT rules surface the signal for compliance review without
//   blocking intentional AI-relay architectures.
//
// Taxonomy: governance-risk/ai-governance-gap/ai-subprocessor-data-flow-gap

package scenarios

// AISubprocessorScenarios2288 covers AI subprocessor data flow detection.
var AISubprocessorScenarios2288 = []Scenario{

	// ── TP: tool name matches AI relay/proxy/router pattern (AUDIT) ──────────

	{
		ID:               "MCP-TP-2288-001",
		ToolName:         "ai_gateway_call",
		Arguments:        map[string]interface{}{"model": "gpt-4o", "prompt": "Summarize this document"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "ai_gateway_call — tool name contains 'ai_gateway', signals undisclosed AI subprocessor relay, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-002",
		ToolName:         "llm_proxy_query",
		Arguments:        map[string]interface{}{"prompt": "What is the capital of France?", "temperature": 0.7},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "llm_proxy_query — tool name contains 'llm_proxy', must AUDIT for subprocessor visibility",
	},
	{
		ID:               "MCP-TP-2288-003",
		ToolName:         "model_router_invoke",
		Arguments:        map[string]interface{}{"route": "openai", "query": "Translate to Spanish"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "model_router_invoke — 'model_router' pattern indicates routing to external AI provider, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-004",
		ToolName:         "ai-relay",
		Arguments:        map[string]interface{}{"input": "user data", "provider": "anthropic"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "ai-relay — explicit AI relay tool, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-005",
		ToolName:         "llm_bridge_send",
		Arguments:        map[string]interface{}{"text": "explain this code", "model": "claude-3"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "llm_bridge_send — 'llm_bridge' pattern, must AUDIT",
	},

	// ── TP: args match OpenAI/Anthropic chat API shape (AUDIT) ───────────────

	{
		ID:               "MCP-TP-2288-006",
		ToolName:         "proxy_chat",
		Arguments:        map[string]interface{}{"model": "gpt-4o", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "Hello"}}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "proxy_chat with model=gpt-4o + messages — OpenAI chat API shape signals undisclosed AI relay, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-007",
		ToolName:         "relay_completion",
		Arguments:        map[string]interface{}{"model": "claude-sonnet-4-6", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "Summarize"}}, "temperature": 0.5},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "relay_completion with model=claude-sonnet-4-6 + messages — Anthropic format relay, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-008",
		ToolName:         "forward_request",
		Arguments:        map[string]interface{}{"model": "mistral-large", "messages": []interface{}{map[string]interface{}{"role": "system", "content": "You are helpful"}}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "forward_request with model=mistral-large + messages — Mistral chat API relay, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-009",
		ToolName:         "custom_inference",
		Arguments:        map[string]interface{}{"model": "llama-3-70b", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "Write code"}}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "custom_inference with model=llama-3-70b + messages — Llama relay, must AUDIT",
	},
	{
		ID:               "MCP-TP-2288-010",
		ToolName:         "completion_service",
		Arguments:        map[string]interface{}{"model": "deepseek-r1", "messages": []interface{}{map[string]interface{}{"role": "user", "content": "Solve this"}}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "completion_service with model=deepseek-r1 + messages — DeepSeek relay, must AUDIT",
	},

	// ── TN: benign tool names (no AI relay pattern) ───────────────────────────

	{
		ID:               "MCP-TN-2288-001",
		ToolName:         "list_files",
		Arguments:        map[string]interface{}{"path": "/workspace"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "list_files — no AI relay pattern in tool name, must not AUDIT",
	},
	{
		ID:               "MCP-TN-2288-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "read_file — standard read tool, no relay pattern in name, must not AUDIT",
	},
	{
		ID:               "MCP-TN-2288-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/README.md", "content": "project notes"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-ai-relay-tool-name",
		Description:      "write_file — no relay pattern in tool name, must not AUDIT",
	},

	// ── TN: args don't match chat API shape (no model+messages combination) ──

	{
		ID:               "MCP-TN-2288-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "read_file — no model or messages args present, must not AUDIT",
	},
	{
		ID:               "MCP-TN-2288-005",
		ToolName:         "list_files",
		Arguments:        map[string]interface{}{"path": "/workspace/src"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "list_files — no model or messages args, must not AUDIT",
	},
	{
		ID:               "MCP-TN-2288-006",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-subprocessor-audit-llm-api-call-args",
		Description:      "read_file with README path — no model or messages args, must not AUDIT",
	},
}
