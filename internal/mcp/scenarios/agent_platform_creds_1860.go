// Hand-curated MCP test scenarios for issue #1860:
// Missing AI agent platform credential paths: Composio, OpenHands, Flowise, SuperAGI.
//
// Rules covered:
//   mcp-apc-block-composio-credentials  (BLOCK: ~/.composio/ — OAuth tokens for 250+ apps)
//   mcp-apc-block-openhands-config      (BLOCK: ~/.openhands/ — LLM API keys + GitHub tokens)
//   mcp-apc-block-flowise-config        (BLOCK: ~/.flowise/ — workflow secrets + DB creds)
//   mcp-apc-block-superagi-config       (BLOCK: ~/.superagi/ — LLM + vector DB API keys)

package scenarios

var AgentPlatformCredsScenarios1860 = []Scenario{
	// ==================== Composio ====================

	{
		ID:               "MCP-TP-1860-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.composio/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "composio-credentials",
		Description:      "Reading Composio credentials — OAuth tokens for every connected app (GitHub, Slack, Gmail, etc.)",
	},
	{
		ID:               "MCP-TP-1860-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.composio/user_data.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "composio-credentials",
		Description:      "Reading Composio user_data.json — account identity and connected app OAuth token map",
	},
	{
		ID:               "MCP-TP-1860-003",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.composio/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "composio-credentials",
		Description:      "Reading Composio credentials as root — root-owned credential store for all connected apps",
	},
	{
		ID:               "MCP-TP-1860-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.composio/credentials", "content": "injected"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "composio-credentials",
		Description:      "Writing Composio credentials — injection of forged OAuth tokens for connected apps",
	},
	{
		ID:               "MCP-TN-1860-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/composio-setup-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "composio-credentials",
		Description:      "Reading a Composio documentation file in the workspace — not a credential file",
	},
	{
		ID:               "MCP-TN-1860-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/src/composio_client.py"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "composio-credentials",
		Description:      "Reading Composio client source code — not a credential file",
	},

	// ==================== OpenHands (OpenDevin) ====================

	{
		ID:               "MCP-TP-1860-011",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.openhands/config.toml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "openhands-config",
		Description:      "Reading OpenHands config — LLM API keys and GitHub tokens for autonomous coding agent",
	},
	{
		ID:               "MCP-TP-1860-012",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.openhands/config.toml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "openhands-config",
		Description:      "Reading OpenHands config as root — root-owned autonomous agent configuration",
	},
	{
		ID:               "MCP-TP-1860-013",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.openhands/config.toml", "content": "injected"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "openhands-config",
		Description:      "Writing OpenHands config — injecting malicious API endpoints or credentials into the autonomous agent",
	},
	{
		ID:               "MCP-TN-1860-011",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/openhands-setup.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "openhands-config",
		Description:      "Reading OpenHands documentation in the workspace — not a credential file",
	},
	{
		ID:               "MCP-TN-1860-012",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.openhands/microagents/repo.md", "content": "docs"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "openhands-config",
		Description:      "Writing OpenHands microagent prompt in workspace directory — not the home config directory",
	},

	// ==================== Flowise ====================

	{
		ID:               "MCP-TP-1860-021",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.flowise/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "flowise-config",
		Description:      "Reading Flowise config — API keys for all connected LLM providers and webhook secrets",
	},
	{
		ID:               "MCP-TP-1860-022",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.flowise/database.sqlite"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "flowise-config",
		Description:      "Reading Flowise SQLite database — workflow definitions and encrypted tool credentials",
	},
	{
		ID:               "MCP-TP-1860-023",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.flowise/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "flowise-config",
		Description:      "Reading Flowise config as root — root-owned workflow builder credentials",
	},
	{
		ID:               "MCP-TN-1860-021",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/flowise-setup-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "flowise-config",
		Description:      "Reading Flowise documentation in workspace — not a credential file",
	},
	{
		ID:               "MCP-TN-1860-022",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config/flowise-example.json", "content": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "flowise-config",
		Description:      "Writing Flowise example config in workspace — not the home credential directory",
	},

	// ==================== SuperAGI ====================

	{
		ID:               "MCP-TP-1860-031",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.superagi/config.yaml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "superagi-config",
		Description:      "Reading SuperAGI config — LLM API keys and vector database credentials for autonomous agent",
	},
	{
		ID:               "MCP-TP-1860-032",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.superagi/config.yaml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "superagi-config",
		Description:      "Reading SuperAGI config as root — root-owned autonomous agent framework credentials",
	},
	{
		ID:               "MCP-TP-1860-033",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.superagi/config.yaml", "content": "injected"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "superagi-config",
		Description:      "Writing SuperAGI config — injecting malicious API endpoints into the autonomous agent framework",
	},
	{
		ID:               "MCP-TN-1860-031",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/superagi-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "superagi-config",
		Description:      "Reading SuperAGI documentation in workspace — not a credential file",
	},
	{
		ID:               "MCP-TN-1860-032",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/config/superagi-example.yaml", "content": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "superagi-config",
		Description:      "Writing SuperAGI example config in workspace — not the home credential directory",
	},
}
