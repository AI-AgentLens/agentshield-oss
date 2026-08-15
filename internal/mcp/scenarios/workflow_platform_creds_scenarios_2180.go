// Hand-curated MCP test scenarios for issue #2180:
// Flowise/LangFlow/Dify AI workflow platform credential file access detection.
//
// Rules covered:
//   mcp-sec-block-flowise-config-read   (BLOCK — ~/.config/flowise/config.json)
//   mcp-sec-block-langflow-config-read  (BLOCK — ~/.config/langflow/credentials.json)
//   mcp-sec-block-dify-config-read      (BLOCK — ~/.dify/config.yaml)
//
// Rules live in packs/premium/mcp/mcp-devtool-creds.yaml.
// Taxonomy: credential-exposure/specialized-credentials/workflow-orchestration-credential-access
//
// Threat: AI workflow platforms (Flowise, LangFlow, Dify) store LLM provider API keys,
// OAuth tokens, and service credentials in user config dirs. An MCP read on these
// files exfiltrates all credentials in a single operation.
package scenarios

// WorkflowPlatformCredsScenarios2180 covers MCP rules blocking read access to
// Flowise, LangFlow, and Dify AI workflow platform credential configuration files.
var WorkflowPlatformCredsScenarios2180 = []Scenario{
	// TP: Flowise config read
	{
		ID:               "MCP-TP-2180-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.config/flowise/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "read_file Flowise config — contains API keys for all integrated LLM providers, must BLOCK",
	},
	{
		ID:               "MCP-TP-2180-002",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.config/flowise/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat_file Flowise config as root — must BLOCK",
	},
	{
		ID:               "MCP-TP-2180-003",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/home/ubuntu/.config/flowise/credentials.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "get_file_contents Flowise credentials.json — must BLOCK",
	},
	// TP: LangFlow config read
	{
		ID:               "MCP-TP-2180-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.config/langflow/credentials.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "read_file LangFlow credentials — API keys and OAuth tokens for all LLM providers, must BLOCK",
	},
	{
		ID:               "MCP-TP-2180-005",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.config/langflow/config.yaml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat_file LangFlow config as root — must BLOCK",
	},
	// TP: Dify config read
	{
		ID:               "MCP-TP-2180-006",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.dify/config.yaml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "read_file Dify config — model provider credentials and secret key, must BLOCK",
	},
	{
		ID:               "MCP-TP-2180-007",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.dify/credentials.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat_file Dify credentials as root — must BLOCK",
	},
	// TN: Flowise workspace files (not config)
	{
		ID:               "MCP-TN-2180-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/flowise/flows/my-chatbot.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "read_file Flowise flow file in project workspace — not a config dir, must NOT trigger",
	},
	// TN: LangFlow docs
	{
		ID:               "MCP-TN-2180-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/langflow-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "read_file LangFlow documentation — not a credential path, must NOT trigger",
	},
	// TN: Dify project workflow file
	{
		ID:               "MCP-TN-2180-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/dify/workflows/my-app.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "read_file Dify workflow definition in project workspace — not a credential path, must NOT trigger",
	},
}
