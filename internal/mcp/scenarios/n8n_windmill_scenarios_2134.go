// Hand-curated MCP test scenarios for issue #2134:
// n8n and Windmill workflow platform credential file access detection.
//
// Rules covered:
//   mcp-sec-block-n8n-config-read      (BLOCK — ~/.n8n/config, contains encryptionKey)
//   mcp-sec-block-n8n-database-read    (BLOCK — ~/.n8n/database.sqlite, encrypted credentials)
//   mcp-sec-block-windmill-config-read (BLOCK — ~/.config/windmill/** and ~/.windmill/config.json)

package scenarios

// N8NWindmillScenarios2134 covers MCP rules blocking access to n8n and Windmill
// workflow platform credential and configuration files.
var N8NWindmillScenarios2134 = []Scenario{
	// TP: n8n config (encryptionKey) → BLOCK
	{
		ID:               "MCP-TP-2134-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.n8n/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "Read n8n config file — contains encryptionKey for all integration credentials, must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-002",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.n8n/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat n8n config as root — must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-003",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/home/ubuntu/.n8n/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "get_file_contents of n8n config — must BLOCK",
	},
	// TP: n8n SQLite database → BLOCK
	{
		ID:               "MCP-TP-2134-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.n8n/database.sqlite"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "Read n8n SQLite credential database — contains all encrypted integration credentials, must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-005",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/root/.n8n/database.sqlite"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat n8n database.sqlite as root — must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-006",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/home/ubuntu/.n8n/n8n.sqlite"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "Access to alternate n8n SQLite DB filename — must BLOCK",
	},
	// TP: Windmill config → BLOCK
	{
		ID:               "MCP-TP-2134-007",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.config/windmill/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "Read Windmill XDG config — contains workspace API token, must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-008",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.windmill/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "cat Windmill alternate config location — must BLOCK",
	},
	{
		ID:               "MCP-TP-2134-009",
		ToolName:         "open_file",
		Arguments:        map[string]interface{}{"path": "/Users/alice/.config/windmill/config.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "workflow-platform-credentials",
		Description:      "Open Windmill config on macOS — must BLOCK",
	},
	// TN: docs/workflow files about n8n and Windmill must NOT trigger
	{
		ID:               "MCP-TN-2134-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/n8n-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "Reading docs about n8n — path mentions n8n but is documentation, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2134-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/n8n/workflows/my-automation.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "Reading n8n workflow definition in project directory — not a credential file, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2134-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/data/analytics.sqlite"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "SQLite file in workspace (not n8n dir) — must NOT trigger",
	},
	{
		ID:               "MCP-TN-2134-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/windmill-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "Docs about Windmill — not a credential file, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2134-005",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/windmill/scripts/my-workflow.py"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "workflow-platform-credentials",
		Description:      "Windmill Python script in project — not a credential file, must NOT trigger",
	},
}
