// Hand-curated MCP test scenarios for Temporal Cloud credential access rules.
// Issue #1587: Temporal Cloud CLI credentials not blocked via MCP.
//
// Rules tested:
//   mcp-devtool-block-temporal-credentials  — blocks read/write of ~/.config/temporalio/**
//                                             and ~/.temporal/credentials

package scenarios

// TemporalScenarios1587 covers Temporal Cloud credential access detection.
var TemporalScenarios1587 = []Scenario{

	// ── mcp-devtool-block-temporal-credentials — TP cases ────────────────────

	{
		ID:       "MCP-TP-1587-001",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/home/user/.config/temporalio/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on Temporal Cloud API key file — must BLOCK",
	},
	{
		ID:       "MCP-TP-1587-002",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/home/user/.config/temporalio/temporal.yaml",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on Temporal CLI config (contains auth settings) — must BLOCK",
	},
	{
		ID:       "MCP-TP-1587-003",
		ToolName: "str_replace_editor",
		Arguments: map[string]interface{}{
			"path": "/home/user/.config/temporalio/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "str_replace_editor on Temporal credentials — must BLOCK (full tool family coverage)",
	},
	{
		ID:       "MCP-TP-1587-004",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path": "/home/user/.config/temporalio/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "write_file on Temporal credentials — must BLOCK (key replacement attack vector)",
	},
	{
		ID:       "MCP-TP-1587-005",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/home/user/.temporal/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on ~/.temporal/credentials (legacy location) — must BLOCK",
	},
	{
		ID:       "MCP-TP-1587-006",
		ToolName: "cat_file",
		Arguments: map[string]interface{}{
			"path": "/Users/alice/.config/temporalio/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "cat_file on macOS user Temporal credentials — must BLOCK",
	},
	{
		ID:       "MCP-TP-1587-007",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/root/.config/temporalio/credentials",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on root Temporal credentials — must BLOCK",
	},

	// ── mcp-devtool-block-temporal-credentials — TN cases ────────────────────

	{
		ID:       "MCP-TN-1587-001",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/workspace/docs/temporal-workflow-guide.md",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on Temporal documentation — must not BLOCK (workspace doc, not credential)",
	},
	{
		ID:       "MCP-TN-1587-002",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/workspace/src/temporal_client.go",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on Temporal Go client source — must not BLOCK (workspace source code)",
	},
	{
		ID:       "MCP-TN-1587-003",
		ToolName: "read_file",
		Arguments: map[string]interface{}{
			"path": "/workspace/temporal-worker.ts",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-devtool-block-temporal-credentials",
		Description:      "read_file on Temporal worker TypeScript source — must not BLOCK",
	},
}
