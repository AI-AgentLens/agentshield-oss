// MCP scenarios for issue #2056: agent orchestration hijacking via writes to
// LangGraph/CrewAI/AutoGen/Temporal config and definition files.

package scenarios

// OrchestrationHijackingScenarios2056 contains TP and TN test scenarios for:
//   - mcp-agentic-block-orchestration-config-write
//   - mcp-agentic-audit-agent-role-def-write
//   - mcp-agentic-audit-workflow-def-write
//
// in packs/premium/mcp/mcp-agentic-attacks.yaml.
var OrchestrationHijackingScenarios2056 = []Scenario{

	// === TPs: framework-specific orchestration config files (BLOCK) ===

	{
		ID:               "MCP-TP-2056-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/langgraph.json", "content": "{\"nodes\": {}}"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to langgraph.json — LangGraph state machine definition",
	},
	{
		ID:               "MCP-TP-2056-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/crew.yaml", "content": "crew_name: research"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to crew.yaml — CrewAI crew configuration",
	},
	{
		ID:               "MCP-TP-2056-003",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/app/OAI_CONFIG_LIST.json", "content": "[{\"model\": \"gpt-4\"}]"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to OAI_CONFIG_LIST.json — AutoGen OpenAI config",
	},
	{
		ID:               "MCP-TP-2056-004",
		ToolName:         "write_to_file",
		Arguments:        map[string]interface{}{"path": "/infra/temporal-server.yaml", "content": "temporal: {}"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to temporal-server.yaml — Temporal workflow engine config",
	},
	{
		ID:               "MCP-TP-2056-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/agents/autogen_config.json", "content": "{\"max_turns\": 100}"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to autogen_config.json — AutoGen agent config",
	},

	// === TPs: agent role definition files (AUDIT) ===

	{
		ID:               "MCP-TP-2056-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/config/agents.yaml", "content": "agents:\n  - role: researcher"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-agent-role-def-write",
		Description:      "Write to agents.yaml — CrewAI agent role definitions",
	},
	{
		ID:               "MCP-TP-2056-007",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/crewai-project/tasks.yaml", "content": "tasks:\n  - description: research task"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-agent-role-def-write",
		Description:      "Write to tasks.yaml — CrewAI task definitions",
	},

	// === TPs: agent framework project directories (AUDIT) ===

	{
		ID:               "MCP-TP-2056-008",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.langgraph/config.json", "content": "{\"version\": 1}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-workflow-def-write",
		Description:      "Write inside .langgraph/ hidden directory — LangGraph project state",
	},
	{
		ID:               "MCP-TP-2056-009",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/crews/research_crew.yaml", "content": "crew: research"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-workflow-def-write",
		Description:      "Write to crews/<name>.yaml — agent crew definition in crews/ directory",
	},

	// === TNs: reads and unrelated writes should not trigger block rules ===

	{
		ID:               "MCP-TN-2056-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/langgraph.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Read (not write) of langgraph.json — must not BLOCK",
	},
	{
		ID:               "MCP-TN-2056-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/docs/README.md", "content": "# LangGraph Project\n\nThis project uses LangGraph."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to README.md mentioning LangGraph — must not BLOCK",
	},
	{
		ID:               "MCP-TN-2056-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/my-langgraph-notes.txt", "content": "Notes about our setup."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-orchestration-config-write",
		Description:      "Write to notes.txt with langgraph in name — must not BLOCK",
	},
	{
		ID:               "MCP-TN-2056-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/project/config/agents.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-agent-role-def-write",
		Description:      "Read (not write) of agents.yaml — must not trigger write AUDIT rule",
	},
	{
		ID:               "MCP-TN-2056-005",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.langgraph/config.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-workflow-def-write",
		Description:      "Read (not write) inside .langgraph/ — must not trigger write AUDIT rule",
	},
	{
		ID:               "MCP-TN-2056-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/src/agents/agent_runner.py", "content": "def run(): pass"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-workflow-def-write",
		Description:      "Write to agents/ Python source file (not YAML) — must not AUDIT as orchestration write",
	},
}
