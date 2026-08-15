package scenarios

// AI Agent Framework Supply Chain Compromise scenarios (issue #2217)
// Rule: mcp-sc-audit-ai-framework-requirements-write
// Taxonomy: supply-chain/package-install/ai-agent-framework-compromise
//
// Detects MCP write tool calls that add AI orchestration framework packages
// (LangChain, LlamaIndex, AutoGen, CrewAI, Haystack, Semantic Kernel) to
// dependency manifests without hash verification.

var AIFrameworkScenarios2217 = []Scenario{
	// True Positives — write to requirements file with AI framework in content
	{
		ID:               "MCP-TP-2217-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/requirements.txt", "content": "langchain==0.3.7\nrequests==2.31.0\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to requirements.txt with langchain — must AUDIT (mcp-sc-audit-ai-framework-requirements-write)",
	},
	{
		ID:               "MCP-TP-2217-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/requirements-dev.txt", "content": "langchain-core>=0.3.0\npytest\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] create_file to requirements-dev.txt with langchain-core — must AUDIT",
	},
	{
		ID:               "MCP-TP-2217-003",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/app/pyproject.toml", "content": "[project]\ndependencies = [\"llama-index>=0.10.0\", \"fastapi\"]\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] edit_file to pyproject.toml with llama-index — must AUDIT",
	},
	{
		ID:               "MCP-TP-2217-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/requirements/prod.txt", "content": "crewai==0.28.0\ncelery\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to requirements/prod.txt with crewai — must AUDIT",
	},
	{
		ID:               "MCP-TP-2217-005",
		ToolName:         "create_or_update_file",
		Arguments:        map[string]interface{}{"path": "requirements.txt", "content": "autogen-agentchat==0.2.0\nboto3\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] create_or_update_file requirements.txt with autogen-agentchat — must AUDIT",
	},
	{
		ID:               "MCP-TP-2217-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/Pipfile", "content": "[[packages]]\nhaystack-ai = \"*\"\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to Pipfile with haystack-ai — must AUDIT",
	},
	{
		ID:               "MCP-TP-2217-007",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/project/requirements.txt", "content": "semantic-kernel==1.0.0\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain",
		Description:      "[AI framework] append_file to requirements.txt with semantic-kernel — must AUDIT",
	},

	// True Negatives — safe writes that must NOT trigger the rule
	{
		ID:               "MCP-TN-2217-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/requirements.txt", "content": "requests==2.31.0\nnumpy==1.26.0\nfastapi==0.110.0\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to requirements.txt with only non-framework packages — must NOT trigger AI framework rule",
	},
	{
		ID:               "MCP-TN-2217-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/src/main.py", "content": "import langchain\n# using langchain for agent logic\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to Python source file (not a manifest) mentioning langchain — path doesn't match manifest glob, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2217-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/project/requirements.txt"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "[AI framework] read_file of requirements.txt — read-only, not a write tool, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2217-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/langchain-setup.md", "content": "# LangChain Setup Guide\n\nInstall with: `pip install langchain`\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain",
		Description:      "[AI framework] write_file to docs .md (not a manifest) mentioning langchain — path doesn't match manifest glob, must NOT trigger",
	},
}
