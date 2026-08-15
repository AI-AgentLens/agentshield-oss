// Hand-curated MCP test scenarios for mcp-sc-audit-ai-instruction-file-read.
// Issue #2115: Repository-embedded AI instruction poisoning.
//
// Attack: A malicious repository embeds override directives in per-project AI
// agent instruction files (.cursorrules, CLAUDE.md, etc.). When an MCP read
// tool returns these files to the agent, the injected content can silently
// alter agent behavior for the entire session.
//
// Rule covered:
//   mcp-sc-audit-ai-instruction-file-read  (AUDIT)

package scenarios

var AIInstructionReadScenarios2115 = []Scenario{

	// ── mcp-sc-audit-ai-instruction-file-read — TP ───────────────────────────

	{
		ID:               "MCP-TP-2115-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.cursorrules"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: .cursorrules — AI instruction file read must be audited (Cursor IDE poisoning vector)",
	},
	{
		ID:               "MCP-TP-2115-002",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/home/user/repo/.github/copilot-instructions.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "cat_file: .github/copilot-instructions.md — GitHub Copilot workspace instructions must be audited",
	},
	{
		ID:               "MCP-TP-2115-003",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/project/CLAUDE.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "get_file_contents: CLAUDE.md — Claude Code operator context file must be audited",
	},
	{
		ID:               "MCP-TP-2115-004",
		ToolName:         "view_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.windsurfrules"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "view_file: .windsurfrules — Windsurf IDE instruction file must be audited",
	},
	{
		ID:               "MCP-TP-2115-005",
		ToolName:         "open_file",
		Arguments:        map[string]interface{}{"path": "/repo/.aider.conf.yml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "open_file: .aider.conf.yml — Aider AI coder config must be audited",
	},
	{
		ID:               "MCP-TP-2115-006",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.claude/settings.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: .claude/settings.json — Claude config directory file must be audited",
	},
	{
		ID:               "MCP-TP-2115-007",
		ToolName:         "read",
		Arguments:        map[string]interface{}{"path": "/home/user/project/.clinerules"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read: .clinerules — Cline VS Code extension instruction file must be audited",
	},
	{
		ID:               "MCP-TP-2115-008",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/project/subdir/CLAUDE.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: nested CLAUDE.md — instruction poisoning can target subdirectory context files",
	},
	{
		ID:               "MCP-TP-2115-009",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/.github/instructions/python.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: .github/instructions fragment — GitHub Copilot per-file instruction must be audited",
	},

	// ── mcp-sc-audit-ai-instruction-file-read — TN ───────────────────────────
	//
	// TN cases use AUDIT as the expected decision because the MCP default policy
	// is AUDIT. The key assertion is that MY rule does not fire on these inputs;
	// if another rule or the MCP default produces AUDIT, that is correct behavior.
	// TN-003 uses BLOCK because the .cursorrules write is caught by the IDE
	// workspace trust rule — confirming that write_file is NOT in my tool_name_any.

	{
		ID:               "MCP-TN-2115-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: README.md — benign project documentation; rule must not fire (MCP default AUDIT is expected)",
	},
	{
		ID:               "MCP-TN-2115-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/cursorrules-reference.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: cursorrules-reference.md — contains word but not the dotfile name pattern; rule must not fire",
	},
	{
		ID:               "MCP-TN-2115-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/.cursorrules", "content": "# style rules"},
		ExpectedDecision: "BLOCK",
		Classification:   "TN",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "write_file: .cursorrules — write tool not in read-family; blocked by IDE workspace trust rule, not this rule",
	},
	{
		ID:               "MCP-TN-2115-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/src/main.go"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-ai-instruction-file-read",
		Description:      "read_file: main.go — ordinary source file; rule must not fire (MCP default AUDIT is expected)",
	},
}
