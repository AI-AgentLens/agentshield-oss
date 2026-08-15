// Hand-curated MCP test scenarios for LSP workspace configuration file write
// detection (LSP prompt injection via config poisoning). Issue #2304.
//
// Rules tested:
//   mcp-audit-lsp-workspace-config-write  — pyrightconfig.json, .pylsp.toml,
//                                           .clangd, rust-analyzer.toml (AUDIT)

package scenarios

// LSPWorkspaceConfigScenarios2304 covers LSP workspace config file write detection.
var LSPWorkspaceConfigScenarios2304 = []Scenario{

	// ── mcp-audit-lsp-workspace-config-write — TP (pyrightconfig.json) ───────

	{
		ID:               "MCP-TP-2304-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/pyrightconfig.json", "content": "{\"plugins\":[{\"path\":\"/tmp/evil\"}],\"pythonVersion\":\"3.11\"}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "write_file to pyrightconfig.json with malicious plugin path — must AUDIT",
	},
	{
		ID:               "MCP-TP-2304-002",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/home/dev/myapp/pyrightconfig.json", "content": "{\"pythonVersion\":\"3.10\",\"extraPaths\":[\"/tmp/attacker-stubs\"]}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "edit_file to pyrightconfig.json with attacker extraPaths — must AUDIT",
	},

	// ── mcp-audit-lsp-workspace-config-write — TP (.pylsp.toml) ─────────────

	{
		ID:               "MCP-TP-2304-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/dev/myapp/.pylsp.toml", "content": "[pylsp.plugins.evil]\nenabled = true\npath = \"/tmp/malicious\""},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "write_file to .pylsp.toml loading malicious plugin — must AUDIT",
	},

	// ── mcp-audit-lsp-workspace-config-write — TP (.clangd) ─────────────────

	{
		ID:               "MCP-TP-2304-004",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/project/.clangd", "new_str": "CompileFlags:\n  Add: [-I/tmp/evil-headers]"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "str_replace_editor to .clangd with evil include path injection — must AUDIT",
	},

	// ── mcp-audit-lsp-workspace-config-write — TP (rust-analyzer.toml) ──────

	{
		ID:               "MCP-TP-2304-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/repo/rust-analyzer.toml", "content": "[cargo]\nextraEnv = {\"RUSTC_WRAPPER\" = \"/tmp/evil\"}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "write_file to rust-analyzer.toml with malicious RUSTC_WRAPPER env — must AUDIT",
	},
	{
		ID:               "MCP-TP-2304-006",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/workspace/app/pyrightconfig.json", "content": ",\"extraPaths\":[\"/tmp/attacker-stubs\"]"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "append_file to pyrightconfig.json injecting extraPaths — must AUDIT",
	},

	// ── mcp-audit-lsp-workspace-config-write — TN (read, not write) ─────────

	{
		ID:               "MCP-TN-2304-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/pyrightconfig.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "read_file on pyrightconfig.json — read-only access, no write; must NOT trigger",
	},

	// ── mcp-audit-lsp-workspace-config-write — TN (docs file mentioning config name) ─

	{
		ID:               "MCP-TN-2304-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/docs/pyrightconfig-reference.md", "content": "# pyrightconfig.json reference guide\n\nThis file configures Pyright type checking."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "write_file to a documentation markdown file (name contains pyrightconfig) — must NOT trigger; path does not match **/pyrightconfig.json glob",
	},

	// ── mcp-audit-lsp-workspace-config-write — TN (unrelated write) ─────────

	{
		ID:               "MCP-TN-2304-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/src/main.py", "content": "# main module\nprint('hello')"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-lsp-workspace-config-write",
		Description:      "write_file to a normal Python source file — unrelated to LSP config; must NOT trigger",
	},
}
