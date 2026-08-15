// MCP test scenarios for package-manager registry redirect protection (issue #1664).
//
// Rules covered: mcp-sc-block-npmrc-write, mcp-sc-block-pip-conf-write,
// mcp-sc-block-pip-ini-write, mcp-sc-block-gemrc-write,
// mcp-sc-block-cargo-config-write, mcp-sc-block-yarnrc-yml-write,
// mcp-sc-block-bundle-config-write.
//
// All rules live in packs/premium/mcp/mcp-package-registry-redirect.yaml.
// Taxonomy: supply-chain/dependency-confusion/registry-redirect
//
// NOTE (issue #1897 — Phase 4 review): npm and pip rules downgraded from BLOCK to AUDIT
// because legitimate enterprise registry setup (Verdaccio, Artifactory, GitHub Packages,
// AWS CodeArtifact) is indistinguishable from attacker redirect at the glob level.
// TP scenarios for these rules expect AUDIT (rule fires but does not block).
// gemrc / cargo / yarnrc / bundler rules remain at BLOCK pending review.
package scenarios

// PkgRegistryRedirectScenarios1664 are MCP test scenarios for registry redirect protection.
var PkgRegistryRedirectScenarios1664 = []Scenario{
	// === True Positives: writes to package-manager registry configs ===

	// npm (.npmrc) — rule now AUDIT (issue #1897: enterprise scoped-registry FP)
	{
		ID:               "MCP-TP-1664-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.npmrc", "content": "registry=https://evil.com"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.npmrc with malicious registry — must be flagged (AUDIT) by mcp-sc-block-npmrc-write",
	},
	{
		ID:               "MCP-TP-1664-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/root/.npmrc"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "create_file to /root/.npmrc — must be flagged (AUDIT)",
	},
	{
		ID:               "MCP-TP-1664-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/home/developer/.npmrc"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "str_replace_editor to ~/.npmrc — BLOCK (community mcp-sec-block-package-manager-creds covers str_replace_editor as a hybrid read/edit tool that exposes auth tokens)",
	},
	{
		ID:               "MCP-TP-1664-004",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.npmrc", "content": "@company:registry=https://evil.com/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "append_file to ~/.npmrc adding scoped registry redirect — must be flagged (AUDIT)",
	},

	// pip.conf — still BLOCK from the generated community rule mcp-gen-protected-path-pip
	// which covers **/.pip/** and **/.config/pip/** (auto-generated from shell rules).
	// The premium mcp-sc-block-pip-conf-write is now AUDIT, but the generated community rule
	// takes precedence (BLOCK > AUDIT = most_restrictive_wins). Fixing pip.conf writes
	// to AUDIT requires modifying the generated community rule — tracked as follow-up.
	{
		ID:               "MCP-TP-1664-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.pip/pip.conf", "content": "[global]\nindex-url = https://evil.com/simple/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.pip/pip.conf — BLOCK from generated community rule mcp-gen-protected-path-pip (**/.pip/**)",
	},
	{
		ID:               "MCP-TP-1664-006",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.config/pip/pip.conf"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "edit_file to XDG pip.conf — BLOCK from generated community rule mcp-gen-protected-path-config-pip (**/.config/pip/**)",
	},
	{
		ID:               "MCP-TP-1664-007",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/Users/dev/AppData/Roaming/pip/pip.ini", "content": "[global]\nindex-url = https://evil.com/simple/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to pip.ini (Windows AppData path) — must be flagged (AUDIT) by mcp-sc-block-pip-ini-write (generated rule doesn't cover Windows pip.ini path)",
	},

	// gem (.gemrc)
	{
		ID:               "MCP-TP-1664-008",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.gemrc", "content": ":sources:\n- https://evil.com/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.gemrc with malicious gem source — must be blocked",
	},
	{
		ID:               "MCP-TP-1664-009",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/root/.gemrc"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "str_replace_editor to /root/.gemrc — must be blocked",
	},

	// cargo (.cargo/config.toml)
	{
		ID:               "MCP-TP-1664-010",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.cargo/config.toml", "content": "[source.crates-io]\nreplace-with = 'evil'"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.cargo/config.toml with crates-io redirect — must be blocked",
	},
	{
		ID:               "MCP-TP-1664-011",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/home/developer/.cargo/config.toml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "create_file to ~/.cargo/config.toml — must be blocked",
	},

	// yarn (.yarnrc.yml)
	{
		ID:               "MCP-TP-1664-012",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.yarnrc.yml", "content": "npmRegistryServer: https://evil.com"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.yarnrc.yml with malicious registry server — must be blocked",
	},
	{
		ID:               "MCP-TP-1664-013",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.yarnrc.yml"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "edit_file to ~/.yarnrc.yml — must be blocked",
	},

	// bundler (.bundle/config)
	{
		ID:               "MCP-TP-1664-014",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.bundle/config", "content": "BUNDLE_MIRROR__HTTPS__RUBYGEMS__ORG: https://evil.com"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.bundle/config with mirror redirect — must be blocked",
	},
	{
		ID:               "MCP-TP-1664-015",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.bundle/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "create_file to ~/.bundle/config — must be blocked",
	},
	{
		ID:               "MCP-TP-1664-016",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/root/.bundle/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/registry-redirect",
		Description:      "str_replace_editor to /root/.bundle/config — must be blocked",
	},

	// === True Negatives: reads and non-config file writes ===

	// Writes to unrelated config files (not registry configs)
	{
		ID:               "MCP-TN-1664-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.eslintrc.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to .eslintrc.json — project linter config, must NOT be blocked by registry redirect rules",
	},
	{
		ID:               "MCP-TN-1664-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/pyproject.toml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to pyproject.toml — project build config (not pip.conf), must NOT be blocked",
	},

	// Writes to non-config package files
	{
		ID:               "MCP-TN-1664-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/package.json", "content": "{\"name\": \"app\"}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to package.json — normal project file, must NOT be blocked",
	},
	{
		ID:               "MCP-TN-1664-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/requirements.txt", "content": "requests==2.28.0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to requirements.txt — normal project file, must NOT be blocked",
	},
	{
		ID:               "MCP-TN-1664-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/Cargo.toml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to Cargo.toml — normal project manifest, must NOT be blocked",
	},

	// Template/example config files
	{
		ID:               "MCP-TN-1664-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/.npmrc.example"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to .npmrc.example — template file, not actual config, must NOT be blocked",
	},

	// Documentation files
	{
		ID:               "MCP-TN-1664-007",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/npmrc-configuration-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to docs about npmrc configuration — documentation, must NOT be blocked",
	},

	// Gemfile (not gemrc)
	{
		ID:               "MCP-TN-1664-008",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/Gemfile"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to Gemfile — normal project dependency manifest, must NOT be blocked",
	},

	// Enterprise npm registry setup — key regression test for issue #1897.
	// write_file to ~/.npmrc now correctly returns AUDIT (not BLOCK): the premium
	// mcp-sc-block-npmrc-write rule is AUDIT, and the community read-only rule
	// (mcp-sec-block-package-manager-creds) does not include write_file in its tool list.
	// Content uses only the registry URL line (no auth token) to avoid content-scanner interference.
	{
		ID:               "MCP-TN-1664-009",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.npmrc", "content": "@mycompany:registry=https://npm.internal.mycompany.com/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/registry-redirect",
		Description:      "write_file to ~/.npmrc with enterprise scoped registry URL — must NOT be BLOCKED (AUDIT only, issue #1897 regression test)",
	},
	// NOTE: pip.conf write_file is still BLOCK from the generated community rule
	// mcp-gen-protected-path-pip (**/.pip/**). Fixing this requires modifying the
	// generated community pack — tracked as a follow-up to issue #1897.
}
