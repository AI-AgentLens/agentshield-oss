// Curated MCP scenarios for issue #1547: named package registry publish tool calls.
// Tests mcp-sc-block-named-npm-publish-tool, mcp-sc-block-named-pypi-publish-tool,
// mcp-sc-block-named-cargo-publish-tool, and mcp-sc-block-named-gem-publish-tool
// in mcp-supply-chain.yaml.

package scenarios

// PkgPublishScenarios contains TP and TN test scenarios for named package
// registry publish MCP tool rules (issue #1547).
var PkgPublishScenarios = []Scenario{

	// ── mcp-sc-block-named-npm-publish-tool ──────────────────────────────────

	{
		ID:               "MCP-TP-1547-001",
		ToolName:         "publish_npm_package",
		Arguments:        map[string]interface{}{"name": "my-package", "version": "1.0.1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "publish_npm_package — must BLOCK (supply chain: unauthorized npm publish)",
	},
	{
		ID:               "MCP-TP-1547-002",
		ToolName:         "npm_publish",
		Arguments:        map[string]interface{}{"package": "react", "version": "19.0.1-evil"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "npm_publish — must BLOCK",
	},
	{
		ID:               "MCP-TP-1547-003",
		ToolName:         "publish_to_npm",
		Arguments:        map[string]interface{}{"name": "lodash", "tag": "latest"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "publish_to_npm — must BLOCK",
	},

	// ── mcp-sc-block-named-pypi-publish-tool ─────────────────────────────────

	{
		ID:               "MCP-TP-1547-004",
		ToolName:         "pypi_upload",
		Arguments:        map[string]interface{}{"package": "my-package", "dist": "./dist/my-package-1.0.0.tar.gz"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-pypi-publish-tool",
		Description:      "pypi_upload — must BLOCK (supply chain: unauthorized PyPI publish)",
	},
	{
		ID:               "MCP-TP-1547-005",
		ToolName:         "upload_to_pypi",
		Arguments:        map[string]interface{}{"wheel": "my_package-1.0.0-py3-none-any.whl"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-pypi-publish-tool",
		Description:      "upload_to_pypi — must BLOCK",
	},
	{
		ID:               "MCP-TP-1547-006",
		ToolName:         "twine_upload",
		Arguments:        map[string]interface{}{"dist_dir": "./dist/*"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-pypi-publish-tool",
		Description:      "twine_upload — must BLOCK",
	},

	// ── mcp-sc-block-named-cargo-publish-tool ────────────────────────────────

	{
		ID:               "MCP-TP-1547-007",
		ToolName:         "cargo_publish",
		Arguments:        map[string]interface{}{"package": "serde", "dry_run": false},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-cargo-publish-tool",
		Description:      "cargo_publish — must BLOCK (supply chain: unauthorized crates.io publish)",
	},
	{
		ID:               "MCP-TP-1547-008",
		ToolName:         "publish_crate",
		Arguments:        map[string]interface{}{"name": "tokio", "version": "1.99.0"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-cargo-publish-tool",
		Description:      "publish_crate — must BLOCK",
	},

	// ── mcp-sc-block-named-gem-publish-tool ──────────────────────────────────

	{
		ID:               "MCP-TP-1547-009",
		ToolName:         "gem_push",
		Arguments:        map[string]interface{}{"gem": "my-gem-1.0.0.gem"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-gem-publish-tool",
		Description:      "gem_push — must BLOCK (supply chain: unauthorized RubyGems publish)",
	},
	{
		ID:               "MCP-TP-1547-010",
		ToolName:         "publish_gem",
		Arguments:        map[string]interface{}{"name": "rails", "version": "8.0.1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-named-gem-publish-tool",
		Description:      "publish_gem — must BLOCK",
	},

	// ── True Negatives: benign npm/package tools ──────────────────────────────

	{
		ID:               "MCP-TN-1547-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/package.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "read_file on package.json — not a publish operation, must not BLOCK",
	},
	{
		ID:               "MCP-TN-1547-002",
		ToolName:         "npm_install",
		Arguments:        map[string]interface{}{"package": "lodash", "version": "4.17.21"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "npm_install — install (not publish), must not BLOCK",
	},
	{
		ID:               "MCP-TN-1547-003",
		ToolName:         "pip_install",
		Arguments:        map[string]interface{}{"package": "requests", "version": "2.31.0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-pypi-publish-tool",
		Description:      "pip_install — install (not publish), must not BLOCK",
	},
	{
		ID:               "MCP-TN-1547-004",
		ToolName:         "cargo_build",
		Arguments:        map[string]interface{}{"package": "my-crate"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-cargo-publish-tool",
		Description:      "cargo_build — build (not publish), must not BLOCK",
	},
	{
		ID:               "MCP-TN-1547-005",
		ToolName:         "gem_install",
		Arguments:        map[string]interface{}{"name": "bundler"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-gem-publish-tool",
		Description:      "gem_install — install (not publish), must not BLOCK",
	},
	{
		ID:               "MCP-TN-1547-006",
		ToolName:         "list_npm_packages",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-named-npm-publish-tool",
		Description:      "list_npm_packages — read-only query, must not BLOCK",
	},
}
