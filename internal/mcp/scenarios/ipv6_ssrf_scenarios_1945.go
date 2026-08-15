// Hand-curated MCP test scenarios for IPv6 SSRF via 'uri' argument.
// Issue #1945.
//
// Rules tested:
//   mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal — IPv6 link-local + IPv6-mapped loopback/IMDS (BLOCK)
//   mcp-agentic-audit-resource-uri-ssrf-ipv6-ula       — IPv6 ULA + IPv6-mapped private IPv4 (AUDIT)
//
// Attack vector:
//   A malicious MCP server registers resources/read or custom resource-access URIs
//   that use IPv6 link-local (fe80::/10) or ULA (fc00::/7) addresses — the IPv6
//   equivalents of the already-blocked IMDS and RFC 1918 ranges. IPv6-mapped IPv4
//   notation (::ffff:10.x) also bypasses IPv4-only SSRF filters.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf

package scenarios

// IPv6SSRFScenarios1945 covers IPv6 SSRF via 'uri' argument.
var IPv6SSRFScenarios1945 = []Scenario{

	// ── TP: BLOCK — IPv6 link-local (fe80::/10) ────────────────────────────────

	{
		ID:               "MCP-TP-1945-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://[fe80::1%25eth0]:8080/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "resources/read with IPv6 link-local URI (fe80::/10) — probes adjacent hosts, must BLOCK",
	},
	{
		ID:               "MCP-TP-1945-002",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[fe80::dead:beef]/internal-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "read_resource with link-local fe80:: URI — same-segment host probing, must BLOCK",
	},
	{
		ID:               "MCP-TP-1945-003",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "https://[fe80::1]/health-feed"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "fetch_resource with HTTPS link-local IPv6 — must BLOCK",
	},

	// ── TP: BLOCK — IPv6-mapped loopback (::ffff:127.x) ───────────────────────

	{
		ID:               "MCP-TP-1945-004",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:127.0.0.1]/local-service"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "IPv6-mapped loopback ::ffff:127.0.0.1 — maps to 127.0.0.1, bypasses IPv4 localhost rule, must BLOCK",
	},
	{
		ID:               "MCP-TP-1945-005",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:127.0.0.2]:9200/_cat/indices"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "IPv6-mapped loopback ::ffff:127.0.0.2 targeting Elasticsearch port — must BLOCK",
	},

	// ── TP: BLOCK — IPv6-mapped link-local/IMDS (::ffff:169.254.x) ────────────

	{
		ID:               "MCP-TP-1945-006",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:169.254.169.254]/latest/meta-data/iam/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "IPv6-mapped AWS IMDS ::ffff:169.254.169.254 — IMDS credential theft via IPv6 mapping, must BLOCK",
	},
	{
		ID:               "MCP-TP-1945-007",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:169.254.1.1]/metadata"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "IPv6-mapped link-local 169.254.x.x — link-local address family, must BLOCK",
	},

	// ── TP: AUDIT — IPv6 ULA (fc00::/7) ───────────────────────────────────────

	{
		ID:               "MCP-TP-1945-008",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://[fd00::1]:9200/_cat/indices"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "resources/read with IPv6 ULA fd00:: (private range) — must AUDIT",
	},
	{
		ID:               "MCP-TP-1945-009",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[fc00::dead:beef]/internal-service"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "read_resource with IPv6 ULA fc00:: — must AUDIT",
	},
	{
		ID:               "MCP-TP-1945-010",
		ToolName:         "resources/subscribe",
		Arguments:        map[string]interface{}{"uri": "http://[fd12:3456:789a::1]/health"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "resources/subscribe with IPv6 ULA fd12:: — must AUDIT",
	},

	// ── TP: AUDIT — IPv6-mapped private IPv4 ──────────────────────────────────

	{
		ID:               "MCP-TP-1945-011",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:10.0.0.5]:8080/admin/config"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "IPv6-mapped 10.x private IPv4 ::ffff:10.x — must AUDIT (mirrors IPv4 private-net rule)",
	},
	{
		ID:               "MCP-TP-1945-012",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:192.168.1.100]/api"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "IPv6-mapped 192.168.x private IPv4 — must AUDIT",
	},
	{
		ID:               "MCP-TP-1945-013",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:172.16.0.2]/internal"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "IPv6-mapped 172.16.x private IPv4 — must AUDIT",
	},

	// ── TN: public IPv6 and non-IPv6 URIs should NOT trigger ──────────────────

	{
		ID:               "MCP-TN-1945-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "Workspace file:// URI — benign project file access, must not trigger IPv6 SSRF rules",
	},
	{
		ID:               "MCP-TN-1945-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "Public HTTPS API URI — must not trigger IPv6 SSRF rules",
	},
	{
		ID:               "MCP-TN-1945-003",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[2001:db8::1]/public-api"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "Public IPv6 documentation range 2001:db8:: — not ULA/link-local, must not trigger",
	},
	{
		ID:               "MCP-TN-1945-004",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://[2606:4700::6810:f8f8]/v1/data"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-resource-uri-ssrf-ipv6-linklocal",
		Description:      "Cloudflare public IPv6 — not ULA or link-local, must not trigger",
	},
	{
		ID:               "MCP-TN-1945-005",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://[::ffff:93.184.216.34]/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "IPv6-mapped public IP 93.184.216.34 (example.com) — not private range, must not trigger IPv6-ULA AUDIT rule",
	},
	{
		ID:               "MCP-TN-1945-006",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://internal.mycompany.com/docs"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-ipv6-ula",
		Description:      "Internal hostname (not raw IP) — DNS-based, not an IPv6 literal, must not trigger",
	},
}
