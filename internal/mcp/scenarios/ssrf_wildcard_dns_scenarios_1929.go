// Hand-curated MCP test scenarios for SSRF via wildcard DNS services.
// Issue #1929.
//
// Rules tested:
//   mcp-agentic-block-ssrf-wildcard-dns-url — wildcard DNS in 'url' arg (BLOCK)
//   mcp-agentic-block-ssrf-wildcard-dns-uri — wildcard DNS in 'uri' arg (BLOCK)
//
// Attack vector:
//   An agent uses wildcard DNS services (nip.io, sslip.io, xip.io) or
//   always-localhost services (localtest.me, vcap.me) to embed private IP
//   addresses in domain names, bypassing IP-based SSRF filters in the
//   community mcp-struct-block-ssrf-* rules.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-local-server-dns-rebinding

package scenarios

// SSRFWildcardDNSScenarios1929 covers MCP SSRF via wildcard DNS bypass.
var SSRFWildcardDNSScenarios1929 = []Scenario{

	// ── TP: wildcard DNS in 'url' argument (BLOCK) ─────────────────────────────

	{
		ID:               "MCP-TP-1929-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://10.0.0.1.nip.io/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request with 10.x.x.x.nip.io URL — RFC 1918 private IP via wildcard DNS, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "http://192.168.1.100.nip.io/internal-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "fetch_url with 192.168.x.x.nip.io URL — private IP via wildcard DNS, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-003",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "http://169.254.169.254.nip.io/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "make_request with AWS IMDS via nip.io — IMDS SSRF bypass, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://10-0-0-1.nip.io/api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request with hyphen-notation nip.io URL — 10-x-x-x.nip.io bypass, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-005",
		ToolName:         "navigate",
		Arguments:        map[string]interface{}{"url": "http://192-168-1-1.sslip.io/login"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "browser navigate with hyphen sslip.io URL — 192-168-x-x.sslip.io bypass, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-006",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://127.0.0.1.nip.io/internal"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request with loopback via nip.io — 127.x.x.x.nip.io bypass, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-007",
		ToolName:         "navigate",
		Arguments:        map[string]interface{}{"url": "http://localhost.localtest.me/api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "browser navigate to localtest.me — always resolves to 127.0.0.1, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-008",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://internal.vcap.me/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request to vcap.me — always resolves to 127.0.0.1, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-009",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://100.100.100.200.nip.io/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request with Alibaba IMDS (CGNAT range) via nip.io — 100.64/10 bypass, must BLOCK",
	},

	// ── TP: wildcard DNS in 'uri' argument (BLOCK) ─────────────────────────────

	{
		ID:               "MCP-TP-1929-010",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://10.0.0.1.nip.io/internal-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "resources/read with 10.x.x.x.nip.io URI — private IP via wildcard DNS in uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-011",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://192.168.1.100.sslip.io/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "read_resource with 192.168.x.x.sslip.io URI — private IP via wildcard DNS in uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-012",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "http://169.254.169.254.nip.io/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "fetch_resource with IMDS via nip.io URI — IMDS SSRF bypass in uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1929-013",
		ToolName:         "resources/subscribe",
		Arguments:        map[string]interface{}{"uri": "http://127.0.0.1.nip.io/health-data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "resources/subscribe with loopback via nip.io URI — 127.x.x.x bypass in uri arg, must BLOCK",
	},

	// ── TN: legitimate URLs and bare DNS service domains ──────────────────────
	// Note: MCP default decision is AUDIT; these TNs verify the new rules
	// do NOT fire on public URLs or non-matching domain patterns.

	{
		ID:               "MCP-TN-1929-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request to public GitHub API — no wildcard DNS, wildcard-dns rules must not trigger",
	},
	{
		ID:               "MCP-TN-1929-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "http://nip.io/about"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "fetch_url to nip.io homepage (no embedded IP) — bare DNS service domain, must not trigger",
	},
	{
		ID:               "MCP-TN-1929-003",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://10.0.0.1.example.com/api"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-url",
		Description:      "http_request to 10.0.0.1.example.com (not a wildcard DNS service) — must not trigger",
	},
	{
		ID:               "MCP-TN-1929-004",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "resources/read with file:// URI to workspace — no wildcard DNS, must not trigger",
	},
	{
		ID:               "MCP-TN-1929-005",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-wildcard-dns-uri",
		Description:      "resources/read with public HTTPS URI — no wildcard DNS, must not trigger",
	},
}
