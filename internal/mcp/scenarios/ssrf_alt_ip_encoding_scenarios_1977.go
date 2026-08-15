// Hand-curated MCP test scenarios for SSRF via alternative IP encoding.
// Issue #1977.
//
// Rules tested:
//   mcp-agentic-block-ssrf-alt-ip-encoding-url — hex/decimal/octal loopback+IMDS in 'url' arg (BLOCK)
//   mcp-agentic-block-ssrf-alt-ip-encoding-uri — hex/decimal/octal loopback+IMDS in 'uri' arg (BLOCK)
//
// Attack vector:
//   Classic SSRF filters check literal dotted-decimal IPs (127.0.0.1, 169.254.169.254)
//   and miss alternative representations. HTTP stacks (curl, Python requests, Go net/http)
//   resolve all of these identically:
//     Hex:     http://0x7f000001/   → 127.0.0.1
//     Decimal: http://2130706433/  → 127.0.0.1
//     Octal:   http://0177.0.0.1/  → 127.0.0.1
//     Hex:     http://0xa9fea9fe/  → 169.254.169.254 (AWS IMDS)
//     Decimal: http://2852039166/  → 169.254.169.254 (AWS IMDS)
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf

package scenarios

// AltIPEncodingSSRFScenarios1977 covers SSRF via alternative IP encoding in url/uri args.
var AltIPEncodingSSRFScenarios1977 = []Scenario{

	// ── TP: BLOCK — hex IP in 'url' argument ──────────────────────────────────

	{
		ID:               "MCP-TP-1977-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://0x7f000001/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "http_request with hex-encoded loopback (0x7f000001 = 127.0.0.1) in url — SSRF bypass must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "http://0xa9fea9fe/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "fetch_url with hex-encoded IMDS (0xa9fea9fe = 169.254.169.254) — cloud credential theft must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-003",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "http://2130706433/sensitive-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "make_request with decimal loopback (2130706433 = 127.0.0.1) — SSRF bypass must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-004",
		ToolName:         "fetch",
		Arguments:        map[string]interface{}{"url": "http://2852039166/latest/meta-data/iam/security-credentials/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "fetch with decimal IMDS (2852039166 = 169.254.169.254) — IAM credential theft must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-005",
		ToolName:         "navigate",
		Arguments:        map[string]interface{}{"url": "http://0177.0.0.1/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "navigate with octal loopback (0177.0.0.1 = 127.0.0.1) — SSRF bypass must BLOCK",
	},

	// ── TP: BLOCK — hex IP in 'uri' argument ──────────────────────────────────

	{
		ID:               "MCP-TP-1977-006",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://0x7f000001/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "resources/read with hex-encoded loopback in uri — SSRF bypass must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-007",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://2130706433/internal-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "read_resource with decimal loopback (2130706433) in uri — SSRF bypass must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-008",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "http://0177.0.0.1/etc/shadow"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "fetch_resource with octal loopback (0177.0.0.1) in uri — SSRF bypass must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-009",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://0xa9fea9fe/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "resources/read with hex IMDS (0xa9fea9fe) in uri — IAM credential exfil must BLOCK",
	},
	{
		ID:               "MCP-TP-1977-010",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://2852039166/latest/meta-data/iam/security-credentials/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "read_resource with decimal IMDS (2852039166) in uri — IAM credential exfil must BLOCK",
	},

	// ── TN: AUDIT — legitimate URLs that must NOT be blocked ──────────────────

	{
		ID:               "MCP-TN-1977-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "http_request to legitimate GitHub API — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-1977-002",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://192.168.1.1/api"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "http_request to literal private IP (already AUDIT'd by private-net rule) — alt-encoding rule must NOT double-block",
	},
	{
		ID:               "MCP-TN-1977-003",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://example.com/path?ref=0x7f000001"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-url",
		Description:      "http_request where hex IP is in query param (not host) — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-1977-004",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "resources/read of workspace file — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-1977-005",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "https://api.example.com/data/2130706433"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-uri",
		Description:      "read_resource where decimal IP appears in URL path (not host) — must NOT be blocked",
	},
}
