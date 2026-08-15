// Hand-curated MCP test scenarios for agentic attack vectors.
// Issue #1658.
//
// Rules tested:
//   mcp-agentic-audit-resource-uri-ssrf-private-net — private IP via uri arg (AUDIT)
//   mcp-agentic-block-resource-uri-ssrf-cgnat       — CGNAT via uri arg (BLOCK)
//   mcp-agentic-block-procfs-kcore-read             — /proc/kcore (BLOCK)
//   mcp-agentic-audit-procfs-kmsg-read              — /proc/kmsg (AUDIT)
//
// Attack vectors:
//   - SSRF: MCP resource URIs targeting private/CGNAT IP ranges probe internal services
//   - Resource exhaustion + credential dump: kernel pseudo-file reads via MCP file tools

package scenarios

// AgenticAttackScenarios1658 covers resource URI SSRF and procfs kernel access.
var AgenticAttackScenarios1658 = []Scenario{

	// ── TP: SSRF via uri argument — private network ranges (AUDIT) ────────────

	{
		ID:               "MCP-TP-1658-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://10.0.0.5:9200/_cat/indices"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/read with uri targeting 10.x.x.x — private network SSRF, must AUDIT",
	},
	{
		ID:               "MCP-TP-1658-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://192.168.1.100/admin/config"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/read with uri targeting 192.168.x.x — private network SSRF, must AUDIT",
	},
	{
		ID:               "MCP-TP-1658-003",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://172.16.0.2:8080/internal-api/secrets"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "read_resource with uri targeting 172.16.x.x — private network SSRF, must AUDIT",
	},
	{
		ID:               "MCP-TP-1658-004",
		ToolName:         "resources/subscribe",
		Arguments:        map[string]interface{}{"uri": "http://10.10.10.10/health-data"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/subscribe with uri targeting 10.10.x.x — private network SSRF via subscription, must AUDIT",
	},

	// ── TP: SSRF via uri argument — CGNAT range (BLOCK) ──────────────────────

	{
		ID:               "MCP-TP-1658-005",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://100.64.0.1/internal-api"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-cgnat",
		Description:      "resources/read with CGNAT uri (100.64.x.x) — BLOCK, no legitimate agent use",
	},
	{
		ID:               "MCP-TP-1658-006",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "http://100.127.255.1/metadata"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-resource-uri-ssrf-cgnat",
		Description:      "read_resource with CGNAT upper-range uri (100.127.x.x) — BLOCK",
	},

	// ── TP: /proc/kcore kernel memory dump via MCP file tools (BLOCK) ─────────

	{
		ID:               "MCP-TP-1658-007",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/proc/kcore"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-procfs-kcore-read",
		Description:      "read_file targeting /proc/kcore — dumps kernel physical memory (credentials + unbounded), must BLOCK",
	},
	{
		ID:               "MCP-TP-1658-008",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/proc/kcore"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-procfs-kcore-read",
		Description:      "cat_file targeting /proc/kcore — must BLOCK",
	},

	// ── TP: /proc/kmsg infinite kernel log stream (AUDIT) ─────────────────────

	{
		ID:               "MCP-TP-1658-009",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/proc/kmsg"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-procfs-kmsg-read",
		Description:      "read_file targeting /proc/kmsg — infinite kernel log stream, must AUDIT",
	},
	{
		ID:               "MCP-TP-1658-010",
		ToolName:         "view_file",
		Arguments:        map[string]interface{}{"path": "/proc/kmsg"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-procfs-kmsg-read",
		Description:      "view_file targeting /proc/kmsg — must AUDIT",
	},

	// ── TN: safe resource URIs — file:// and public HTTPS ─────────────────────

	{
		ID:               "MCP-TN-1658-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/read with file:// URI to workspace — safe, must not trigger SSRF rule",
	},
	{
		ID:               "MCP-TN-1658-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/read with public HTTPS URI — safe, must not trigger private IP SSRF rule",
	},
	{
		ID:               "MCP-TN-1658-003",
		ToolName:         "resources/subscribe",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/src/config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-resource-uri-ssrf-private-net",
		Description:      "resources/subscribe to workspace file — legitimate file monitoring, must not trigger SSRF rule",
	},

	// ── TN: safe proc files — benign /proc entries ────────────────────────────

	{
		ID:               "MCP-TN-1658-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/proc/cpuinfo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-procfs-kcore-read",
		Description:      "read_file targeting /proc/cpuinfo — bounded informational file, must not trigger kcore exhaustion rule",
	},
	{
		ID:               "MCP-TN-1658-005",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/proc/cmdline"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-procfs-kmsg-read",
		Description:      "read_file targeting /proc/cmdline — bounded kernel boot args, distinct from /proc/kmsg, must not trigger",
	},
	{
		ID:               "MCP-TN-1658-006",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/proc-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-procfs-kcore-read",
		Description:      "read_file for docs file mentioning proc in name — benign workspace file, must not trigger procfs rule",
	},
}
