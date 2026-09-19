// Hand-curated MCP test scenarios for the Go-based alt-form IPv4 SSRF check.
// Issue #3675.
//
// Rule tested (Go-native, not YAML):
//   mcp-agentic-block-ssrf-alt-ip-encoding-structural — decoder-based check in
//   internal/mcp/toolcall_altform_ssrf.go, wired into PolicyEvaluator.evaluate
//   (internal/mcp/policy.go).
//
// Attack vector:
//   The sibling YAML rules mcp-agentic-block-ssrf-alt-ip-encoding-url/-uri
//   (see ssrf_alt_ip_encoding_scenarios_1977.go) enumerate hex/decimal/octal
//   IP forms as literal regex alternatives, and their reason text claims
//   octal-encoded AWS IMDS coverage that the regex does not actually
//   implement: the octal alternation only matches the loopback literal
//   "0177.", never the IMDS octet spelling. This check decodes the host
//   generically (ipv4FromAltForm) and classifies the canonical result against
//   the same private/loopback/link-local/IMDS range tables the resources/list
//   authority scanner uses, so any alt-form encoding of any address in those
//   ranges is caught — not just the two the YAML rule authors enumerated.
//
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-resource-uri-ssrf

package scenarios

// AltIPEncodingSSRFStructuralScenarios3675 covers the decoder-based alt-form
// IPv4 SSRF check for tool-call url/uri/endpoint/target/server/base_url args.
var AltIPEncodingSSRFStructuralScenarios3675 = []Scenario{

	// ── TP: BLOCK — the reported gap: dotted-octal AWS IMDS ───────────────────

	{
		ID:               "MCP-TP-3675-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "http://0251.0376.0251.0376/latest/meta-data/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "http_request with dotted-octal AWS IMDS (0251.0376.0251.0376 = 169.254.169.254) in url — the exact gap reported in #3675; the sibling YAML rule's octal alternation only covers the loopback literal, not this — must BLOCK",
	},
	{
		ID:               "MCP-TP-3675-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "resources/read with dotted-octal AWS IMDS in uri — IAM credential exfil must BLOCK",
	},

	// ── TP: BLOCK — the broader class the enumeration never reaches ───────────

	{
		ID:               "MCP-TP-3675-003",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"endpoint": "http://0251.0376.0251.02/v2/credentials/task"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "fetch_resource with dotted-octal ECS task-role IMDS (0251.0376.0251.02 = 169.254.169.2) in endpoint — never enumerated by the YAML rule at all — must BLOCK",
	},
	{
		ID:               "MCP-TP-3675-004",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"target": "http://0xa.0x0.0x0.0x1/internal"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "make_request with dotted-hex RFC 1918 host (0xa.0x0.0x0.0x1 = 10.0.0.1) in target — an ordinary private address the two-literal enumeration never covered — must BLOCK",
	},
	{
		ID:               "MCP-TP-3675-005",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"base_url": "http://0177.0000.0000.0001/admin"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "http_request with dotted-octal loopback (0177.0000.0000.0001 = 127.0.0.1) via 'base_url' — the sibling YAML rules only match args_match keys 'url'/'uri', so this arg name has no coverage at all outside this check — must BLOCK",
	},

	// ── TN: legitimate/public values that must NOT be blocked ─────────────────

	{
		ID:               "MCP-TN-3675-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/example/repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "http_request to legitimate GitHub API — must NOT be blocked",
	},
	{
		ID:               "MCP-TN-3675-002",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "https://docs.example.com/ssrf-guide?example=0251.0376.0251.0376"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "the octal-dotted IMDS string appears in a query-param VALUE, not the host — must NOT be blocked (guards against over-broad substring matching)",
	},
	{
		ID:               "MCP-TN-3675-003",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"target": "http://010.010.010.010/dns-query"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "dotted-octal encoding of a PUBLIC address (010.010.010.010 = 8.8.8.8) in 'target' — alt-form decoding must not itself be treated as adversarial; only the decoded RANGE matters — must NOT be blocked. Uses 'target' (not 'url'/'uri') to isolate this assertion to the new structural check: the sibling YAML rules' args_match only inspects 'url'/'uri' keys, and their hex line is separately over-broad on ANY '0x' host regardless of range (pre-existing, tracked in a follow-up, out of scope for #3675) — a public IP under 'url'/'uri' in hex form would still trip that unrelated rule and could not isolate this check.",
	},
	{
		ID:               "MCP-TN-3675-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/notes.md", "content": "see http://0251.0376.0251.0376/ for background on IMDS octal encoding"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-ssrf-alt-ip-encoding-structural",
		Description:      "octal IMDS string mentioned in file content, argument name 'content' is not in the recognized url/uri/endpoint/target/server/base_url set — must NOT be blocked",
	},
}
