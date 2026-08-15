// Hand-curated MCP test scenarios for file:// URI credential path bypass.
// Issue #1780.
//
// Rules tested:
//   mcp-agentic-block-file-uri-credential-access — file:// URI in 'uri' arg pointing to creds (BLOCK)
//
// Attack vector:
//   Tools like read_resource, resources/read, fetch_resource use 'uri' as the
//   argument name instead of 'path'. The community mcp-struct-block-credential-path-access
//   rule only checks 'path'. This gap allows file:// URIs to credential files to pass
//   undetected.

package scenarios

// CredentialURIScenarios1780 covers file:// URI credential path bypass.
var CredentialURIScenarios1780 = []Scenario{

	// ── TP: file:// URI to credential paths via read_resource / resources/read ────

	{
		ID:               "MCP-TP-1780-001",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with file:// URI to .aws/credentials — credential bypass via uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1780-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.ssh/id_rsa"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "resources/read with file:// URI to .ssh/id_rsa — SSH private key via uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1780-003",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "file:///etc/shadow"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "fetch_resource with file:// URI to /etc/shadow — system credential file, must BLOCK",
	},
	{
		ID:               "MCP-TP-1780-004",
		ToolName:         "get_resource",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.gnupg/secring.gpg"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "get_resource with file:// URI to .gnupg secret ring — GPG key via uri arg, must BLOCK",
	},
	{
		ID:               "MCP-TP-1780-005",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.kube/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with file:// URI to .kube/config — Kubernetes credentials, must BLOCK",
	},

	// ── TN: benign file:// workspace URIs — must not trigger the rule ─────────

	{
		ID:               "MCP-TN-1780-001",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with file:// URI to workspace README — benign, must not block",
	},
	{
		ID:               "MCP-TN-1780-002",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/src/main.go"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "resources/read with file:// URI to workspace source file — benign, must not block",
	},
	{
		ID:               "MCP-TN-1780-003",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "https://api.example.com/resource"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with https:// URI — non-file scheme, must not trigger file credential rule",
	},
	{
		ID:               "MCP-TN-1780-004",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "resources://memory/session/abc123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with resources:// URI — MCP memory resource, must not block",
	},

	// ── TP: GitHub Copilot credential bypass via file:// URI (issue #2147) ────

	{
		ID:               "MCP-TP-1780-006",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.config/github-copilot/hosts.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "resources/read with file:// URI to github-copilot hosts.json — OAuth token exfil via uri arg bypass, must BLOCK",
	},
	{
		ID:               "MCP-TP-1780-007",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "file:///home/user/.config/github-copilot-chat/token.json"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with file:// URI to github-copilot-chat token — OAuth token exfil via uri arg bypass, must BLOCK",
	},

	// ── TN: GitHub Copilot documentation file in workspace — must not block ──

	{
		ID:               "MCP-TN-1780-005",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/docs/github-copilot-setup.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-block-file-uri-credential-access",
		Description:      "read_resource with file:// URI to workspace doc containing 'github-copilot' in path — must not block",
	},
}
