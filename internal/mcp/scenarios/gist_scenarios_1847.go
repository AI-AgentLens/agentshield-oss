// Hand-curated MCP test scenarios for issue #1847:
// GitHub Gist public creation via MCP — data exfil via public code sharing.
//
// Rules covered:
//   mcp-response-integrity-block-public-gist-public-arg    (BLOCK public=true)
//   mcp-response-integrity-block-public-gist-visibility-arg (BLOCK visibility=public)
//   mcp-response-integrity-audit-gist-write                 (AUDIT catch-all)

package scenarios

var GistScenarios1847 = []Scenario{
	// TP: public=true → BLOCK
	{
		ID:               "MCP-TP-1847-001",
		ToolName:         "create_gist",
		Arguments:        map[string]interface{}{"public": "true", "description": "sharing workspace code"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "create_gist with public=true — irreversible public publication under user's GitHub identity",
	},
	{
		ID:               "MCP-TP-1847-002",
		ToolName:         "github_create_gist",
		Arguments:        map[string]interface{}{"public": "true", "description": "backup"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "github_create_gist with public=true — exfil via public gist",
	},
	{
		ID:               "MCP-TP-1847-003",
		ToolName:         "create_gist",
		Arguments:        map[string]interface{}{"visibility": "public", "description": "shared code"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "create_gist with visibility=public — public gist creation should be blocked",
	},
	{
		ID:               "MCP-TP-1847-004",
		ToolName:         "update_gist",
		Arguments:        map[string]interface{}{"gist_id": "abc123", "visibility": "public"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "update_gist changing visibility to public — retroactive public exposure should be blocked",
	},
	// TP: no public flag → AUDIT (not ALLOW, not BLOCK)
	{
		ID:               "MCP-TP-1847-005",
		ToolName:         "create_gist",
		Arguments:        map[string]interface{}{"description": "code snippet"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "create_gist with no visibility flag — catch-all AUDIT for any gist write",
	},
	{
		ID:               "MCP-TP-1847-006",
		ToolName:         "github_create_gist",
		Arguments:        map[string]interface{}{"description": "notes"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "github_create_gist with no visibility — catch-all AUDIT",
	},
	{
		ID:               "MCP-TP-1847-007",
		ToolName:         "create_or_update_gist",
		Arguments:        map[string]interface{}{"public": "false", "description": "private"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "gist-public-exfil",
		Description:      "create_or_update_gist with public=false — AUDIT (not BLOCK), gist still needs review",
	},
	// TN: read-only gist operations → AUDIT/ALLOW (no gist write rule fires)
	{
		ID:               "MCP-TN-1847-001",
		ToolName:         "list_gists",
		Arguments:        map[string]interface{}{"username": "octocat"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "gist-public-exfil",
		Description:      "list_gists is a read-only operation — should not trigger gist write rules",
	},
	{
		ID:               "MCP-TN-1847-002",
		ToolName:         "get_gist",
		Arguments:        map[string]interface{}{"gist_id": "abc123def456"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "gist-public-exfil",
		Description:      "get_gist is a read-only operation — should not trigger gist write rules",
	},
	{
		ID:               "MCP-TN-1847-003",
		ToolName:         "delete_gist",
		Arguments:        map[string]interface{}{"gist_id": "def456789abc"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "gist-public-exfil",
		Description:      "delete_gist is a delete operation — should not trigger gist write rules",
	},
	{
		ID:               "MCP-TN-1847-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/gist-helper.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "gist-public-exfil",
		Description:      "read_file for gist documentation — unrelated to gist write, should not trigger",
	},
}
