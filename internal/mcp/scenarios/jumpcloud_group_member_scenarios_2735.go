// Hand-curated MCP test scenarios for JumpCloud system admin group member write via MCP.
// Issue #2735.
//
// Rules tested:
//   mcp-privesc-block-jumpcloud-group-member-write-api — JumpCloud /usergroups/{id}/members write (BLOCK)
//
// Gap: JumpCloud admin group member write via console.jumpcloud.com was not covered
// by the Okta/Auth0/Entra rules in PR #2734. A POST to this endpoint adding a user to
// the system administrators group grants sudo/root access across all managed systems.

package scenarios

// JumpCloudGroupMemberScenarios2735 covers JumpCloud privilege escalation via
// system admin group member write through MCP HTTP tools.
var JumpCloudGroupMemberScenarios2735 = []Scenario{

	// ── TP: JumpCloud group member write ──────────────────────────────────────

	{
		ID:               "MCP-TP-2735-001",
		ToolName:         "http_post",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups/ADMIN_GROUP/members", "body": `{"id":"attacker","type":"user","op":"add"}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_post to JumpCloud /usergroups/{id}/members — adds user to system admin group, must BLOCK",
	},
	{
		ID:               "MCP-TP-2735-002",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups/sysadmin-group/members", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "make_request POST to JumpCloud /usergroups/{slug}/members — sysadmin group write, must BLOCK",
	},
	{
		ID:               "MCP-TP-2735-003",
		ToolName:         "http_put",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v1/usergroups/PRIV_GROUP/members"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_put to JumpCloud v1 /usergroups/{id}/members — PUT variant, must BLOCK",
	},
	{
		ID:               "MCP-TP-2735-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups/admins/members", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_request POST to JumpCloud /usergroups/admins/members — must BLOCK",
	},

	// ── TN: JumpCloud member listing (GET) and unrelated calls ────────────────

	{
		ID:               "MCP-TN-2735-001",
		ToolName:         "http_get",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups/ADMIN_GROUP/members"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_get to JumpCloud /usergroups/{id}/members — GET tool, read-only listing, must not BLOCK",
	},
	{
		ID:               "MCP-TN-2735-002",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups/ADMIN_GROUP"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_request to JumpCloud /usergroups/{id} without /members — group metadata read, must not BLOCK",
	},
	{
		ID:               "MCP-TN-2735-003",
		ToolName:         "http_post",
		Arguments:        map[string]interface{}{"url": "https://console.jumpcloud.com/api/v2/usergroups"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-jumpcloud-group-member-write-api",
		Description:      "http_post to JumpCloud /usergroups collection — group creation, not member write, must not BLOCK",
	},
}
