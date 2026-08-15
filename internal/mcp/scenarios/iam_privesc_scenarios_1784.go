// Hand-curated MCP test scenarios for AWS IAM SDK privilege escalation via MCP.
// Issue #1784.
//
// Rules tested:
//   mcp-privesc-block-aws-iam-admin-policy-attach  — attach AdministratorAccess/IAMFullAccess (BLOCK)
//   mcp-privesc-block-aws-iam-access-key-create-sdk — create access keys via SDK tool (BLOCK)
//
// Gap context: The existing mcp-privesc-block-aws-iam-create-api rule covers IAM mutations
// via raw http_request tools (calls to iam.amazonaws.com). This file covers the complementary
// gap: dedicated AWS IAM SDK MCP tools (iam_attach_role_policy, iam_create_access_key, etc.)
// that abstract the HTTP layer. Both threat classes use the same taxonomy.

package scenarios

// IAMPrivescScenarios1784 covers AWS IAM admin policy attachment and access key creation
// via dedicated SDK MCP tools (not the HTTP API path, which is covered by mcp-privesc-block-aws-iam-create-api).
var IAMPrivescScenarios1784 = []Scenario{

	// ── TP: attach AdministratorAccess via SDK tool ────────────────────────────

	{
		ID:               "MCP-TP-1784-001",
		ToolName:         "iam_attach_role_policy",
		Arguments:        map[string]interface{}{"RoleName": "my-role", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-aws-iam-admin-policy-attach-sdk",
		Description:      "iam_attach_role_policy with AdministratorAccess ARN (CamelCase key) — grants root-equivalent AWS access, must BLOCK",
	},
	{
		ID:               "MCP-TP-1784-002",
		ToolName:         "aws_iam_attach_user_policy",
		Arguments:        map[string]interface{}{"UserName": "backdoor-user", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-aws-iam-admin-policy-attach",
		Description:      "aws_iam_attach_user_policy with AdministratorAccess ARN — must BLOCK regardless of user target",
	},
	{
		ID:               "MCP-TP-1784-003",
		ToolName:         "iam_attach_group_policy",
		Arguments:        map[string]interface{}{"GroupName": "engineers", "PolicyArn": "arn:aws:iam::aws:policy/IAMFullAccess"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-aws-iam-admin-policy-attach-sdk",
		Description:      "iam_attach_group_policy with IAMFullAccess ARN (CamelCase key) — grants full IAM control, must BLOCK",
	},

	// ── TP: create IAM access key via SDK tool ─────────────────────────────────

	{
		ID:               "MCP-TP-1784-004",
		ToolName:         "iam_create_access_key",
		Arguments:        map[string]interface{}{"UserName": "backdoor-user"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-aws-iam-access-key-create-sdk",
		Description:      "iam_create_access_key via SDK tool — creates persistent backdoor credentials, must BLOCK",
	},
	{
		ID:               "MCP-TP-1784-005",
		ToolName:         "aws_iam_create_access_key",
		Arguments:        map[string]interface{}{"user_name": "attacker"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-aws-iam-access-key-create-sdk",
		Description:      "aws_iam_create_access_key via SDK tool — persistent credential creation, must BLOCK",
	},

	// ── TN: read-only IAM operations — must NOT be BLOCK ──────────────────────

	{
		ID:               "MCP-TN-1784-001",
		ToolName:         "iam_attach_role_policy",
		Arguments:        map[string]interface{}{"RoleName": "lambda-exec", "PolicyArn": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-aws-iam-admin-policy-attach",
		Description:      "iam_attach_role_policy with read-only policy (not admin) — must NOT be BLOCK. Gets AUDIT from existing aws-cli rule.",
	},
	{
		ID:               "MCP-TN-1784-002",
		ToolName:         "iam_list_access_keys",
		Arguments:        map[string]interface{}{"UserName": "my-user"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-aws-iam-access-key-create-sdk",
		Description:      "iam_list_access_keys — read-only listing, must NOT be BLOCK. Gets default AUDIT.",
	},
	{
		ID:               "MCP-TN-1784-003",
		ToolName:         "iam_get_role",
		Arguments:        map[string]interface{}{"RoleName": "my-role"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-aws-iam-admin-policy-attach",
		Description:      "iam_get_role — read-only inspection, must NOT be BLOCK. Gets default AUDIT.",
	},
}
