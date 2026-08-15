// Hand-curated MCP test scenarios for issue #2066:
// Terraform backend.tf and providers.tf write — state backend redirect and
// provider API endpoint injection vectors.
//
// Rules covered:
//   mcp-sc-audit-terraform-backend-write          (AUDIT write to **/backend.tf)
//   mcp-sc-audit-terraform-provider-config-write  (AUDIT write to **/providers.tf or **/provider.tf)

package scenarios

var TerraformBackendScenarios2066 = []Scenario{
	// TP: write_file to backend.tf → AUDIT
	{
		ID:               "MCP-TP-2066-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/backend.tf", "content": "terraform { backend \"s3\" {} }"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-backend-redirect",
		Description:      "write_file to backend.tf — must audit; state backend controls where infrastructure secrets are stored",
	},
	// TP: create_file to nested backend.tf → AUDIT
	{
		ID:               "MCP-TP-2066-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/terraform/envs/prod/backend.tf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-backend-redirect",
		Description:      "create_file to nested backend.tf — must audit",
	},
	// TP: str_replace_editor to backend.tf → AUDIT
	{
		ID:               "MCP-TP-2066-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/backend.tf", "new_str": "terraform {}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-backend-redirect",
		Description:      "str_replace_editor to backend.tf — must audit",
	},
	// TP: write_file to providers.tf → AUDIT
	{
		ID:               "MCP-TP-2066-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/providers.tf", "content": "provider \"aws\" { region = \"us-east-1\" }"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-provider-endpoint-injection",
		Description:      "write_file to providers.tf — must audit; provider config can inject endpoint overrides",
	},
	// TP: create_file to provider.tf → AUDIT
	{
		ID:               "MCP-TP-2066-005",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/project/terraform/provider.tf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-provider-endpoint-injection",
		Description:      "create_file to provider.tf — must audit",
	},
	// TP: edit_file to providers.tf → AUDIT
	{
		ID:               "MCP-TP-2066-006",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/workspace/envs/staging/providers.tf", "content": "provider \"azurerm\" {}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "terraform-provider-endpoint-injection",
		Description:      "edit_file to providers.tf in staging env — must audit",
	},
	// TN: read_file on backend.tf — read-only, must NOT trigger backend rule
	{
		ID:               "MCP-TN-2066-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/backend.tf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "terraform-backend-redirect",
		Description:      "read_file on backend.tf — read-only; must NOT trigger the backend write rule",
	},
	// TN: write_file to main.tf — same tool, different Terraform file
	{
		ID:               "MCP-TN-2066-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/main.tf", "content": "resource \"aws_s3_bucket\" \"data\" {}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "terraform-backend-redirect",
		Description:      "write_file to main.tf — routine Terraform resource file; must NOT trigger backend or provider rules",
	},
	// TN: write_file to doc about Terraform backend — .md extension
	{
		ID:               "MCP-TN-2066-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/terraform-backend-guide.md", "content": "# Backend Configuration Guide"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "terraform-backend-redirect",
		Description:      "write_file to markdown doc about backends — .md extension; must NOT trigger the backend.tf rule",
	},
	// TN: read_file on providers.tf — read-only, must NOT trigger provider rule
	{
		ID:               "MCP-TN-2066-004",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/infra/providers.tf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "terraform-provider-endpoint-injection",
		Description:      "read_file on providers.tf — read-only; must NOT trigger the provider write rule",
	},
}
