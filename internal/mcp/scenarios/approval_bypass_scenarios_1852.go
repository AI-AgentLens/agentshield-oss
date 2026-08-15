// Hand-curated MCP test scenarios for issue #1852:
// IaC deployment auto-approval bypass via auto_approve and confirm argument flags.
//
// Rules covered:
//   mcp-agentic-block-iac-auto-approve-bypass  (BLOCK auto_approve=true on IaC tools)
//   mcp-agentic-audit-deployment-confirm-bypass (AUDIT confirm=false on deployment tools)

package scenarios

var ApprovalBypassScenarios1852 = []Scenario{
	// TP: terraform_apply with auto_approve=true → BLOCK
	{
		ID:               "MCP-TP-1852-001",
		ToolName:         "terraform_apply",
		Arguments:        map[string]interface{}{"workspace": "prod", "auto_approve": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "terraform_apply with auto_approve=true — bypasses plan review, agent self-approving infra change",
	},
	{
		ID:               "MCP-TP-1852-002",
		ToolName:         "pulumi_up",
		Arguments:        map[string]interface{}{"stack": "production", "auto_approve": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "pulumi_up with auto_approve=true — agent bypassing Pulumi confirmation gate on production stack",
	},
	{
		ID:               "MCP-TP-1852-003",
		ToolName:         "helm_upgrade",
		Arguments:        map[string]interface{}{"release": "payment-service", "chart": "stable/payment", "auto_approve": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "helm_upgrade with auto_approve=true — Helm release upgrade without human review",
	},
	{
		ID:               "MCP-TP-1852-004",
		ToolName:         "cdk_deploy",
		Arguments:        map[string]interface{}{"stack": "ProdStack", "auto_approve": "yes"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "cdk_deploy with auto_approve=yes (string variant) — CDK deployment bypassing approval",
	},
	{
		ID:               "MCP-TP-1852-005",
		ToolName:         "terraform_destroy",
		Arguments:        map[string]interface{}{"workspace": "staging", "auto_approve": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "terraform_destroy with auto_approve=true — destructive infra removal without review",
	},
	{
		ID:               "MCP-TP-1852-006",
		ToolName:         "pulumi_destroy",
		Arguments:        map[string]interface{}{"stack": "dev", "auto_approve": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "iac-approval-bypass",
		Description:      "pulumi_destroy with auto_approve=true — Pulumi stack destruction without confirmation",
	},
	// TP: deployment tools with confirm=false → AUDIT
	{
		ID:               "MCP-TP-1852-007",
		ToolName:         "deploy_stack",
		Arguments:        map[string]interface{}{"name": "prod-stack", "confirm": false},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "deployment-confirm-bypass",
		Description:      "deploy_stack with confirm=false — deployment bypassing interactive confirmation",
	},
	{
		ID:               "MCP-TP-1852-008",
		ToolName:         "kubernetes_rollout",
		Arguments:        map[string]interface{}{"deployment": "api-gateway", "confirm": false},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "deployment-confirm-bypass",
		Description:      "kubernetes_rollout with confirm=false — K8s rollout without confirmation",
	},
	// TN: IaC tools WITHOUT auto_approve → should not be blocked
	{
		ID:               "MCP-TN-1852-001",
		ToolName:         "terraform_apply",
		Arguments:        map[string]interface{}{"workspace": "prod"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "iac-approval-bypass",
		Description:      "terraform_apply without auto_approve — normal apply with human review, should pass through",
	},
	{
		ID:               "MCP-TN-1852-002",
		ToolName:         "terraform_plan",
		Arguments:        map[string]interface{}{"dir": "/infra/prod", "auto_approve": true},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "iac-approval-bypass",
		Description:      "terraform_plan with auto_approve=true — plan is read-only, auto_approve has no security implication here",
	},
	{
		ID:               "MCP-TN-1852-003",
		ToolName:         "pulumi_preview",
		Arguments:        map[string]interface{}{"stack": "production", "auto_approve": true},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "iac-approval-bypass",
		Description:      "pulumi_preview with auto_approve=true — preview is read-only, no approval bypass risk",
	},
	{
		ID:               "MCP-TN-1852-004",
		ToolName:         "helm_list",
		Arguments:        map[string]interface{}{"all": true},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "iac-approval-bypass",
		Description:      "helm_list — read-only Helm operation, no deployment action",
	},
	{
		ID:               "MCP-TN-1852-005",
		ToolName:         "get_deployment_status",
		Arguments:        map[string]interface{}{"name": "prod-stack", "confirm": false},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "deployment-confirm-bypass",
		Description:      "get_deployment_status with confirm=false — read-only status check, no deployment action",
	},
	{
		ID:               "MCP-TN-1852-006",
		ToolName:         "deploy_stack",
		Arguments:        map[string]interface{}{"name": "prod-stack", "confirm": true},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "deployment-confirm-bypass",
		Description:      "deploy_stack with confirm=true — confirmation enabled, human review intact",
	},
}
