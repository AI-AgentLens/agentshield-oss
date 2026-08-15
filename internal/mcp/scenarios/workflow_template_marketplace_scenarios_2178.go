// Hand-curated MCP test scenarios for issue #2178:
// AI workflow template marketplace poisoning detection.
//
// Rules covered:
//   mcp-sc-block-workflow-exfil-webhook-write (BLOCK — workflow file write containing exfil webhook URL)
//
// Rule lives in packs/premium/mcp/mcp-supply-chain-premium.yaml.
// Taxonomy: supply-chain/config-tampering/ai-workflow-template-marketplace-poisoning
//
// Attack vector: poisoned n8n/Flowise/LangFlow marketplace templates embed hidden
// webhook nodes routing execution data to ephemeral capture services (webhook.site,
// ngrok, requestbin, pipedream, canarytokens). When an agent writes such a template
// to disk, this rule fires before the file lands on the filesystem.
package scenarios

// WorkflowTemplateMarketplaceScenarios2178 covers MCP rules blocking writes of
// workflow definition files that contain known exfiltration webhook service URLs.
var WorkflowTemplateMarketplaceScenarios2178 = []Scenario{
	// TP: write n8n workflow JSON with webhook.site URL
	{
		ID:               "MCP-TP-2178-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/my-workflow.n8n.json", "content": `{"nodes":[{"type":"webhook","parameters":{"url":"https://webhook.site/abc12345-dead-beef-0000-aabbccddeeff"}}]}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: n8n workflow JSON with webhook.site exfiltration URL — must BLOCK",
	},
	// TP: create flow JSON with ngrok URL
	{
		ID:               "MCP-TP-2178-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/workspace/flows/automation.flow.json", "content": `{"connections":[{"webhookUrl":"https://2a3b4c.ngrok.io/receive"}]}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "create_file: workflow flow.json with ngrok.io URL — must BLOCK",
	},
	// TP: write n8n workflow with requestbin URL
	{
		ID:               "MCP-TP-2178-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/n8n/credential-harvest.n8n.json", "content": `{"nodes":[{"url":"https://requestbin.com/r/en1234abcd"}]}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: n8n workflow JSON with requestbin.com exfil URL — must BLOCK",
	},
	// TP: edit flowise workflow JSON with pipedream URL
	{
		ID:               "MCP-TP-2178-004",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/workspace/flowise-workflow.flow.json", "content": `{"nodes":[{"data":{"webhookUrl":"https://pipedream.net/sources/dc_abc123/sse"}}]}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "edit_file: flowise flow.json with pipedream.net exfil URL — must BLOCK",
	},
	// TP: write workflow YAML with canarytokens URL
	{
		ID:               "MCP-TP-2178-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/automation-workflow.yaml", "content": "nodes:\n  - type: webhook\n    url: https://canarytokens.com/generate?memo=test/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: workflow YAML with canarytokens.com exfil URL — must BLOCK",
	},
	// TN: n8n workflow with legitimate internal webhook URL — no exfil service
	{
		ID:               "MCP-TN-2178-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/my-workflow.n8n.json", "content": `{"nodes":[{"type":"webhook","parameters":{"url":"https://api.mycompany.com/webhook/ingest"}}]}`},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: n8n workflow with legitimate internal API webhook — must NOT trigger exfil webhook rule",
	},
	// TN: write to non-workflow file — path doesn't match workflow glob
	{
		ID:               "MCP-TN-2178-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/src/app.go", "content": "package main\nfunc main() {}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: Go source file — path doesn't match any workflow glob pattern, must NOT trigger",
	},
	// TN: documentation file mentioning exfil service — path doesn't match workflow glob
	{
		ID:               "MCP-TN-2178-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/webhook-security.md", "content": "# Webhook Security\n\nDo not use webhook.site in production workflows."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: markdown doc mentioning webhook.site (educational) — path is .md, not workflow glob, must NOT trigger",
	},
	// TN: n8n workflow with short legitimate webhook URL — no exfil service, content below entropy threshold
	{
		ID:               "MCP-TN-2178-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/my-workflow.n8n.json", "content": `{"url": "https://alerts.myco.io/hook"}`},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "supply-chain/workflow-template-marketplace-poisoning",
		Description:      "write_file: n8n workflow with short legitimate webhook URL — no exfil service domain, must NOT trigger exfil webhook or content scanner rules",
	},
}
