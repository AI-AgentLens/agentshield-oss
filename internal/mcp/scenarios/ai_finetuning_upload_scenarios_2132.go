// Hand-curated MCP test scenarios for issue #2132:
// Azure OpenAI Service fine-tuning upload rules — BLOCK for *.openai.azure.com
// and *.cognitiveservices.azure.com files/fine_tuning endpoints.
//
// Rules covered:
//   mcp-llmdf-block-ai-finetuning-azure-openai-upload           (BLOCK — Azure OpenAI /openai/files, /openai/fine_tuning)
//   mcp-llmdf-block-ai-finetuning-azure-cognitiveservices-upload (BLOCK — Azure CogSvc /openai/files)

package scenarios

// AIFineTuningAzureScenarios2132 covers MCP rules blocking AI training-data
// upload to Azure OpenAI Service endpoints used for fine-tuning exfiltration.
var AIFineTuningAzureScenarios2132 = []Scenario{
	// TP: Azure OpenAI files API upload → BLOCK
	{
		ID:               "MCP-TP-2132-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://mycompany.openai.azure.com/openai/files", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure OpenAI files API — fine-tuning data exfiltration via HTTP tool, must BLOCK",
	},
	{
		ID:               "MCP-TP-2132-002",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://eastus-resource.openai.azure.com/openai/files/create", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure OpenAI files/create subpath via make_request — must BLOCK",
	},
	{
		ID:               "MCP-TP-2132-003",
		ToolName:         "network_request",
		Arguments:        map[string]interface{}{"url": "https://corp-ai.openai.azure.com/openai/fine_tuning/jobs", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure OpenAI fine_tuning/jobs endpoint — training job creation exfiltrates data, must BLOCK",
	},
	{
		ID:               "MCP-TP-2132-004",
		ToolName:         "api_request",
		Arguments:        map[string]interface{}{"url": "https://myorg.openai.azure.com/openai/fine_tuning/jobs/ft-abc123/cancel", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure OpenAI fine_tuning subpath via api_request — must BLOCK",
	},
	// TP: Azure Cognitive Services OpenAI files API → BLOCK
	{
		ID:               "MCP-TP-2132-005",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://myorg.cognitiveservices.azure.com/openai/files", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure Cognitive Services OpenAI files API — alternate provisioning path with same exfiltration risk, must BLOCK",
	},
	{
		ID:               "MCP-TP-2132-006",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://eastus-cog.cognitiveservices.azure.com/openai/files/upload", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure CogSvc OpenAI files/upload via make_request — must BLOCK",
	},
	{
		ID:               "MCP-TP-2132-007",
		ToolName:         "send_request",
		Arguments:        map[string]interface{}{"url": "https://corp-ai.cognitiveservices.azure.com/openai/files", "method": "POST", "body": "training_data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Azure CogSvc OpenAI files via send_request — must BLOCK",
	},
	// TN: Azure OpenAI inference endpoints must NOT trigger
	{
		ID:               "MCP-TN-2132-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://mycompany.openai.azure.com/openai/deployments/gpt-4/chat/completions", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Normal Azure OpenAI chat completions inference call — must NOT be caught by fine-tuning upload rules",
	},
	{
		ID:               "MCP-TN-2132-002",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://mycompany.openai.azure.com/openai/models", "method": "GET"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Azure OpenAI model listing (GET, read-only) — must NOT trigger",
	},
	{
		ID:               "MCP-TN-2132-003",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://myorg.cognitiveservices.azure.com/openai/deployments/gpt-35/completions", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Azure CogSvc inference completions endpoint — must NOT trigger fine-tuning upload rule",
	},
	{
		ID:               "MCP-TN-2132-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://myorg.cognitiveservices.azure.com/openai/models", "method": "GET"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Azure CogSvc model listing — must NOT trigger",
	},
	{
		ID:               "MCP-TN-2132-005",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/azure_openai_files_guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Reading docs about Azure OpenAI files API — URL appears only in file path text, must NOT trigger",
	},
}
