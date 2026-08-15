// Hand-curated MCP test scenarios for issue #2129:
// AI fine-tuning data upload via MCP HTTP tools — BLOCK for OpenAI/Anthropic/Together,
// AUDIT for HuggingFace dataset uploads.
//
// Rules covered:
//   mcp-llmdf-block-ai-finetuning-openai-files-upload   (BLOCK — OpenAI /v1/files)
//   mcp-llmdf-block-ai-finetuning-anthropic-files-upload (BLOCK — Anthropic /v1/files)
//   mcp-llmdf-block-ai-finetuning-together-files-upload  (BLOCK — Together AI /v1/files)
//   mcp-llmdf-audit-ai-dataset-huggingface-upload        (AUDIT — HuggingFace upload/commit)

package scenarios

// AIFineTuningUploadScenarios2129 covers MCP rules blocking AI training-data
// upload endpoints used for data exfiltration via fine-tuning infrastructure.
var AIFineTuningUploadScenarios2129 = []Scenario{
	// TP: OpenAI files API upload → BLOCK
	{
		ID:               "MCP-TP-2129-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.openai.com/v1/files", "method": "POST", "body": "jsonl_training_data"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to OpenAI files API — fine-tuning data exfiltration via HTTP tool, must BLOCK",
	},
	{
		ID:               "MCP-TP-2129-002",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://api.openai.com/v1/files/create", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to OpenAI files/create subpath via make_request — must BLOCK",
	},
	{
		ID:               "MCP-TP-2129-003",
		ToolName:         "network_request",
		Arguments:        map[string]interface{}{"url": "https://api.openai.com/v1/files/upload", "data": "sensitive_codebase"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "Upload to OpenAI files/upload via network_request — must BLOCK",
	},
	// TP: Anthropic files API upload → BLOCK
	{
		ID:               "MCP-TP-2129-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.anthropic.com/v1/files", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Anthropic files API — training/context data exfiltration, must BLOCK",
	},
	{
		ID:               "MCP-TP-2129-005",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://api.anthropic.com/v1/files/create", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Anthropic files/create via make_request — must BLOCK",
	},
	// TP: Together AI files API upload → BLOCK
	{
		ID:               "MCP-TP-2129-006",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.together.xyz/v1/files", "method": "POST"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Together AI files API — fine-tuning data exfiltration, must BLOCK",
	},
	{
		ID:               "MCP-TP-2129-007",
		ToolName:         "post_request",
		Arguments:        map[string]interface{}{"url": "https://api.together.xyz/v1/files/upload"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to Together AI files/upload via post_request — must BLOCK",
	},
	// TP: HuggingFace dataset upload → AUDIT
	{
		ID:               "MCP-TP-2129-008",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://huggingface.co/api/datasets/myorg/my-dataset/upload", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "POST to HuggingFace dataset upload endpoint (org/repo/upload) — must AUDIT",
	},
	{
		ID:               "MCP-TP-2129-009",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://hf.co/api/models/myorg/my-model/commit", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "Commit to HuggingFace model repo via hf.co (org/repo/commit) — must AUDIT",
	},
	{
		ID:               "MCP-TP-2129-010",
		ToolName:         "network_request",
		Arguments:        map[string]interface{}{"url": "https://huggingface.co/api/datasets/acme-corp/internal-training-data/upload"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "ai-finetuning-data-upload",
		Description:      "Upload to HuggingFace dataset with multi-word repo name — must AUDIT",
	},
	// TN: normal AI API calls must NOT trigger
	{
		ID:               "MCP-TN-2129-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.openai.com/v1/chat/completions", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Normal OpenAI chat completions call — must NOT be caught by fine-tuning upload rules",
	},
	{
		ID:               "MCP-TN-2129-002",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.openai.com/v1/models", "method": "GET"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "OpenAI model listing — must NOT be caught by fine-tuning upload rules",
	},
	{
		ID:               "MCP-TN-2129-003",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.anthropic.com/v1/messages", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Normal Anthropic messages call — must NOT be caught by fine-tuning upload rules",
	},
	{
		ID:               "MCP-TN-2129-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://huggingface.co/api/models?search=mistral", "method": "GET"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "HuggingFace model search (GET, no upload) — must NOT trigger",
	},
	{
		ID:               "MCP-TN-2129-005",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/openai_files_guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Reading docs about OpenAI files API — URL appears only in file path text, must NOT trigger",
	},
	{
		ID:               "MCP-TN-2129-006",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.together.xyz/v1/chat/completions", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ai-finetuning-data-upload",
		Description:      "Together AI chat completions (inference, not upload) — must NOT trigger",
	},
}
