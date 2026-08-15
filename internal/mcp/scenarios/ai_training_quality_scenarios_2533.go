// Hand-curated MCP test scenarios for issue #2533:
// AI training data quality validation gap — AUDIT for fine-tuning job creation
// and training file upload via named MCP tools (SDK-wrapped or vendor MCP servers).
//
// Rules covered:
//   mcp-gov-audit-finetune-job-create   (AUDIT — named fine-tuning job creation tools)
//   mcp-gov-audit-training-file-upload  (AUDIT — named training file upload tools)

package scenarios

// AITrainingQualityScenarios2533 covers MCP governance rules detecting
// fine-tuning invocations via named tools without preceding data validation.
var AITrainingQualityScenarios2533 = []Scenario{
	// TP: create_fine_tuning_job → AUDIT
	{
		ID:               "MCP-TP-2533-001",
		ToolName:         "create_fine_tuning_job",
		Arguments:        map[string]interface{}{"training_file": "file-abc123", "model": "gpt-4o-mini", "suffix": "my-model"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "create_fine_tuning_job with training file — governance gap: confirm data quality gates completed before job launch",
	},
	// TP: train_model → AUDIT
	{
		ID:               "MCP-TP-2533-002",
		ToolName:         "train_model",
		Arguments:        map[string]interface{}{"dataset": "s3://my-bucket/feedback-data.jsonl", "base_model": "llama-3-8b"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "train_model with S3 dataset path — unvalidated feedback ingestion risk, must AUDIT",
	},
	// TP: finetune_model → AUDIT
	{
		ID:               "MCP-TP-2533-003",
		ToolName:         "finetune_model",
		Arguments:        map[string]interface{}{"model": "claude-haiku", "training_data_id": "td-xyz", "hyperparameters": map[string]interface{}{"n_epochs": 3}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "finetune_model with training data reference — must AUDIT for quality validation gate",
	},
	// TP: create_training_run → AUDIT
	{
		ID:               "MCP-TP-2533-004",
		ToolName:         "create_training_run",
		Arguments:        map[string]interface{}{"dataset_id": "ds-001", "model_config": "mistral-7b-instruct"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "create_training_run via MCP — must AUDIT before training data enters model weights",
	},
	// TP: submit_training_job → AUDIT
	{
		ID:               "MCP-TP-2533-005",
		ToolName:         "submit_training_job",
		Arguments:        map[string]interface{}{"job_config": "config/train.yaml", "cluster": "gpu-cluster-01"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "submit_training_job with job config — must AUDIT for data governance review",
	},
	// TP: upload_training_file → AUDIT
	{
		ID:               "MCP-TP-2533-006",
		ToolName:         "upload_training_file",
		Arguments:        map[string]interface{}{"file_path": "/workspace/data/feedback.jsonl", "purpose": "fine-tune"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-training-file-upload",
		Description:      "upload_training_file with raw feedback data — must AUDIT: data quality unverified",
	},
	// TP: upload_fine_tuning_file → AUDIT
	{
		ID:               "MCP-TP-2533-007",
		ToolName:         "upload_fine_tuning_file",
		Arguments:        map[string]interface{}{"content": "[{\"role\": \"user\", \"content\": \"help\"}]", "model": "gpt-4o-mini"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-training-file-upload",
		Description:      "upload_fine_tuning_file with inline training content — must AUDIT for PII and quality",
	},
	// TP: upload_training_data → AUDIT
	{
		ID:               "MCP-TP-2533-008",
		ToolName:         "upload_training_data",
		Arguments:        map[string]interface{}{"dataset_path": "s3://data-lake/raw-support-tickets.csv", "format": "jsonl"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-gov-audit-training-file-upload",
		Description:      "upload_training_data with raw support ticket CSV — risk of PII and noisy data entering model, must AUDIT",
	},
	// TN: list_fine_tuning_jobs — read-only, not creating a training run
	{
		ID:               "MCP-TN-2533-001",
		ToolName:         "list_fine_tuning_jobs",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "list_fine_tuning_jobs — read-only enumeration, must NOT trigger the fine-tuning job creation rule",
	},
	// TN: retrieve_fine_tuning_job — read-only
	{
		ID:               "MCP-TN-2533-002",
		ToolName:         "retrieve_fine_tuning_job",
		Arguments:        map[string]interface{}{"fine_tuning_job_id": "ftjob-abc123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "retrieve_fine_tuning_job — read-only status check, must NOT trigger fine-tuning creation rule",
	},
	// TN: write_file with fine-tuning documentation — not a real fine-tuning API call
	{
		ID:               "MCP-TN-2533-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/fine_tuning_guide.md", "content": "# Fine-Tuning Guide\n\nCall create_fine_tuning_job to start."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-gov-audit-finetune-job-create",
		Description:      "write_file with fine-tuning guide content — documentation write, must NOT trigger fine-tuning creation rule",
	},
	// TN: upload_file (generic upload, not training-specific tool)
	{
		ID:               "MCP-TN-2533-004",
		ToolName:         "upload_file",
		Arguments:        map[string]interface{}{"path": "/workspace/report.pdf", "destination": "s3://reports/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-gov-audit-training-file-upload",
		Description:      "upload_file for a report PDF — generic upload not in training tool list, must NOT trigger training file upload rule",
	},
	// TN: list_files — read-only
	{
		ID:               "MCP-TN-2533-005",
		ToolName:         "list_files",
		Arguments:        map[string]interface{}{"purpose": "fine-tune"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-gov-audit-training-file-upload",
		Description:      "list_files for fine-tuning purpose — read-only listing, must NOT trigger training file upload rule",
	},
}
