// Hand-curated MCP test scenarios for issue #2518:
// Jupyter notebook output injection — AI agent reads .ipynb file whose stored
// cell outputs contain adversarial AI directives from external data sources.
//
// Rules covered:
//   mcp-response-integrity-audit-ipynb-read  (AUDIT any read_* to *.ipynb)

package scenarios

var JupyterNotebookOutputInjectionScenarios2518 = []Scenario{
	// TP: read_file to .ipynb in workspace → AUDIT
	{
		ID:               "MCP-TP-2518-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-output-injection",
		Description:      "read_file to *.ipynb — stored cell outputs may contain adversarial directives; mcp-response-integrity-audit-ipynb-read must AUDIT",
	},
	// TP: get_file_contents to .ipynb in user home research dir → AUDIT
	{
		ID:               "MCP-TP-2518-002",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/home/user/research/data_exploration.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-output-injection",
		Description:      "get_file_contents to .ipynb in user home research dir — must AUDIT",
	},
	// TP: open_file to .ipynb in notebooks subdirectory → AUDIT
	{
		ID:               "MCP-TP-2518-003",
		ToolName:         "open_file",
		Arguments:        map[string]interface{}{"path": "/workspace/notebooks/model_training.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-output-injection",
		Description:      "open_file to .ipynb in notebooks dir — must AUDIT",
	},
	// TP: view_file to .ipynb pipeline notebook → AUDIT
	{
		ID:               "MCP-TP-2518-004",
		ToolName:         "view_file",
		Arguments:        map[string]interface{}{"path": "/workspace/ci/data_pipeline.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-output-injection",
		Description:      "view_file to .ipynb CI pipeline notebook — must AUDIT",
	},
	// TN: read_file to .py Python source — same tool, different extension
	{
		ID:               "MCP-TN-2518-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.py"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "jupyter-notebook-output-injection",
		Description:      "read_file to .py Python source — must NOT trigger the .ipynb-specific rule",
	},
	// TN: read_file to .md docs file mentioning jupyter notebooks — different extension
	{
		ID:               "MCP-TN-2518-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/jupyter-notebook-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "jupyter-notebook-output-injection",
		Description:      "read_file to .md doc about Jupyter notebooks — .md extension; must NOT trigger .ipynb rule",
	},
}
