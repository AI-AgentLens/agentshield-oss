// Hand-curated MCP test scenarios for issue #2065:
// Jupyter notebook (.ipynb) write via MCP — notebook cell injection vector.
//
// Rules covered:
//   mcp-persist-audit-jupyter-notebook-write  (AUDIT any write to *.ipynb)

package scenarios

var JupyterNotebookScenarios2065 = []Scenario{
	// TP: write_file to project .ipynb → AUDIT
	{
		ID:               "MCP-TP-2065-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.ipynb", "content": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-injection",
		Description:      "write_file to *.ipynb — code cells execute on 'Run All'; must trigger audit",
	},
	// TP: create_file to .ipynb in data science dir → AUDIT
	{
		ID:               "MCP-TP-2065-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/home/user/research/data_exploration.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-injection",
		Description:      "create_file to .ipynb in user home dir — must trigger audit",
	},
	// TP: edit_file to nested .ipynb → AUDIT
	{
		ID:               "MCP-TP-2065-003",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/workspace/notebooks/model_training.ipynb", "content": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-injection",
		Description:      "edit_file to nested *.ipynb — adding/modifying cells must trigger audit",
	},
	// TP: str_replace_editor to .ipynb → AUDIT
	{
		ID:               "MCP-TP-2065-004",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/workspace/experiments/feature_engineering.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-injection",
		Description:      "str_replace_editor to .ipynb — cell modification must trigger audit",
	},
	// TP: append_file to .ipynb (injecting new cell at end) → AUDIT
	{
		ID:               "MCP-TP-2065-005",
		ToolName:         "append_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.ipynb", "content": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "jupyter-notebook-injection",
		Description:      "append_file to .ipynb — appending cells is the primary injection vector; must trigger audit",
	},
	// TN: read_file on .ipynb — read-only, must NOT trigger
	{
		ID:               "MCP-TN-2065-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.ipynb"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "jupyter-notebook-injection",
		Description:      "read_file on .ipynb — read-only access; must NOT trigger the notebook write rule",
	},
	// TN: write_file to .py Python source — same tool, different extension
	{
		ID:               "MCP-TN-2065-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/analysis.py", "content": "import pandas as pd"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "jupyter-notebook-injection",
		Description:      "write_file to .py — Python source file; must NOT trigger the .ipynb-specific rule",
	},
	// TN: write_file to a path that mentions .ipynb in a directory name but is a different file
	{
		ID:               "MCP-TN-2065-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/jupyter-notebook-guide.md", "content": "# Jupyter Notebooks\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "jupyter-notebook-injection",
		Description:      "write_file to .md doc about Jupyter notebooks — .md extension; must NOT trigger the .ipynb rule",
	},
}
