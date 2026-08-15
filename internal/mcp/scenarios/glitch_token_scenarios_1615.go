// Hand-curated MCP test scenarios for glitch-token injection detection.
// Issue #1615.
//
// Rules tested:
//   mcp-desc-glitch-token  — Go-engine sentinel in description_scanner.go
//                            (SignalGlitchToken in ScanToolDescription)
//
// Note: description-scanner rules are tested via description_scanner_test.go
// unit tests. The scenarios here verify that the *policy evaluator* correctly
// passes AUDIT for benign tool calls involving path/content arguments that
// happen to contain partial substring matches of glitch-token strings.

package scenarios

// GlitchTokenScenarios1615 covers glitch-token attack detection.
var GlitchTokenScenarios1615 = []Scenario{
	// ── TN: Benign file operations must not be blocked ────────────────────────

	{
		ID:               "MCP-TN-1615-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "glitch-token",
		Description:      "read_file on benign path — must not be affected by glitch-token detection",
	},
	{
		ID:               "MCP-TN-1615-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/src/main.go", "content": "package main"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "glitch-token",
		Description:      "write_file with normal content — must not trigger glitch-token rule",
	},
	{
		ID:               "MCP-TN-1615-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.config/app/settings.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "glitch-token",
		Description:      "read_file on config path — no glitch token in description, must AUDIT (config-guard)",
	},
}
