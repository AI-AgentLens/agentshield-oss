// Hand-curated MCP test scenarios for issue #1951:
// Approval-fatigue exploitation — bait-and-switch (BLOCK) and burst-rate (AUDIT).
//
// Rules covered:
//   mcp-agentic-block-approval-bait-and-switch  (BLOCK — __mcp_approval_bait_switch__)
//   mcp-agentic-audit-approval-burst-rate       (AUDIT — __mcp_approval_burst__)
//
// Note: the synthetic tool names are emitted by internal/mcp/approval_fatigue.go
// when the per-session tracker detects the pattern. The policy rules match on
// these names, so the YAML tests validate that the policy engine wires up
// correctly.

package scenarios

var ApprovalFatigueScenarios1951 = []Scenario{
	// TP: bait-and-switch synthetic name → BLOCK
	{
		ID:               "MCP-TP-1951-001",
		ToolName:         syntheticApprovalBaitSwitch,
		Arguments:        map[string]interface{}{"context": "delete_file after 4 consecutive read_file calls"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "approval-fatigue",
		Description:      "Approval-fatigue bait-and-switch: synthetic tool name indicates prior all-read-only sequence ending in destructive call",
	},
	// TP: burst synthetic name → AUDIT
	{
		ID:               "MCP-TP-1951-002",
		ToolName:         syntheticApprovalBurst,
		Arguments:        map[string]interface{}{"context": "write_file after 5 rapid calls"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "approval-fatigue",
		Description:      "Approval-fatigue burst: synthetic tool name indicates ≥5 tool calls in 30 s followed by high-impact call",
	},
	// TN: normal read_file — must not trigger approval-fatigue rules
	{
		ID:               "MCP-TN-1951-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "approval-fatigue",
		Description:      "Normal read_file — must not be caught by approval-fatigue rules",
	},
	// TN: normal write_file with no approval-fatigue context
	{
		ID:               "MCP-TN-1951-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/output.txt", "content": "result"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "approval-fatigue",
		Description:      "Normal write_file — must not be caught by approval-fatigue rules (policy only fires on synthetic names)",
	},
}

// syntheticApprovalBaitSwitch mirrors internal/mcp/approval_fatigue.go.
const syntheticApprovalBaitSwitch = "__mcp_approval_bait_switch__"

// syntheticApprovalBurst mirrors internal/mcp/approval_fatigue.go.
const syntheticApprovalBurst = "__mcp_approval_burst__"
