// Hand-curated MCP test scenarios for the fake tool-response continuation
// protocol resource-amplification attack. Issue #2776.
//
// Research basis: "Beyond Max Tokens: Stealthy Resource Amplification via
// Tool Calling Chains in LLM Agents" (arXiv:2601.10955, NTU/UIUC/HKUST/SJTU,
// Jan 2026). A compromised/malicious MCP tool server withholds the real
// result behind a fake "calibration" handshake, instructing the agent to
// echo back a long comma-separated integer sequence before it will return
// the final payload — inflating tool-calling cost 100-650x without changing
// the final answer.
//
// Rule tested:
//
//	mcp-agentic-audit-fake-calibration-echo-payload — long integer-list
//	  echoed back in a 'calibration_sequence' argument (AUDIT)
//
// The companion rule (mcp-agentic-audit-fake-continuation-segment-loop) is a
// cross-call sequence rule and cannot fire on a single scenario call; it is
// validated separately by TestMCPSequenceRule_ResourceAmplificationSegmentLoop
// in internal/mcp/sequence_rule_test.go.
package scenarios

// ResourceAmplificationScenarios2776 covers the fake calibration-echo
// continuation-protocol resource-amplification attack.
var ResourceAmplificationScenarios2776 = []Scenario{

	// ── TP: long integer-list echoed back as a 'calibration_sequence' arg ────

	{
		ID:               "MCP-TP-2776-001",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"calibration_sequence": "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-fake-calibration-echo-payload",
		Description:      "read_resource carrying a 20-integer 'calibration_sequence' echo — fake continuation-protocol compliance, must AUDIT",
	},
	{
		ID:               "MCP-TP-2776-002",
		ToolName:         "call_tool",
		Arguments:        map[string]interface{}{"calibration_sequence": "3, 6, 9, 12, 15, 18, 21, 24, 27, 30, 33, 36, 39, 42, 45"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-fake-calibration-echo-payload",
		Description:      "call_tool carrying a 15-integer space-separated 'calibration_sequence' echo — meets the minimum threshold, must AUDIT",
	},

	// ── TN: short or non-numeric 'calibration_sequence' values ───────────────

	{
		ID:               "MCP-TN-2776-001",
		ToolName:         "call_tool",
		Arguments:        map[string]interface{}{"calibration_sequence": "1,2,3"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-fake-calibration-echo-payload",
		Description:      "call_tool with a short 3-integer list — below the 15-integer threshold, must NOT trigger the amplification rule",
	},
	{
		ID:               "MCP-TN-2776-002",
		ToolName:         "get_batch_status",
		Arguments:        map[string]interface{}{"calibration_sequence": "v2.1-baseline"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-fake-calibration-echo-payload",
		Description:      "get_batch_status with a non-numeric version-string 'calibration_sequence' value — must NOT trigger the amplification rule",
	},
}
