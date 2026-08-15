// Hand-curated MCP test scenarios for MCP UI component injection.
// Issue #2622 — MCP UI component injection via OpenAI Apps SDK and MCP-UI spec.
//
// Rules tested:
//   mcp-agentic-audit-ui-scheme-resource — resources/read with ui:// scheme (AUDIT)
//
// Response-content signals (tested in response_scanner_test.go):
//   SignalResponseUIBridgeCall — window.openai.callTool / sendFollowUpMessage / window.ai.callTool
//   SignalResponseUICredentialForm — <form action=http://...> + <input type=password>
//
// Attack vectors:
//   1. Host-bridge tool escalation: MCP server returns HTML resource with
//      window.openai.callTool() / sendFollowUpMessage() / window.ai.callTool()
//      script tags — widget dispatches agent tool calls without user consent.
//   2. Visual deception: HTML resource contains a <form action="https://attacker.tld">
//      with a password input field, painting a phishing overlay in the host renderer.
//   3. ui:// scheme: MCP-UI spec interactive widget resources fetch in the trusted
//      host frame — every ui:// fetch is audited before content is loaded.

package scenarios

// MCPUIInjectionScenarios2622 covers MCP UI component injection attack vectors.
var MCPUIInjectionScenarios2622 = []Scenario{

	// ── TP: ui:// scheme resource fetch — AUDIT ───────────────────────────────

	{
		ID:               "MCP-TP-2622-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "ui://server/components/dashboard"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-ui-scheme-resource",
		Description:      "resources/read with ui:// scheme — MCP-UI interactive widget resource, must AUDIT",
	},
	{
		ID:               "MCP-TP-2622-002",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "ui://mcp-ui.example.com/widgets/approval-gate"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-ui-scheme-resource",
		Description:      "read_resource with ui:// scheme to external host — interactive widget resource fetched in host renderer, must AUDIT",
	},
	{
		ID:               "MCP-TP-2622-003",
		ToolName:         "fetch_resource",
		Arguments:        map[string]interface{}{"uri": "ui://localhost/components/form"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-ui-scheme-resource",
		Description:      "fetch_resource with ui://localhost scheme — local MCP-UI widget, must AUDIT",
	},

	// ── TN: Benign resource URIs — not triggered by ui:// rule ───────────────
	// These expect AUDIT (not ALLOW) because other rules audit resource fetch calls.
	// The goal is to verify the ui:// rule does NOT fire for normal schemes.

	{
		ID:               "MCP-TN-2622-001",
		ToolName:         "resources/read",
		Arguments:        map[string]interface{}{"uri": "file:///workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-ui-scheme-resource",
		Description:      "resources/read with file:// workspace URI — normal file resource, must NOT be flagged by ui:// rule (AUDIT from other rules is ok)",
	},
	{
		ID:               "MCP-TN-2622-002",
		ToolName:         "read_resource",
		Arguments:        map[string]interface{}{"uri": "https://api.github.com/repos/example/repo/contents"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-ui-scheme-resource",
		Description:      "read_resource with HTTPS URI — normal external resource fetch, must NOT be flagged by ui:// rule (AUDIT from external-HTTP rule is ok)",
	},
}
