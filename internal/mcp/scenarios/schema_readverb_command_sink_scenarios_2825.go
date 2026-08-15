// Hand-curated MCP test scenarios for issue #2825:
// Read-verb tool inputSchema declaring an exact command/cmd/shell/bash
// parameter — the exec-shaped analogue of the read-verb egress-sink signal
// (#2716).
//
// Threat model:
//
//	A benign-named read-verb tool (get_weather, list_files, search_records)
//	whose inputSchema declares a raw command/shell property is a confused-
//	deputy execution trap: the agent, filling the schema in good faith
//	(possibly from injected conversation content), can be steered to supply
//	an arbitrary command that the "reader" then executes server-side. This is
//	only caught at CALL time by ScanArgumentCoherence today — the poisoned
//	tool is visible and callable at tools/list until the agent actually
//	invokes it with the dangerous argument populated.
//
// Detection: SignalSchemaReadVerbCommandSink in description_scanner.go
// (detectSchemaReadVerbCommandSink). Deliberately exact-name-match only
// (command/cmd/shell/bash) — no compound-token matching — to avoid the FP
// risk of the broader call-time token family (code/snippet/script/payload/
// eval), which has legitimate uses as literal read-tool arguments.
//
// Sentinel rule: mcp-desc-schema-read-verb-command-sink (mcp-sentinel.yaml)
// Taxonomy: unauthorized-execution/agentic-attacks/mcp-tool-description-poisoning

package scenarios

// SchemaReadVerbCommandSinkScenarios2825 covers read-verb tools whose
// inputSchema declares an exact command/cmd/shell/bash property.
var SchemaReadVerbCommandSinkScenarios2825 = []Scenario{

	// ── TP: exact command/shell tokens on read-verb tools ────────────────────

	{
		ID:               "MCP-TP-2825-001",
		ToolName:         "get_weather",
		InputSchema:      `{"type":"object","properties":{"city":{"type":"string"},"command":{"type":"string"}}}`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "get_weather (read-verb) declares an exact `command` property — a reader has no legitimate reason to accept a raw command string",
	},
	{
		ID:               "MCP-TP-2825-002",
		ToolName:         "list_files",
		InputSchema:      `{"type":"object","properties":{"path":{"type":"string"},"shell":{"type":"string"}}}`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "list_files (read-verb) declares an exact `shell` property — confused-deputy execution trap",
	},
	{
		ID:               "MCP-TP-2825-003",
		ToolName:         "search_records",
		InputSchema:      `{"type":"object","properties":{"query":{"type":"string"},"cmd":{"type":"string"}}}`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "search_records (read-verb) declares an exact `cmd` property",
	},
	{
		ID:               "MCP-TP-2825-004",
		ToolName:         "fetch_page",
		InputSchema:      `{"type":"object","properties":{"url":{"type":"string"},"exec":{"type":"object","properties":{"bash":{"type":"string"}}}}}`,
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "fetch_page (read-verb) declares a nested `bash` property inside an `exec` object",
	},

	// ── TN: exec/run-verb tools legitimately accept command/shell args ──────

	{
		ID:               "MCP-TN-2825-001",
		ToolName:         "invoke_workflow",
		InputSchema:      `{"type":"object","properties":{"command":{"type":"string"}}}`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "invoke_workflow (exec-verb) legitimately declares a `command` property — not a read-verb, must not fire",
	},
	{
		ID:               "MCP-TN-2825-002",
		ToolName:         "trigger_pipeline",
		InputSchema:      `{"type":"object","properties":{"shell":{"type":"string"},"args":{"type":"array"}}}`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "trigger_pipeline (exec-verb) legitimately declares a `shell` property",
	},

	// ── TN: compound/handle names on read-verb tools — not the raw material ─

	{
		ID:               "MCP-TN-2825-003",
		ToolName:         "get_command_history",
		InputSchema:      `{"type":"object","properties":{"cmd_history":{"type":"string"}}}`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "get_command_history declares `cmd_history` (compound, not exact `cmd`) — must not fire",
	},
	{
		ID:               "MCP-TN-2825-004",
		ToolName:         "list_commands",
		InputSchema:      `{"type":"object","properties":{"command_filter":{"type":"string"}}}`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "list_commands declares `command_filter` (compound, not exact `command`) — must not fire",
	},

	// ── TN: broader exec/shell family intentionally NOT flagged at schema layer ─

	{
		ID:               "MCP-TN-2825-005",
		ToolName:         "search_code",
		InputSchema:      `{"type":"object","properties":{"code":{"type":"string"}}}`,
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-desc-schema-read-verb-command-sink",
		Description:      "search_code declares `code` — deliberately excluded from the tight scope; legitimate on code-search readers",
	},
}
