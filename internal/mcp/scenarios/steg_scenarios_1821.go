// Curated MCP scenarios for issue #1821: invisible Unicode steganography in file writes.
// Tests the mcp-content-audit-invisible-unicode-write rule in
// packs/premium/mcp/mcp-content-integrity.yaml.

package scenarios

// SteganographyScenarios1821 contains TP and TN test scenarios for the
// mcp-content-audit-invisible-unicode-write rule (premium/mcp/mcp-content-integrity.yaml).
var SteganographyScenarios1821 = []Scenario{

	// TP: write_file with zero-width space (U+200B) in content — must AUDIT
	{
		ID:       "MCP-TP-1737",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/project/utils.py",
			"content": "def process():\u200b\n    pass",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "write_file with U+200B zero-width space in content — steganographic exfil marker, must AUDIT (issue #1821)",
	},

	// TP: create_file with zero-width non-joiner (U+200C) mid-content — must AUDIT
	{
		ID:       "MCP-TP-1738",
		ToolName: "create_file",
		Arguments: map[string]interface{}{
			"path":    "/workspace/README.md",
			"content": "# Project\u200chidden directive embedded in readme",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "create_file with U+200C zero-width non-joiner mid-content — steganographic use, must AUDIT (issue #1821)",
	},

	// TP: append_file with zero-width joiner (U+200D) in content — must AUDIT
	{
		ID:       "MCP-TP-1739",
		ToolName: "append_file",
		Arguments: map[string]interface{}{
			"path":    "/project/output.txt",
			"content": "normal text\u200dhidden-payload",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "append_file with U+200D zero-width joiner in content — steganographic covert channel, must AUDIT (issue #1821)",
	},

	// TP: str_replace_editor with word joiner (U+2060) — must AUDIT
	{
		ID:       "MCP-TP-1740",
		ToolName: "str_replace_editor",
		Arguments: map[string]interface{}{
			"path":    "/project/main.go",
			"content": "package main\u2060\n\nfunc main() {}",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "str_replace_editor with U+2060 word joiner in content — invisible to code review, must AUDIT (issue #1821)",
	},

	// TN: write_file with clean ASCII content — must NOT trigger
	{
		ID:       "MCP-TN-1737",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/project/utils.py",
			"content": "def process():\n    pass\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "write_file with normal ASCII content — no invisible chars, rule must not fire (issue #1821)",
	},

	// TN: write_file describing zero-width chars as ASCII text (no actual chars) — must NOT trigger
	{
		ID:       "MCP-TN-1738",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/docs/unicode-guide.md",
			"content": "Use zero-width space (U+200B) sparingly in HTML for word-break hints.",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-content-audit-invisible-unicode-write",
		Description:      "write_file describing zero-width chars by name only — no actual invisible chars, must not trigger (issue #1821)",
	},
}
