package scenarios

// Issue #2729 — Zip Slip: archive extraction with path traversal in destination.
// Rules: mcp-sc-block-archive-extract-traversal-destination (BLOCK)
//        mcp-sc-block-archive-extract-traversal-output-dir (BLOCK)
//
// Both rules are in packs/premium/mcp/mcp-supply-chain-premium.yaml.
// Each fires when the archive extraction tool call contains '..' in the
// destination or output_dir argument respectively.

// ArchiveExtractionZipSlipScenarios2729 covers Zip Slip path traversal detection.
var ArchiveExtractionZipSlipScenarios2729 = []Scenario{

	// ── TPs: destination argument contains path traversal '..' ────────────────

	{
		ID:               "MCP-TP-2729-001",
		ToolName:         "extract_zip",
		Arguments:        map[string]interface{}{"archive": "/workspace/download.zip", "destination": "../../.ssh/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "extract_zip with '..' in destination — Zip Slip traversal to .ssh; must BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TP-2729-002",
		ToolName:         "unzip_file",
		Arguments:        map[string]interface{}{"file": "release.zip", "destination": "../../../etc/cron.d/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "unzip_file with traversal destination to etc/cron.d — path traversal backdoor install; must BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TP-2729-003",
		ToolName:         "decompress_archive",
		Arguments:        map[string]interface{}{"source": "/tmp/package.tar.gz", "destination": "../../home/victim/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "decompress_archive with '..' destination targeting user home — Zip Slip to home directory; must BLOCK (issue #2729).",
	},

	// ── TPs: output_dir argument contains path traversal '..' ─────────────────

	{
		ID:               "MCP-TP-2729-004",
		ToolName:         "extract_archive",
		Arguments:        map[string]interface{}{"source": "/tmp/release.tar.gz", "output_dir": "../../home/user/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "extract_archive with '..' in output_dir — path traversal to user home; must BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TP-2729-005",
		ToolName:         "decompress_file",
		Arguments:        map[string]interface{}{"archive": "package.zip", "output_dir": "../../../etc/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "decompress_file with '../..' in output_dir targeting /etc — etc directory traversal; must BLOCK (issue #2729).",
	},

	// ── TNs: legitimate extraction with clean destination paths ───────────────

	{
		ID:               "MCP-TN-2729-001",
		ToolName:         "extract_zip",
		Arguments:        map[string]interface{}{"archive": "/workspace/project.zip", "destination": "/workspace/output/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "extract_zip with absolute destination path — no traversal, should NOT BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TN-2729-002",
		ToolName:         "extract_archive",
		Arguments:        map[string]interface{}{"path": "/workspace/deps.tar.gz", "destination": "/app/build/vendor/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "extract_archive to /app/build/vendor — legitimate vendor extraction, no traversal; must NOT BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TN-2729-003",
		ToolName:         "extract_archive",
		Arguments:        map[string]interface{}{"source": "/workspace/archive.tar.gz", "output_dir": "/workspace/extracted/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "extract_archive with clean output_dir — no '..' in path; must NOT BLOCK (issue #2729).",
	},
	{
		ID:               "MCP-TN-2729-004",
		ToolName:         "unzip_file",
		Arguments:        map[string]interface{}{"file": "/tmp/tools.zip", "output_dir": "/usr/local/share/tools/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "agent-archive-extraction-path-traversal",
		Description:      "unzip_file to /usr/local/share/tools — legitimate tool install path, no traversal; must NOT BLOCK (issue #2729).",
	},
}
