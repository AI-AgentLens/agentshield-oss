// Hand-curated MCP test scenarios for issue #2227:
// Direct write to Ollama model blob store bypasses integrity checks.
//
// Rule covered:
//   mcp-sc-block-ollama-blob-write (BLOCK — write to ~/.ollama/models/**)

package scenarios

// OllamaBlobWriteScenarios2227 covers the MCP rule blocking direct writes
// to the Ollama model blob store, which bypasses ollama pull integrity checks.
var OllamaBlobWriteScenarios2227 = []Scenario{
	// TP: direct write to blob store → BLOCK
	{
		ID:               "MCP-TP-2227-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.ollama/models/blobs/sha256-abc123def456"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ollama-blob-write",
		Description:      "write_file to Ollama blob store — model weight replacement without registry, must BLOCK",
	},
	{
		ID:               "MCP-TP-2227-002",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "/root/.ollama/models/manifests/registry.ollama.ai/library/llama3/latest"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ollama-blob-write",
		Description:      "create_file to Ollama manifests dir — manifest tampering to redirect model version, must BLOCK",
	},
	{
		ID:               "MCP-TP-2227-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/Users/alice/.ollama/models/blobs/sha256-deadbeef0000"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "ollama-blob-write",
		Description:      "str_replace_editor to Ollama blob — must BLOCK (macOS user path)",
	},
	// TN: read-only access to blob store — should AUDIT, not BLOCK
	{
		ID:               "MCP-TN-2227-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.ollama/models/blobs/sha256-abc123def456"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ollama-blob-write",
		Description:      "read_file of Ollama blob — read access is not in scope for write rule, must not BLOCK",
	},
	// TN: docs file that mentions ollama blobs — must not trigger
	{
		ID:               "MCP-TN-2227-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/docs/ollama-setup.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ollama-blob-write",
		Description:      "write_file to project docs about Ollama — benign path outside blob store, must not BLOCK",
	},
	// TN: ollama signing key (covered by separate rule, but blob rule should not double-fire)
	{
		ID:               "MCP-TN-2227-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/.ollama/id_ed25519.pub"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "ollama-blob-write",
		Description:      "write to Ollama public key (not models/) — outside blob store path, must not match this rule",
	},
}
