// Hand-curated MCP test scenarios for issue #3171:
// "SharedRoot" (Accomplish AI, disclosed 2026-07-23, CVE-2026-46331) —
// Claude Cowork's local execution VM bind-shares the entire host filesystem
// read-write into the guest at one VirtioFS mount, /mnt/.virtiofs-root.
//
// Rule covered:
//   mcp-privesc-audit-cowork-virtiofs-host-share-access (AUDIT — file-access
//   tool families reaching the /mnt/.virtiofs-root/** mount path)

package scenarios

var CoworkVirtioFSHostShareScenarios3171 = []Scenario{
	// TP paths deliberately avoid ~/.ssh, ~/.aws, and browser credential-store
	// paths — those already BLOCK via more specific existing rules
	// (mcp-sec-block-ssh-private-key-read, mcp-sec-block-aws-access,
	// mcp-struct-block-credential-path-access), and the combiner's
	// most_restrictive_wins would report BLOCK for the whole call, not this
	// rule's own AUDIT. These paths isolate the overshare signal itself.
	{
		ID:               "MCP-TP-3171-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/mnt/.virtiofs-root/Users/user/Documents/quarterly-report.pdf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "read_file reaches the Cowork VirtioFS host-share mount — a contained guest reading a host document through the overshared root, the SharedRoot escape primitive",
	},
	{
		ID:               "MCP-TP-3171-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/mnt/.virtiofs-root/Users/user/Desktop/build-notes.txt", "content": "hello"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "write_file reaches the VirtioFS host-share mount — writing to the host desktop through the overshared root",
	},
	{
		ID:               "MCP-TP-3171-003",
		ToolName:         "cat_file",
		Arguments:        map[string]interface{}{"path": "/mnt/.virtiofs-root/Users/victim/Downloads/invoice.pdf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "cat_file reaches the VirtioFS host-share mount — reading another user's downloaded file through the overshared root",
	},
	// TN: ordinary workspace path, no VirtioFS mount reference
	{
		ID:               "MCP-TN-3171-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "read_file on an ordinary workspace path — must NOT trigger the VirtioFS host-share rule",
	},
	// TN: different /mnt subpath that is not the VirtioFS overshare mount
	{
		ID:               "MCP-TN-3171-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/mnt/data/report.csv"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "read_file under an unrelated /mnt/data mount — must NOT match the /mnt/.virtiofs-root glob (guards against over-broad /mnt/* matching)",
	},
	// TN: write to an ordinary project file
	{
		ID:               "MCP-TN-3171-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/user/workspace/notes.md", "content": "meeting notes"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-audit-cowork-virtiofs-host-share-access",
		Description:      "write_file to an ordinary project path — must NOT trigger the VirtioFS host-share rule",
	},
}
