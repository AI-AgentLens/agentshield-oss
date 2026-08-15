// Hand-curated MCP test scenarios for alternative path argument key credential access.
// Issue #2306.
//
// Rules tested:
//   mcp-prem-block-cred-path-file-key     — 'file' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-filepath-key — 'filepath' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-filename-key — 'filename' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-src-key      — 'src' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-source-key   — 'source' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-location-key — 'location' arg key pointing to creds (BLOCK)
//   mcp-prem-block-cred-path-target-key   — 'target' arg key pointing to creds (BLOCK)
//
// Attack vector:
//   The community mcp-struct-block-credential-path-access rule only checks the
//   'path' argument key. MCP servers commonly use alternative argument names for
//   file paths ('file', 'filepath', 'filename', 'src', 'source', 'location', 'target').
//   These bypass the community rule entirely, exposing credentials to exfiltration.

package scenarios

// AltPathArgCredentialScenarios2306 covers alternative path argument key credential access.
var AltPathArgCredentialScenarios2306 = []Scenario{

	// ── TP: 'file' argument key — SSH keys ─────────────────────────────────────

	{
		ID:               "MCP-TP-2306-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"file": "/home/user/.ssh/id_rsa"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-file-key",
		Description:      "read_file with 'file' arg key to .ssh/id_rsa — bypasses community 'path' check, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-002",
		ToolName:         "open_file",
		Arguments:        map[string]interface{}{"file": "/root/.ssh/id_ed25519"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-file-key",
		Description:      "open_file with 'file' arg key to .ssh/id_ed25519 — SSH key via alternative arg name, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-003",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"file": "/home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-file-key",
		Description:      "get_file_contents with 'file' arg to .aws/credentials — cloud credentials via 'file' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-004",
		ToolName:         "load_file",
		Arguments:        map[string]interface{}{"file": "/home/user/.kube/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-file-key",
		Description:      "load_file with 'file' arg to .kube/config — Kubernetes credentials via 'file' key, must BLOCK (#2306)",
	},

	// ── TP: 'filepath' argument key ────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-005",
		ToolName:         "read_document",
		Arguments:        map[string]interface{}{"filepath": "/home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filepath-key",
		Description:      "read_document with 'filepath' arg to .aws/credentials — AWS creds via 'filepath' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-006",
		ToolName:         "process_file",
		Arguments:        map[string]interface{}{"filepath": "/home/user/.ssh/id_rsa"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filepath-key",
		Description:      "process_file with 'filepath' arg to .ssh/id_rsa — SSH key via 'filepath' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-007",
		ToolName:         "get_contents",
		Arguments:        map[string]interface{}{"filepath": "/home/user/.gnupg/secring.gpg"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filepath-key",
		Description:      "get_contents with 'filepath' arg to .gnupg/ — GPG secret key via 'filepath' key, must BLOCK (#2306)",
	},

	// ── TP: 'filename' argument key ────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-008",
		ToolName:         "preview_file",
		Arguments:        map[string]interface{}{"filename": "/root/.kube/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filename-key",
		Description:      "preview_file with 'filename' arg to .kube/config — kubeconfig via 'filename' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-009",
		ToolName:         "download_file",
		Arguments:        map[string]interface{}{"filename": "/home/user/.ssh/id_rsa"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filename-key",
		Description:      "download_file with 'filename' arg to .ssh/id_rsa — SSH key via 'filename' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-010",
		ToolName:         "upload_file",
		Arguments:        map[string]interface{}{"filename": "/home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-filename-key",
		Description:      "upload_file with 'filename' arg to .aws/credentials — AWS creds exfil via 'filename' key, must BLOCK (#2306)",
	},

	// ── TP: 'src' argument key ─────────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-011",
		ToolName:         "copy_doc",
		Arguments:        map[string]interface{}{"src": "/home/user/.aws/credentials", "dst": "/tmp/c"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-src-key",
		Description:      "copy_doc with 'src' arg to .aws/credentials — credential staging via 'src' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-012",
		ToolName:         "link_file",
		Arguments:        map[string]interface{}{"src": "/home/user/.ssh/id_rsa", "link": "/tmp/key"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-src-key",
		Description:      "link_file with 'src' arg to .ssh/id_rsa — SSH key symlink via 'src' key, must BLOCK (#2306)",
	},

	// ── TP: 'source' argument key ──────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-013",
		ToolName:         "transfer_file",
		Arguments:        map[string]interface{}{"source": "/home/user/.ssh/id_rsa", "destination": "/tmp/x"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-source-key",
		Description:      "transfer_file with 'source' arg to .ssh/id_rsa — SSH key transfer via 'source' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-014",
		ToolName:         "backup_file",
		Arguments:        map[string]interface{}{"source": "/home/user/.gnupg/private-keys-v1.d/"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-source-key",
		Description:      "backup_file with 'source' arg to .gnupg/ — GPG private key backup via 'source' key, must BLOCK (#2306)",
	},

	// ── TP: 'location' argument key ────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-015",
		ToolName:         "read_storage",
		Arguments:        map[string]interface{}{"location": "/home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-location-key",
		Description:      "read_storage with 'location' arg to .aws/credentials — AWS creds via 'location' key, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-016",
		ToolName:         "fetch_content",
		Arguments:        map[string]interface{}{"location": "/home/user/.kube/config"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-location-key",
		Description:      "fetch_content with 'location' arg to .kube/config — kubeconfig via 'location' key, must BLOCK (#2306)",
	},

	// ── TP: 'target' argument key ──────────────────────────────────────────────

	{
		ID:               "MCP-TP-2306-017",
		ToolName:         "create_symlink",
		Arguments:        map[string]interface{}{"target": "/home/user/.ssh/id_rsa", "link_name": "/tmp/key"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-target-key",
		Description:      "create_symlink with 'target' arg to .ssh/id_rsa — symlink to SSH key via 'target' key exposes it, must BLOCK (#2306)",
	},
	{
		ID:               "MCP-TP-2306-018",
		ToolName:         "make_link",
		Arguments:        map[string]interface{}{"target": "/home/user/.aws/credentials"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-prem-block-cred-path-target-key",
		Description:      "make_link with 'target' arg to .aws/credentials — hardlink to AWS creds via 'target' key, must BLOCK (#2306)",
	},

	// ── TN: benign paths via alternative arg keys — must NOT block ─────────────

	{
		ID:               "MCP-TN-2306-001",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"file": "/workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-file-key",
		Description:      "read_file with 'file' arg to workspace README — benign project file, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-002",
		ToolName:         "read_document",
		Arguments:        map[string]interface{}{"filepath": "/tmp/output.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-filepath-key",
		Description:      "read_document with 'filepath' arg to /tmp/output.json — benign temp file, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-003",
		ToolName:         "preview_file",
		Arguments:        map[string]interface{}{"filename": "/workspace/src/main.go"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-filename-key",
		Description:      "preview_file with 'filename' arg to workspace source file — benign, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-004",
		ToolName:         "copy_doc",
		Arguments:        map[string]interface{}{"src": "/workspace/build/output.tar.gz", "dst": "/tmp/archive.tar.gz"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-src-key",
		Description:      "copy_doc with 'src' arg to workspace build artifact — benign copy, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-005",
		ToolName:         "transfer_file",
		Arguments:        map[string]interface{}{"source": "/workspace/dist/app.bin", "destination": "/tmp/release.bin"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-source-key",
		Description:      "transfer_file with 'source' arg to workspace dist binary — benign artifact transfer, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-006",
		ToolName:         "read_storage",
		Arguments:        map[string]interface{}{"location": "/workspace/data/config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-location-key",
		Description:      "read_storage with 'location' arg to workspace config — benign project config, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-007",
		ToolName:         "create_symlink",
		Arguments:        map[string]interface{}{"target": "/workspace/dist/latest", "link_name": "/workspace/current"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-target-key",
		Description:      "create_symlink with 'target' arg to workspace dist dir — benign symlink for deployment, must not block (#2306)",
	},
	{
		ID:               "MCP-TN-2306-008",
		ToolName:         "download_file",
		Arguments:        map[string]interface{}{"filename": "/home/user/Documents/report.pdf"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-prem-block-cred-path-filename-key",
		Description:      "download_file with 'filename' arg to user Documents — benign document, must not block (#2306)",
	},
}
