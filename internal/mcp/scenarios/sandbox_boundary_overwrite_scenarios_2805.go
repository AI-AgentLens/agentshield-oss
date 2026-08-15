// Hand-curated MCP test scenarios for DuneSlide-class sandbox enforcement
// boundary overwrite. Issue #2805.
//
// Rules tested:
//   mcp-ide-trust-audit-scope-widen-workdir-system-path  — working_directory redirected to a system path (AUDIT)
//   mcp-ide-trust-audit-scope-widen-cwd-system-path       — cwd redirected to a system path (AUDIT)
//   mcp-ide-trust-block-sandbox-enforcement-artifact-write — write targets a sandbox enforcement artifact (BLOCK)
//
// The composite two-call chain (mcp-ide-trust-block-sandbox-boundary-widen-then-overwrite-chain)
// is a session-level sequence rule and cannot be expressed as a single-call
// scenario here — it is validated by TestMCPSequenceRule_SandboxBoundaryWidenThenOverwrite
// in internal/mcp/sequence_rule_test.go.
//
// DuneSlide (CVE-2026-50548/CVE-2026-50549, Cato Networks, 2026-07-01, CVSS 9.8):
// a sandbox trusts a self-declared working_directory/cwd tool-call parameter to
// expand its write-allowlist without validating it against a fixed project root.
// Indirect prompt injection redirects that parameter to a system path, then a
// subsequent write overwrites the sandbox's own enforcement binary/policy file —
// disabling containment for the rest of the session, not just one command.
package scenarios

// SandboxBoundaryOverwriteScenarios2805 covers DuneSlide-class working_directory
// scope-widening and sandbox enforcement artifact writes.
var SandboxBoundaryOverwriteScenarios2805 = []Scenario{

	// ── TP: working_directory redirected to a system path (AUDIT) ────────────

	{
		ID:               "MCP-TP-2805-001",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "notes.txt", "working_directory": "/usr/lib/cursor-sandbox", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ide-trust-audit-scope-widen-workdir-system-path",
		Description:      "create_file with working_directory redirected to /usr/lib/cursor-sandbox — Stage 1 boundary-redefinition of a DuneSlide-class sandbox bypass",
	},
	{
		ID:               "MCP-TP-2805-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "notes.txt", "working_directory": "/opt/ide/sandbox-enforcer", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ide-trust-audit-scope-widen-workdir-system-path",
		Description:      "write_file with working_directory redirected to /opt/ide/sandbox-enforcer — a file-write tool scope widened to a system path",
	},

	// ── TP: cwd redirected to a system path (AUDIT) ───────────────────────────

	{
		ID:               "MCP-TP-2805-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "notes.txt", "cwd": "/etc/cursor", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ide-trust-audit-scope-widen-cwd-system-path",
		Description:      "str_replace_editor with cwd redirected to /etc/cursor — the cwd-keyed twin of the working_directory scope-widen rule",
	},
	{
		ID:               "MCP-TP-2805-004",
		ToolName:         "save_file",
		Arguments:        map[string]interface{}{"path": "notes.txt", "cwd": "/Applications/Cursor.app/Contents/Resources", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ide-trust-audit-scope-widen-cwd-system-path",
		Description:      "save_file with cwd redirected into the Cursor.app bundle — a system-path scope widen via cwd",
	},

	// ── TP: write to sandbox enforcement artifact (BLOCK) ─────────────────────

	{
		ID:               "MCP-TP-2805-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/usr/lib/cursor-sandbox/enforcer.so", "content": "patched"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "write_file overwriting a sandbox enforcement shared library under /usr/lib — Stage 2 enforcement self-destruction of a DuneSlide-class attack",
	},
	{
		ID:               "MCP-TP-2805-006",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/opt/ide/sandbox-enforcer", "content": "patched"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "edit_file overwriting a sandbox enforcement binary under /opt — never a legitimate agent workflow",
	},
	{
		ID:               "MCP-TP-2805-007",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "/Applications/Cursor.app/Contents/Resources/app/out/sandbox.sb", "content": "(allow default)"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "str_replace_editor overwriting a macOS sandbox-exec .sb profile inside the Cursor.app bundle",
	},

	// ── TN: normal working directories inside the project root (AUDIT/ALLOW) ─

	{
		ID:               "MCP-TN-2805-001",
		ToolName:         "create_file",
		Arguments:        map[string]interface{}{"path": "notes.txt", "working_directory": "/workspace/project", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-audit-scope-widen-workdir-system-path",
		Description:      "create_file scoped to the project's own working directory — must not be flagged",
	},
	{
		ID:               "MCP-TN-2805-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "README.md", "content": "docs"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-audit-scope-widen-workdir-system-path",
		Description:      "write_file with no working_directory argument at all — absent arg must not satisfy the predicate",
	},
	{
		ID:               "MCP-TN-2805-003",
		ToolName:         "str_replace_editor",
		Arguments:        map[string]interface{}{"path": "notes.txt", "cwd": "/workspace/project", "content": "x"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-audit-scope-widen-cwd-system-path",
		Description:      "str_replace_editor scoped to the project's own cwd — must not be flagged",
	},

	// ── TN: writes naming "sandbox" outside any IDE install root (AUDIT) ──────

	{
		ID:               "MCP-TN-2805-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/tests/sandbox/test_runner.py", "content": "def test(): pass"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "write to a project's own tests/sandbox/ directory — 'sandbox' in the path but not under an IDE install root; must not be blocked",
	},
	{
		ID:               "MCP-TN-2805-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/home/dev/repo/docs/sandboxing.md", "content": "# Sandbox architecture"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "documentation file discussing sandboxing, in the project's own docs/ directory — must not be blocked",
	},
	{
		ID:               "MCP-TN-2805-006",
		ToolName:         "edit_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/src/sandbox-utils.js", "content": "export const x = 1;"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ide-trust-block-sandbox-enforcement-artifact-write",
		Description:      "project source file named sandbox-utils.js — outside any IDE install root; must not be blocked",
	},
}
