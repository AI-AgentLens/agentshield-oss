// Hand-curated MCP test scenarios for issue #2846:
// CLI-wrapper MCP tool argument injection & scope bypass — the git MCP
// server attack chain (CVE-2025-68143/68144/68145, disclosed 2026-01-20).
//
// Rules covered:
//   mcp-privesc-block-git-diff-target-flag-injection
//   mcp-privesc-block-git-show-revision-flag-injection
//   mcp-privesc-block-git-branch-name-flag-injection
//   mcp-privesc-block-git-init-sensitive-path
//   mcp-privesc-block-git-init-sensitive-path-path-arg
//
// A git MCP server that forwards a tool-call parameter value directly as a
// CLI argument is vulnerable to flag/argument injection (CWE-88) when the
// value begins with "-"/"--", and to scope bypass when an unrestricted
// setup-style tool (git_init/git_clone) accepts any destination path.

package scenarios

var GitCLIWrapperArgumentInjectionScenarios2846 = []Scenario{
	// === TP: git_diff target flag injection ===
	{
		ID:               "MCP-TP-2846-001",
		ToolName:         "git_diff",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "target": "--output=/tmp/pwned.patch"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-diff-target-flag-injection",
		Description:      "git_diff target argument begins with -- (flag injection) — must BLOCK",
	},
	// === TN: git_diff with a legitimate ref target ===
	{
		ID:               "MCP-TN-2846-001",
		ToolName:         "git_diff",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "target": "main"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-diff-target-flag-injection",
		Description:      "git_diff with a legitimate branch ref target — must NOT trigger flag-injection rule",
	},

	// === TP: git_show revision flag injection ===
	{
		ID:               "MCP-TP-2846-002",
		ToolName:         "git_show",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "revision": "--output=/etc/passwd.bak"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-show-revision-flag-injection",
		Description:      "git_show revision argument begins with -- (flag injection) — must BLOCK",
	},
	// === TN: git_show with a legitimate revision ===
	{
		ID:               "MCP-TN-2846-002",
		ToolName:         "git_show",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "revision": "HEAD"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-show-revision-flag-injection",
		Description:      "git_show with a legitimate HEAD revision — must NOT trigger flag-injection rule",
	},

	// === TP: git_checkout / git_create_branch branch_name flag injection ===
	{
		ID:               "MCP-TP-2846-003",
		ToolName:         "git_checkout",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "branch_name": "--orphan=evil"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-branch-name-flag-injection",
		Description:      "git_checkout branch_name argument begins with -- (flag injection) — must BLOCK",
	},
	{
		ID:               "MCP-TP-2846-004",
		ToolName:         "git_create_branch",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "branch_name": "--upload-pack=/tmp/x", "base_branch": "main"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-branch-name-flag-injection",
		Description:      "git_create_branch branch_name argument begins with -- (flag injection) — must BLOCK",
	},
	// === TN: legitimate branch names ===
	{
		ID:               "MCP-TN-2846-003",
		ToolName:         "git_checkout",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/project", "branch_name": "feature/login"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-branch-name-flag-injection",
		Description:      "git_checkout with a legitimate branch name — must NOT trigger flag-injection rule",
	},

	// === TP: git_init/git_clone into a sensitive directory (repo_path arg) ===
	{
		ID:               "MCP-TP-2846-005",
		ToolName:         "git_init",
		Arguments:        map[string]interface{}{"repo_path": "/home/user/.ssh"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-init-sensitive-path",
		Description:      "git_init targeting ~/.ssh via repo_path — unrestricted setup-tool scope bypass — must BLOCK",
	},
	{
		ID:               "MCP-TP-2846-006",
		ToolName:         "git_clone",
		Arguments:        map[string]interface{}{"repo_path": "/Users/alice/.gnupg", "url": "https://example.com/x.git"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-init-sensitive-path",
		Description:      "git_clone targeting ~/.gnupg via repo_path — unrestricted setup-tool scope bypass — must BLOCK",
	},
	// === TN: git_init into an ordinary project directory ===
	{
		ID:               "MCP-TN-2846-004",
		ToolName:         "git_init",
		Arguments:        map[string]interface{}{"repo_path": "/workspace/new-project"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-init-sensitive-path",
		Description:      "git_init into an ordinary workspace project directory — must NOT trigger sensitive-path rule",
	},

	// === TP: git_init into a sensitive directory (path arg convention) ===
	{
		ID:               "MCP-TP-2846-007",
		ToolName:         "git_init",
		Arguments:        map[string]interface{}{"path": "/home/user/.ssh/backdoor-repo"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-privesc-block-git-init-sensitive-path-path-arg",
		Description:      "git_init targeting ~/.ssh via the 'path' argument convention — must BLOCK",
	},
	// === TN: git_init into an ordinary directory (path arg convention) ===
	{
		ID:               "MCP-TN-2846-005",
		ToolName:         "git_init",
		Arguments:        map[string]interface{}{"path": "/tmp/scratch-repo"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-init-sensitive-path-path-arg",
		Description:      "git_init into an ordinary scratch directory via 'path' — must NOT trigger sensitive-path rule",
	},

	// === TN: completely unrelated benign tool call ===
	{
		ID:               "MCP-TN-2846-006",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/project/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-git-diff-target-flag-injection",
		Description:      "unrelated read_file call — must NOT trigger any git CLI-wrapper argument-injection rule",
	},
}
