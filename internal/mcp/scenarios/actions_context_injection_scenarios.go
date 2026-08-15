// Hand-curated MCP test scenarios for the GitHub Actions untrusted-context
// shell-injection rule (mcp-sc-block-actions-untrusted-context-injection).
//
// Attack vector:
//   GitHub Actions interpolates ${{ <expression> }} into a workflow's
//   `run:` block BEFORE the runner shell parses it. When the expression
//   value is attacker-controlled (PR title, issue body, comment text,
//   commit message, branch name) and the expression appears unquoted-
//   from-shell-perspective inside `run:`, an attacker who can name a PR
//   or post a comment can inject shell commands that execute on the
//   runner with GITHUB_TOKEN and any repository/org secrets exposed
//   to the workflow. CWE-1336.
//
// Rule under test:
//   mcp-sc-block-actions-untrusted-context-injection (BLOCK)
//
// TP set: writes/edits to .github/workflows/*.yml whose content contains
// a `run:` step that interpolates an untrusted github.event.* / head_ref
// expression preceded by a shell metacharacter or builtin.
//
// TN set: the safe env-binding form (`env: TITLE: ${{ ... }}` then
// `run: echo "$TITLE"`); use of trusted contexts (github.repository,
// github.actor, github.sha); use as `with:` action input; documentation
// files outside .github/workflows; workflow files with no untrusted-
// context interpolation.

package scenarios

// ActionsContextInjectionScenarios covers GitHub Actions untrusted-context
// shell injection (CWE-1336) detection at the MCP write boundary.
var ActionsContextInjectionScenarios = []Scenario{

	// ── TP: Same-line run: with untrusted context (BLOCK) ────────────────────

	{
		ID:       "MCP-TP-ACTIONS-CTX-INJECT-001",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/project/.github/workflows/pr-comment.yml",
			"content": "on: pull_request\njobs:\n  greet:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"Hello, ${{ github.event.pull_request.title }}\"\n",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "PR-title interpolated into run: echo via double-quoted shell context — classic CWE-1336 RCE vector, must BLOCK",
	},
	{
		ID:       "MCP-TP-ACTIONS-CTX-INJECT-002",
		ToolName: "edit_file",
		Arguments: map[string]interface{}{
			"path":    ".github/workflows/issue-triage.yaml",
			"content": "jobs:\n  triage:\n    steps:\n      - run: |\n          echo \"${{ github.event.issue.title }}\"\n          echo \"${{ github.event.issue.body }}\"\n",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Multi-line run: |  block interpolating issue.title and issue.body through echo — must BLOCK",
	},
	{
		ID:       "MCP-TP-ACTIONS-CTX-INJECT-003",
		ToolName: "patch_file",
		Arguments: map[string]interface{}{
			"path":    "/repo/.github/workflows/release.yml",
			"content": "steps:\n  - run: bash -c \"echo ${{ github.event.head_commit.message }}\"\n",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "head_commit.message interpolated into bash -c — attacker-controlled commit message becomes shell, must BLOCK",
	},
	{
		ID:       "MCP-TP-ACTIONS-CTX-INJECT-004",
		ToolName: "write_to_file",
		Arguments: map[string]interface{}{
			"path":    ".github/workflows/comment.yml",
			"content": "steps:\n  - run: |\n      if [ \"${{ github.event.comment.body }}\" = \"/deploy\" ]; then\n        ./scripts/deploy.sh\n      fi\n",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "comment.body inside if-test string compare in run: |  — slash-command bots are a common source of this RCE pattern, must BLOCK",
	},
	{
		ID:       "MCP-TP-ACTIONS-CTX-INJECT-005",
		ToolName: "apply_diff",
		Arguments: map[string]interface{}{
			"path":    "/project/.github/workflows/checkout.yml",
			"content": "steps:\n  - run: git checkout \"${{ github.head_ref }}\"\n",
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "github.head_ref (PR branch name, attacker-controlled) interpolated into git checkout argument — must BLOCK",
	},

	// ── TN: Safe forms (no BLOCK) ────────────────────────────────────────────

	{
		ID:       "MCP-TN-ACTIONS-CTX-INJECT-001",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "/project/.github/workflows/pr-comment.yml",
			"content": "jobs:\n  greet:\n    steps:\n      - env:\n          TITLE: ${{ github.event.pull_request.title }}\n        run: echo \"$TITLE\"\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Safe env-binding form: untrusted context lives in env: not run: — sibling workflow-write rule still AUDITs but injection rule must NOT BLOCK",
	},
	{
		ID:       "MCP-TN-ACTIONS-CTX-INJECT-002",
		ToolName: "edit_file",
		Arguments: map[string]interface{}{
			"path":    ".github/workflows/ci.yml",
			"content": "steps:\n  - run: echo \"Building ${{ github.repository }}@${{ github.sha }} for ${{ github.actor }}\"\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Trusted contexts (repository, sha, actor) — not in the dangerous-set, must NOT BLOCK",
	},
	{
		ID:       "MCP-TN-ACTIONS-CTX-INJECT-003",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    ".github/workflows/label.yml",
			"content": "steps:\n  - uses: actions-ecosystem/action-add-labels@v1\n    with:\n      labels: ${{ github.event.pull_request.title }}\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Untrusted context passed as `with:` action input (env-quoted by runner, not interpolated into shell) — must NOT BLOCK",
	},
	{
		ID:       "MCP-TN-ACTIONS-CTX-INJECT-004",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    "docs/security-actions.md",
			"content": "Avoid: `run: echo \"${{ github.event.pull_request.title }}\"`\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Markdown documentation describing the dangerous pattern — path is excluded, must NOT BLOCK",
	},
	{
		ID:       "MCP-TN-ACTIONS-CTX-INJECT-005",
		ToolName: "write_file",
		Arguments: map[string]interface{}{
			"path":    ".github/workflows/lint.yml",
			"content": "jobs:\n  lint:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: npm ci && npm run lint\n",
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-sc-block-actions-untrusted-context-injection",
		Description:      "Workflow with no github.event interpolation in run: — must NOT BLOCK (sibling AUDIT rule may still fire)",
	},
}
