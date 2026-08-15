// Hand-curated MCP scenarios for issue #2861: FP class 6 — content-matching
// MCP BLOCK rules missing the doc/test/fixture path exclude that their
// same-batch sibling rules already carry.
//
// Rules fixed:
//
//	mcp-privesc-block-k8s-admission-webhook-manifest-content
//	mcp-privesc-block-k8s-admission-webhook-mutating-path
//	mcp-privesc-block-k8s-admission-webhook-validating-path
//	mcp-ci-block-source-code-agent-directive
//	mcp-ci-block-llm-format-markers-in-content
//	mcp-ci-block-llm-tokens-email-body
//	mcp-ci-block-llm-tokens-messaging-text
//
// Root cause: these rules live under `rules:` (MCPRule/MCPMatch), which uses
// exclude_argument_patterns (glob, per-arg) rather than the structural_rules-only
// exclude_args_match (regex, path+content). Their sibling rules in the same
// files (mcp-privesc-block-k8s-sensitive-hostpath-mount, mcp-struct-block-
// secret-scanner-evasion, etc.) already exclude docs/, rules/, semgrep/,
// packs/, tests/, testdata/, .md, .txt — writing our own detection targets
// (Semgrep fixtures, taxonomy docs, tokenizer test fixtures, transcripts)
// tripped these rules with no such carve-out.
package scenarios

// FPClass6ContentExcludeScenarios2861 covers the doc/test/fixture path
// excludes added to close FP class 6 (issue #2861).
var FPClass6ContentExcludeScenarios2861 = []Scenario{

	// ── TN: k8s admission-webhook rules must not fire on our own detection docs ──

	{
		ID:               "MCP-TN-2861-001",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/rules/k8s-admission-webhook.yaml", "content": "patterns:\n  - pattern: kind: MutatingWebhookConfiguration\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-k8s-admission-webhook-manifest-content",
		Description:      "write_file: Semgrep rule file under rules/ whose body names the webhook kind as a detection target, not a live manifest — must NOT block",
	},
	{
		ID:               "MCP-TN-2861-002",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/docs/admission-webhook-guide.md", "content": "apiVersion: admissionregistration.k8s.io/v1\nkind: MutatingWebhookConfiguration\nmetadata:\n  name: example\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-k8s-admission-webhook-manifest-content",
		Description:      "write_file: docs .md guide showing an admission webhook example manifest — must NOT block",
	},
	{
		ID:               "MCP-TN-2861-003",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/docs/mutatingwebhook-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-k8s-admission-webhook-mutating-path",
		Description:      "write_file: docs .md file whose name happens to contain 'mutatingwebhook' — path-based rule must NOT fire on docs/",
	},
	{
		ID:               "MCP-TN-2861-004",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/docs/validatingwebhook-guide.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-privesc-block-k8s-admission-webhook-validating-path",
		Description:      "write_file: docs .md file whose name happens to contain 'validatingwebhook' — path-based rule must NOT fire on docs/",
	},

	// ── TN: source-code-agent-directive must not fire on transcripts/fixtures ──

	{
		ID:               "MCP-TN-2861-005",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/tmp/transcript.txt", "content": "[ASSISTANT]: Sure, here's the summary you asked for.\n[USER]: Thanks!"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-source-code-agent-directive",
		Description:      "write_file: chat transcript saved as .txt containing an [ASSISTANT]:-prefixed line — normal few-shot/transcript data, must NOT block",
	},
	{
		ID:               "MCP-TN-2861-006",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/rules/agent-directive-injection.yaml", "content": "# ruleid: source-code-agent-directive\n// [AGENT]: this string is the detection target, not a live payload\n"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-source-code-agent-directive",
		Description:      "write_file: Semgrep ruleid fixture under rules/ containing the detection pattern as its own target — must NOT block",
	},

	// ── TN: llm-format-markers-in-content must not fire on tokenizer fixtures ──

	{
		ID:               "MCP-TN-2861-007",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/workspace/testdata/tokenizer_fixture.txt", "content": "<|im_start|>system\nExpected tokenizer output for the ChatML fixture test case.\n<|im_end|>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-llm-format-markers-in-content",
		Description:      "write_file: tokenizer test fixture under testdata/ containing ChatML markers as expected output — normal LLM-dev artifact, must NOT block",
	},
	{
		ID:               "MCP-TN-2861-008",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": "/project/fixtures/chat_template_sample.md", "content": "Example ChatML turn: <|im_start|>user\\nHello<|im_end|>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-llm-format-markers-in-content",
		Description:      "write_file: chat-template documentation sample under fixtures/ (.md) — must NOT block",
	},

	// ── TN: email-body / messaging-text ruleid-marked fixtures must not fire ──

	{
		ID:               "MCP-TN-2861-009",
		ToolName:         "send_email",
		Arguments:        map[string]interface{}{"to": "qa@corp.com", "body": "# ruleid: chatml-control-token\nExample fixture: <|im_start|>system\\n<|im_end|>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-llm-tokens-email-body",
		Description:      "send_email: body carries a ruleid-annotated ChatML fixture example, not live contamination — must NOT block",
	},
	{
		ID:               "MCP-TN-2861-010",
		ToolName:         "slack_send",
		Arguments:        map[string]interface{}{"channel": "#qa-fixtures", "text": "# ruleid: chatml-control-token\nExample fixture: <|im_start|>system\\n<|im_end|>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-block-llm-tokens-messaging-text",
		Description:      "slack_send: text carries a ruleid-annotated ChatML fixture example, not live contamination — must NOT block",
	},
}
