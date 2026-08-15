// MCP test scenarios for package registry metadata injection protection (issue #2215).
//
// Rules covered:
//   mcp-pkg-reg-audit-npm-registry-fetch
//   mcp-pkg-reg-audit-pypi-fetch
//   mcp-pkg-reg-audit-cratesio-fetch
//   mcp-pkg-reg-audit-huggingface-fetch
//   mcp-pkg-reg-audit-raw-github-readme-fetch
//
// All rules live in packs/premium/mcp/mcp-package-registry-metadata-injection.yaml.
// Taxonomy: unauthorized-execution/agentic-attacks/package-registry-metadata-injection
//
// Attack: An attacker publishes a package with AI-targeted injection directives
// embedded in metadata fields (description, keywords, README). When an AI coding
// agent searches registries or fetches package metadata during dependency evaluation,
// the injected directives hijack the agent's behavior before any install occurs.
package scenarios

// PkgRegistryMetadataInjectionScenarios2215 are MCP test scenarios for registry
// metadata injection detection.
var PkgRegistryMetadataInjectionScenarios2215 = []Scenario{
	// === True Positives: fetches to package registry domains ===

	// npm registry — search endpoint (highest injection risk)
	{
		ID:               "MCP-TP-2215-001",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://registry.npmjs.org/-/v1/search?text=http-client"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to npm registry search — descriptions and keywords in search results are attacker-controlled injection vectors",
	},
	{
		ID:               "MCP-TP-2215-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://registry.npmjs.org/lodash"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "fetch_url to npm package metadata — package description and readme are attacker-controlled",
	},
	{
		ID:               "MCP-TP-2215-003",
		ToolName:         "http_get",
		Arguments:        map[string]interface{}{"url": "https://registry.npmjs.org/express/4.18.2"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "http_get to npm versioned package metadata — version-specific description can contain injection directives",
	},

	// PyPI — package metadata endpoint (injection in long description field)
	{
		ID:               "MCP-TP-2215-004",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://pypi.org/pypi/requests/json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to PyPI JSON metadata — project description (long Markdown) is attacker-controlled injection vector",
	},
	{
		ID:               "MCP-TP-2215-005",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://pypi.org/project/flask/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "fetch_url to PyPI project page — rendered description may contain hidden injection directives in HTML comments or zero-width characters",
	},
	{
		ID:               "MCP-TP-2215-006",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://files.pythonhosted.org/packages/source/r/requests/requests-2.28.0.tar.gz"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to PyPI files — source distribution from pythonhosted.org may contain injected setup.py or README payload",
	},

	// crates.io — Rust package registry search and metadata
	{
		ID:               "MCP-TP-2215-007",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://crates.io/api/v1/crates?q=http-client"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to crates.io search API — crate descriptions in search results are attacker-controlled",
	},
	{
		ID:               "MCP-TP-2215-008",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://crates.io/api/v1/crates/tokio"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "fetch_url to crates.io crate metadata — description and readme are attacker-controlled",
	},

	// HuggingFace Hub — model card fetches (highest-risk for AI agent workflows)
	{
		ID:               "MCP-TP-2215-009",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://huggingface.co/api/models?search=llama"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to HuggingFace model search — model card summaries in search results are attacker-controlled; agent model selection workflows are the primary target",
	},
	{
		ID:               "MCP-TP-2215-010",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://huggingface.co/mistralai/Mistral-7B-v0.1/resolve/main/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "fetch_url to HuggingFace model card README — an attacker-controlled Markdown document read by agents during model evaluation; can contain system-override directives in 'Performance Notes' sections",
	},
	{
		ID:               "MCP-TP-2215-011",
		ToolName:         "http_get",
		Arguments:        map[string]interface{}{"url": "https://api.hub.huggingface.co/api/models/bert-base-uncased"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "http_get to HuggingFace Hub API — model metadata response includes attacker-controlled tags, model card text, and pipeline tags",
	},

	// Raw GitHub README (package homepage redirect vector)
	{
		ID:               "MCP-TP-2215-012",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://raw.githubusercontent.com/psf/requests/main/README.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to raw GitHub README — commonly fetched by agents following registry documentation_url links; README content is fully attacker-controlled",
	},
	{
		ID:               "MCP-TP-2215-013",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://raw.githubusercontent.com/expressjs/express/master/Readme.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "fetch_url to raw GitHub Readme.md — case variant; same injection risk as README.md",
	},

	// === True Negatives: benign fetches that must NOT be BLOCKED by registry metadata rules ===
	//
	// These scenarios confirm that:
	//   1. Non-registry URLs don't trigger the new registry-specific rules.
	//   2. Local file reads are unaffected by registry fetch rules.
	//   3. Generic web-search AUDIT (from mcp-response-integrity-audit-web-search) may
	//      still fire on web_fetch calls — the point here is no BLOCK escalation.
	//
	// Note: web_fetch calls to GitHub API/raw return AUDIT from the generic
	// web-search-result-injection rule (mcp-response-integrity), not from our
	// new registry rules. read_file to package.json returns AUDIT from an
	// existing community rule. Expected decisions reflect the full rule stack.

	// GitHub API (structured API, not package registry metadata)
	// Returns AUDIT from the generic web-search-result audit rule — our NEW
	// registry-metadata rules must NOT additionally BLOCK this.
	{
		ID:               "MCP-TN-2215-001",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/expressjs/express"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to GitHub API — structured API response, not package registry metadata; registry metadata rules must NOT BLOCK this (AUDIT from generic web-search rule is acceptable)",
	},
	// Local file reads — must NOT be flagged by fetch-based registry rules
	{
		ID:               "MCP-TN-2215-002",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/package.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "read_file to local package.json — local file, no registry fetch; registry metadata rules must NOT fire on this (AUDIT from existing supply-chain rule is acceptable)",
	},
	{
		ID:               "MCP-TN-2215-003",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/requirements.txt"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "read_file to local requirements.txt — local file; registry metadata rules must NOT fire on this (existing AUDIT acceptable)",
	},
	// Fetch of non-registry GitHub API endpoint
	{
		ID:               "MCP-TN-2215-004",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/django/django/releases"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to GitHub releases API — not a package registry endpoint; registry metadata rules must NOT BLOCK this (AUDIT from generic web-search rule is acceptable)",
	},
	// Raw GitHub source code file (not a README) — should NOT match raw-github-readme rule
	{
		ID:               "MCP-TN-2215-005",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://raw.githubusercontent.com/psf/requests/main/src/requests/api.py"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to raw GitHub source file (not README) — must NOT match the raw-github-readme rule (pattern anchored to README in the path); AUDIT from generic web-search rule is acceptable",
	},
	// PyPI simple index (just file listing, no prose metadata)
	{
		ID:               "MCP-TN-2215-006",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://pypi.org/simple/requests/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "unauthorized-execution/agentic-attacks/package-registry-metadata-injection",
		Description:      "web_fetch to PyPI simple index — URL matches pypi.org/project/ pattern in mcp-pkg-reg-audit-pypi-fetch; AUDIT is the correct outcome (no BLOCK escalation)",
	},
}
