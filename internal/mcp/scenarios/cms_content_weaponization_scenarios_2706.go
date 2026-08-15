// Hand-curated MCP test scenarios for CMS content weaponization — iframe
// injection and canonical URL redirect poisoning.
// Issue #2706.
//
// New rules tested (packs/premium/mcp/mcp-cms-content-weaponization.yaml):
//   mcp-cms-wep-block-iframe-content         — <iframe src="https://..."> in 'content' (BLOCK)
//   mcp-cms-wep-block-iframe-html            — <iframe src="https://..."> in 'html' (BLOCK)
//   mcp-cms-wep-audit-canonical-url-external — canonical_url set to external URL (AUDIT)
//
// Threat: AI agent under prompt injection publishes CMS content containing
// iframes loading attacker-controlled pages (phishing overlays, drive-by malware,
// clickjacking) or sets canonical_url to redirect search traffic to attacker domain.

package scenarios

// CMSContentWeaponizationScenarios2706 covers iframe injection and redirect
// poisoning rules added to the CMS content weaponization pack (issue #2706).
var CMSContentWeaponizationScenarios2706 = []Scenario{

	// ── mcp-cms-wep-block-iframe-content: <iframe> in 'content' arg ──────

	{
		ID:               "MCP-TP-2706-001",
		ToolName:         "wordpress_create_post",
		Arguments:        map[string]interface{}{"title": "Security Guide", "content": "<h1>Guide</h1><p>Read below.</p><iframe src=\"https://phish.attacker.com/login\" width=\"600\" height=\"400\"></iframe>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "wordpress_create_post with <iframe src='https://...'> in content — must BLOCK (iframe injection)",
	},
	{
		ID:               "MCP-TP-2706-002",
		ToolName:         "ghost_update_post",
		Arguments:        map[string]interface{}{"id": "5d234b7e", "content": "<p>Feature update.</p><iframe src='https://malware.example.com/drive-by' style='display:none'></iframe>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "ghost_update_post with hidden iframe to malware domain in content — must BLOCK",
	},
	{
		ID:               "MCP-TP-2706-003",
		ToolName:         "strapi_create_entry",
		Arguments:        map[string]interface{}{"content": "<div><h2>Download</h2><iframe src=\"https://exploit-kit.io/landing\" frameborder=\"0\"></iframe></div>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "strapi_create_entry with exploit kit iframe in content — must BLOCK",
	},
	{
		ID:               "MCP-TP-2706-004",
		ToolName:         "publish_post",
		Arguments:        map[string]interface{}{"slug": "popular-article", "content": "<iframe src='https://bank.com' style='opacity:0;position:absolute'>clickjack</iframe>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "publish_post with clickjacking iframe overlay in content — must BLOCK",
	},
	{
		ID:               "MCP-TN-2706-001",
		ToolName:         "wordpress_create_post",
		Arguments:        map[string]interface{}{"title": "Video Tutorial", "content": "<h1>Watch</h1><iframe src=\"/embed/video-player?id=123\"></iframe>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "wordpress_create_post with relative-path iframe src (no https://) — iframe-content rule must NOT fire",
	},
	{
		ID:               "MCP-TN-2706-002",
		ToolName:         "ghost_create_post",
		Arguments:        map[string]interface{}{"title": "Product Launch", "content": "<p>We shipped a new feature. Iframes can embed trusted content from your CDN.</p>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-block-iframe-content",
		Description:      "ghost_create_post with prose mentioning iframes, no actual <iframe> tag — must NOT BLOCK",
	},

	// ── mcp-cms-wep-block-iframe-html: <iframe> in 'html' arg ───────────

	{
		ID:               "MCP-TP-2706-005",
		ToolName:         "ghost_update_post",
		Arguments:        map[string]interface{}{"id": "5d234b7e", "html": "<p>Featured article</p><iframe src=\"https://attacker.com/phishing\" width=\"100%\" height=\"500\"></iframe>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-html",
		Description:      "ghost_update_post with phishing iframe in html arg — must BLOCK",
	},
	{
		ID:               "MCP-TP-2706-006",
		ToolName:         "webflow_create_item",
		Arguments:        map[string]interface{}{"collection_id": "abc123", "html": "<div class='body'><h2>Update</h2><iframe src='https://malware.kit.io/payload'></iframe></div>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-html",
		Description:      "webflow_create_item with malware iframe in html arg — must BLOCK",
	},
	{
		ID:               "MCP-TP-2706-007",
		ToolName:         "cms_update_post",
		Arguments:        map[string]interface{}{"id": "post-456", "html": "<article><p>Body.</p></article><iframe src=\"https://exploit.attacker.io\" style=\"display:none\"></iframe>"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-cms-wep-block-iframe-html",
		Description:      "cms_update_post with hidden exploit iframe in html arg — must BLOCK",
	},
	{
		ID:               "MCP-TN-2706-003",
		ToolName:         "ghost_create_post",
		Arguments:        map[string]interface{}{"title": "Monthly Update", "html": "<h1>Summary</h1><p>This month we shipped three features.</p>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-block-iframe-html",
		Description:      "ghost_create_post with clean html, no iframe — iframe-html rule must NOT fire",
	},
	{
		ID:               "MCP-TN-2706-004",
		ToolName:         "webflow_create_item",
		Arguments:        map[string]interface{}{"collection_id": "blog", "html": "<div><h2>Review</h2><p>Iframes can embed trusted content from your CDN.</p></div>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-block-iframe-html",
		Description:      "webflow_create_item with prose mentioning iframes, no <iframe> tag — must NOT BLOCK",
	},

	// ── mcp-cms-wep-audit-canonical-url-external: external canonical_url ─

	{
		ID:               "MCP-TP-2706-008",
		ToolName:         "ghost_update_post",
		Arguments:        map[string]interface{}{"id": "5d234b7e", "canonical_url": "https://phishing.attacker.com/fake-login"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "ghost_update_post setting canonical_url to external phishing domain — must AUDIT",
	},
	{
		ID:               "MCP-TP-2706-009",
		ToolName:         "wordpress_update_post",
		Arguments:        map[string]interface{}{"post_id": 42, "canonical_url": "https://malicious-partner.com/hijacked"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "wordpress_update_post with external canonical_url — must AUDIT",
	},
	{
		ID:               "MCP-TP-2706-010",
		ToolName:         "contentful_update_entry",
		Arguments:        map[string]interface{}{"id": "entry-123", "canonical_url": "https://seo-poison.io/organic-traffic"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "contentful_update_entry setting canonical_url to SEO-poisoning domain — must AUDIT",
	},
	{
		ID:               "MCP-TP-2706-011",
		ToolName:         "cms_publish_post",
		Arguments:        map[string]interface{}{"slug": "popular-article", "canonical_url": "https://attacker.example.org/redirect"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "cms_publish_post with canonical_url external redirect — must AUDIT",
	},
	{
		ID:               "MCP-TN-2706-005",
		ToolName:         "ghost_update_post",
		Arguments:        map[string]interface{}{"id": "5d234b7e", "canonical_url": "/blog/original-article"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "ghost_update_post with relative canonical_url — canonical rule must NOT fire (falls through to cms write AUDIT)",
	},
	{
		ID:               "MCP-TN-2706-006",
		ToolName:         "wordpress_update_post",
		Arguments:        map[string]interface{}{"post_id": 42, "title": "Updated Guide", "content": "<p>Content here.</p>"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-cms-wep-audit-canonical-url-external",
		Description:      "wordpress_update_post with no canonical_url field — canonical rule must NOT fire",
	},
}
