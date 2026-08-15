// Hand-curated MCP test scenarios for browser-agent web-security-disabled
// launch configuration. Issue #3358/#3359 (taxonomy addition), rule PR
// following #3107.
//
// Rules tested:
//   mcp-browser-hijack-block-web-security-disabled-launch — launchOptions
//     argument containing a Chromium SOP/CSP-disabling flag (BLOCK)
//   mcp-browser-hijack-block-bypass-csp-context — bypassCSP=true context
//     option (BLOCK)
//   mcp-browser-hijack-block-ignore-https-errors-context — ignoreHTTPSErrors
//     =true context option (BLOCK)
//
// Attack vector:
//   A browser-agent MCP tool call (puppeteer_navigate's official
//   launchOptions/allowDangerous arguments, or an equivalent launch/
//   context-creation tool) disables the browser's same-origin-policy or
//   content-security-policy enforcement. This removes the origin boundary
//   that keeps cross-origin content — including hidden authenticated
//   iframes — out of the agent's perception context, the config
//   precondition for a same-origin-policy-collapse prompt-injection chain.
//
// Precision boundary:
//   Launch/context calls without the dangerous flag/option present must NOT
//   fire — argument_regex_patterns requires the key to be present, so a
//   plain navigate call with no launchOptions/bypassCSP/ignoreHTTPSErrors
//   argument at all is unaffected.

package scenarios

// BrowserWebSecurityDisabledScenarios3358 covers BLOCK of browser-agent MCP
// tool calls that disable same-origin-policy/CSP enforcement.
var BrowserWebSecurityDisabledScenarios3358 = []Scenario{

	// ── TP: launchOptions carrying a SOP/CSP-disabling Chromium flag (BLOCK) ──

	{
		ID:               "MCP-TP-3358-001",
		ToolName:         "puppeteer_navigate",
		Arguments:        map[string]interface{}{"url": "https://example.com", "launchOptions": map[string]interface{}{"args": []interface{}{"--disable-web-security", "--disable-site-isolation-trials"}}, "allowDangerous": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "puppeteer_navigate: official launchOptions.args carries --disable-web-security and --disable-site-isolation-trials — must BLOCK",
	},
	{
		ID:               "MCP-TP-3358-002",
		ToolName:         "browser_launch",
		Arguments:        map[string]interface{}{"launchOptions": map[string]interface{}{"headless": false, "args": []interface{}{"--disable-web-security"}}},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "browser_launch: launchOptions.args carries --disable-web-security — must BLOCK",
	},
	{
		ID:               "MCP-TP-3358-003",
		ToolName:         "playwright_launch",
		Arguments:        map[string]interface{}{"launchOptions": `{"args": ["--disable-features=IsolateOrigins,site-per-process"]}`},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "playwright_launch: stringified launchOptions carries --disable-features=IsolateOrigins,site-per-process — must BLOCK",
	},

	// ── TP: bypassCSP=true context option (BLOCK) ──

	{
		ID:               "MCP-TP-3358-004",
		ToolName:         "new_context",
		Arguments:        map[string]interface{}{"bypassCSP": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-bypass-csp-context",
		Description:      "new_context: bypassCSP=true — must BLOCK",
	},
	{
		ID:               "MCP-TP-3358-005",
		ToolName:         "browser_new_context",
		Arguments:        map[string]interface{}{"bypassCSP": true, "userAgent": "Mozilla/5.0"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-bypass-csp-context",
		Description:      "browser_new_context: bypassCSP=true alongside a benign userAgent arg — must BLOCK",
	},

	// ── TP: ignoreHTTPSErrors=true context option (BLOCK) ──

	{
		ID:               "MCP-TP-3358-006",
		ToolName:         "new_context",
		Arguments:        map[string]interface{}{"ignoreHTTPSErrors": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-ignore-https-errors-context",
		Description:      "new_context: ignoreHTTPSErrors=true — must BLOCK",
	},
	{
		ID:               "MCP-TP-3358-007",
		ToolName:         "create_context",
		Arguments:        map[string]interface{}{"ignoreHTTPSErrors": true, "viewport": map[string]interface{}{"width": 1280, "height": 720}},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-browser-hijack-block-ignore-https-errors-context",
		Description:      "create_context: ignoreHTTPSErrors=true alongside a benign viewport arg — must BLOCK",
	},

	// ── TN: launch/context calls without the dangerous flag/option ──

	{
		ID:               "MCP-TN-3358-001",
		ToolName:         "puppeteer_navigate",
		Arguments:        map[string]interface{}{"url": "https://example.com", "launchOptions": map[string]interface{}{"headless": true}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "puppeteer_navigate: launchOptions present but no dangerous flag — must NOT trigger the launch-flag rule",
	},
	{
		ID:               "MCP-TN-3358-002",
		ToolName:         "browser_launch",
		Arguments:        map[string]interface{}{"launchOptions": map[string]interface{}{"args": []interface{}{"--start-maximized"}}},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "browser_launch: launchOptions.args has an unrelated flag — must NOT trigger the launch-flag rule",
	},
	{
		ID:               "MCP-TN-3358-003",
		ToolName:         "browser_navigate",
		Arguments:        map[string]interface{}{"url": "https://example.com"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-web-security-disabled-launch",
		Description:      "browser_navigate: no launchOptions/bypassCSP/ignoreHTTPSErrors argument at all — must NOT trigger any of the three rules",
	},
	{
		ID:               "MCP-TN-3358-004",
		ToolName:         "new_context",
		Arguments:        map[string]interface{}{"bypassCSP": false},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-bypass-csp-context",
		Description:      "new_context: bypassCSP explicitly false — must NOT trigger",
	},
	{
		ID:               "MCP-TN-3358-005",
		ToolName:         "create_context",
		Arguments:        map[string]interface{}{"userAgent": "Mozilla/5.0"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-bypass-csp-context",
		Description:      "create_context: no bypassCSP key at all — must NOT trigger",
	},
	{
		ID:               "MCP-TN-3358-006",
		ToolName:         "new_context",
		Arguments:        map[string]interface{}{"ignoreHTTPSErrors": false},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-browser-hijack-block-ignore-https-errors-context",
		Description:      "new_context: ignoreHTTPSErrors explicitly false — must NOT trigger",
	},
}
