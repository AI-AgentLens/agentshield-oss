// Hand-curated MCP test scenarios for monitoring platform alert prompt injection.
// Issue #2531.
//
// Rules tested:
//   mcp-agentic-audit-monitoring-platform-alert-fetch  — HTTP fetch to monitoring APIs (AUDIT)
//   mcp-ci-audit-monitoring-alert-read                  — file read of alert export files (AUDIT)
//
// Attack vectors:
//   - AI DevOps/SRE agents fetching alert payloads from Datadog, Grafana, PagerDuty,
//     OpsGenie, CloudWatch, New Relic, Dynatrace via MCP HTTP tools
//   - AI agents reading locally-cached monitoring alert JSON exports
//   - Adversarially-crafted metric label values, incident titles, or runbook content
//     embedding agent-directive payloads in the alert data returned by these APIs

package scenarios

// MonitoringPlatformAlertScenarios2531 covers monitoring platform alert prompt injection.
var MonitoringPlatformAlertScenarios2531 = []Scenario{

	// ── TP: HTTP fetch to monitoring platform APIs (AUDIT) ────────────────────

	{
		ID:               "MCP-TP-2531-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.datadoghq.com/api/v1/events?sources=kubernetes", "method": "GET"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_request to Datadog events API — AI SRE agent fetching alert data containing metric labels that may carry injected directives; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://api.pagerduty.com/incidents/P123456"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "fetch_url to PagerDuty incidents API — AI agent retrieving incident payload where title/description may contain injected instructions; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-003",
		ToolName:         "make_request",
		Arguments:        map[string]interface{}{"url": "https://api.opsgenie.com/v2/alerts?status=open"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "make_request to OpsGenie alerts API — AI agent fetching open alerts; alert message field may contain adversarial directives; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-004",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.newrelic.com/v2/alerts_incidents.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_request to New Relic alerts API — AI DevOps agent fetching incident data; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-005",
		ToolName:         "http_get",
		Arguments:        map[string]interface{}{"url": "https://myorg.live.dynatrace.com/api/v2/problems?status=OPEN"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_get to Dynatrace problems API — AI SRE agent fetching problem details; Dynatrace problem titles are externally controlled; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-006",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://logs.us-east-1.amazonaws.com/2014-03-28", "method": "POST"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_request to CloudWatch Logs API — AI agent querying log metric filter alerts that may contain injected directives in structured log fields; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-007",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://api.grafana.com/api/alertmanager/grafana/api/v2/alerts"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "fetch_url to Grafana alertmanager API — AI agent fetching Grafana alerts whose message bodies may contain attacker-controlled content from monitored services; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-008",
		ToolName:         "web_fetch",
		Arguments:        map[string]interface{}{"url": "https://api.victorops.com/api-public/v1/incidents"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "web_fetch to VictorOps incidents API — AI on-call agent retrieving incident payload; must AUDIT",
	},

	// ── TP: File read of monitoring alert export files (AUDIT) ───────────────

	{
		ID:               "MCP-TP-2531-101",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/pagerduty-incident-P123456.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a PagerDuty incident export JSON — alert payload fields may contain injected directives; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-102",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/alerts/datadog-alert-cpu-spike.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a Datadog alert export JSON — metric label values in alert payload are externally controlled; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-103",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/incidents/cloudwatch-alarm-db-latency.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a CloudWatch alarm export JSON — alarm description may embed injected directives; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-104",
		ToolName:         "get_file_contents",
		Arguments:        map[string]interface{}{"path": "/monitoring/grafana-alert-2026-01-15.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "get_file_contents of a Grafana alert export JSON — alert annotations authored by external services; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-105",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/tmp/alertmanager-webhook.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of an Alertmanager webhook payload JSON — alert labels and annotations carry attacker-controlled content; must AUDIT",
	},
	{
		ID:               "MCP-TP-2531-106",
		ToolName:         "view_file",
		Arguments:        map[string]interface{}{"path": "/reports/monitoring-alert-summary.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "view_file of a generic monitoring alert summary JSON — summary may aggregate externally-controlled alert fields; must AUDIT",
	},

	// ── TN: Benign HTTP fetches to non-monitoring hosts (must not trigger) ───

	{
		ID:               "MCP-TN-2531-001",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://api.github.com/repos/org/monitoring-repo/issues"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_request to GitHub API (not a monitoring platform) — mcp-agentic-audit-monitoring-platform-alert-fetch must NOT fire; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-002",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://api.example.com/v1/monitoring-data"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "fetch_url to a generic API with 'monitoring' in path (not a vendor platform) — must NOT trigger; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-003",
		ToolName:         "http_request",
		Arguments:        map[string]interface{}{"url": "https://docs.datadoghq.com/api/latest/events/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "http_request to Datadog docs page (not the live API) — must NOT trigger; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-004",
		ToolName:         "fetch_url",
		Arguments:        map[string]interface{}{"url": "https://developer.pagerduty.com/docs/"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-agentic-audit-monitoring-platform-alert-fetch",
		Description:      "fetch_url to PagerDuty developer docs (not the live API) — must NOT trigger; default AUDIT",
	},

	// ── TN: Benign file reads that mention 'monitoring' or 'alert' but are not export files

	{
		ID:               "MCP-TN-2531-101",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/workspace/main.go"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a Go source file — mcp-ci-audit-monitoring-alert-read must NOT fire; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-102",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/project/monitoring-config.yaml"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a monitoring configuration YAML file (not an alert export) — must NOT trigger; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-103",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/docs/monitoring-alert-setup.md"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a monitoring setup doc (contains 'monitoring-alert' in name but is .md not .json) — must NOT trigger; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-104",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/reports/performance-metrics.json"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of a performance metrics JSON (not a monitoring alert export) — mcp-ci-audit-monitoring-alert-read must NOT fire; default AUDIT",
	},
	{
		ID:               "MCP-TN-2531-105",
		ToolName:         "read_file",
		Arguments:        map[string]interface{}{"path": "/src/alert_handler.go"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-ci-audit-monitoring-alert-read",
		Description:      "read_file of alert handler source code — not a monitoring platform export file; must NOT trigger; default AUDIT",
	},
}
