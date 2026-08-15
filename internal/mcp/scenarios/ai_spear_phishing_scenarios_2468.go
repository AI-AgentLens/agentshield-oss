// MCP scenarios for issue #2468: AI-generated spear phishing — bulk email send detection.
//
// One rule shipped (stateless, single-call):
//
//   mcp-excessive-agency-bulk-email-send-audit
//     Detects send_email/send_message MCP calls where the `to` argument is a
//     list/array (serialized as "[addr1 addr2 ...]") rather than a single string.
//     Bulk recipient lists are a spear-phishing chain signal — autonomous agents
//     dispatching personalized email to many targets without human confirmation.
//
// Rule B (undisclosed AI disclosure on bulk sends) is DEFERRED — the MCP match engine
// lacks a predicate for "argument does NOT contain string". Go's filepath.Match
// treats bracket-delimited patterns as character classes (not literal strings), making
// *[AI-generated]* match every string. See the comment block in mcp-excessive-agency.yaml
// for the full engine-limitation analysis and resolution options.
//
// Taxonomy: unauthorized-execution/agentic-attacks/ai-spear-phishing-content-generation
// Pack: packs/premium/mcp/mcp-excessive-agency.yaml (version 1.1.0)

package scenarios

// AISpearPhishingScenarios2468 contains TP and TN scenarios for the two
// spear-phishing detection rules added in issue #2468.
var AISpearPhishingScenarios2468 = []Scenario{

	// =========================================================================
	// RULE A: mcp-excessive-agency-bulk-email-send-audit
	// TP: send_email/send_message with array/list `to` field → AUDIT
	// =========================================================================

	{
		ID:               "MCP-TP-2468-001",
		ToolName:         "send_email",
		Arguments:        map[string]interface{}{"to": []string{"alice@corp.com", "bob@corp.com", "charlie@corp.com"}, "subject": "Action Required", "body": "Dear colleague, please verify your credentials."},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "send_email with []string to field — three recipients, array format; spear-phishing bulk dispatch must AUDIT (issue #2468)",
	},
	{
		ID:               "MCP-TP-2468-002",
		ToolName:         "gmail_send",
		Arguments:        map[string]interface{}{"to": []string{"cfo@company.com", "ceo@company.com"}, "subject": "Wire Transfer Authorization", "body": "Please approve the attached transfer."},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "gmail_send with []string to field — executive targeting with bulk recipient list; must AUDIT (issue #2468)",
	},
	{
		ID:               "MCP-TP-2468-003",
		ToolName:         "send_mail",
		Arguments:        map[string]interface{}{"to": []interface{}{"user1@example.com", "user2@example.com", "user3@example.com"}, "subject": "Newsletter", "body": "Hello everyone, click here for your personalized offer."},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "send_mail with []interface{} to field — three recipients as interface slice; must AUDIT (issue #2468)",
	},
	{
		ID:               "MCP-TP-2468-004",
		ToolName:         "deliver_message",
		Arguments:        map[string]interface{}{"to": []string{"team@org.com", "manager@org.com"}, "body": "Urgent: Please reset your password immediately."},
		ExpectedDecision: "AUDIT",
		Classification:   "TP",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "deliver_message with []string bulk recipient — autonomous delivery to multiple targets; must AUDIT (issue #2468)",
	},

	// =========================================================================
	// RULE A: TN — single-recipient sends must NOT trigger
	// =========================================================================

	{
		ID:               "MCP-TN-2468-001",
		ToolName:         "send_email",
		Arguments:        map[string]interface{}{"to": "alice@corp.com", "subject": "Quick question", "body": "[AI-drafted] Hi Alice, following up on our earlier discussion."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "send_email with single-string `to` — fires mcp-excessive-agency-messaging-send-audit (all sends) but NOT the bulk rule; no extra AUDIT from 2468 rule (issue #2468 TN)",
	},
	{
		ID:               "MCP-TN-2468-002",
		ToolName:         "gmail_send",
		Arguments:        map[string]interface{}{"to": "manager@company.com", "subject": "Status Update", "body": "Here is the weekly update."},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "gmail_send with single-string `to` — single recipient, must NOT trigger the bulk rule (issue #2468 TN)",
	},
	{
		ID:               "MCP-TN-2468-003",
		ToolName:         "list_emails",
		Arguments:        map[string]interface{}{"folder": "inbox"},
		ExpectedDecision: "AUDIT",
		Classification:   "TN",
		Category:         "mcp-excessive-agency-bulk-email-send-audit",
		Description:      "list_emails read operation — no send, must not trigger any email send rule (issue #2468 TN)",
	},

	// Rule B (mcp-excessive-agency-bulk-email-undisclosed-ai-audit) is DEFERRED.
	// See comment block in mcp-excessive-agency.yaml and PR body for #2468.
	// Scenarios for rule B will be added when the engine gains a "body_not_contains"
	// predicate or equivalent capability.
}
