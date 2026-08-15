package mcp

import (
	"strings"
	"sync"
)

// LateralWriteSignal is emitted once per session when an infra-mutation
// write/deploy/exec tool is invoked after the session has already exercised
// an untrusted-content-ingest read.
type LateralWriteSignal string

const (
	// SignalLateralWriteAfterIngest fires the first time a session composes a
	// low-trust content-ingest read (logs/analytics/issues/tickets) with a
	// write/deploy/exec-capable call, in that order, across separate tool
	// calls — even when no single call is individually malicious. AUDIT.
	SignalLateralWriteAfterIngest LateralWriteSignal = "lateral_write_after_untrusted_ingest"
)

// syntheticLateralWriteAfterIngest is the virtual tool name injected into the
// policy engine when the composition completes, mirroring the lethal-trifecta
// / sub-agent tracker approach.
const syntheticLateralWriteAfterIngest = "__mcp_lateral_write_after_ingest__"

// LateralWriteTracker accumulates, across a session's MCP tool calls, whether
// an untrusted-content-ingest read has occurred, and fires
// SignalLateralWriteAfterIngest the first time an infra-mutation write/deploy/
// exec tool is subsequently invoked in the same session.
//
// This models the "living off the MCP" session-composition attack (DEF CON 34,
// Tenet Security, "Your WAF Blocked Us, That Was The Exploit", #3275): a
// read-only, low-trust ingest MCP server (e.g. a firewall-events / analytics
// API where an attacker fully controls logged fields such as User-Agent) and
// a write-capable MCP server (e.g. DNS management) share one session under
// one grant. Every individual call is independently authorized — per-call
// argument matching cannot see the composition, only the co-presence of the
// two capability classes in one session can.
//
// Order matters: A (ingest) must precede B (write/deploy/exec) for the signal
// to fire, mirroring the exploit chain's "poisoned content enters context,
// then the agent acts on it" shape. A session that performs the write first
// and reads logs afterward does not fire — that ordering carries no plausible
// taint story.
//
// AUDIT, not BLOCK: the composite is a review signal (both capabilities are
// live in one session, in the exploitable order), not proof that the write's
// content was actually derived from the ingested content. A response-content
// taint match (write args provably derived from the prior read's output) is
// the natural BLOCK-tier follow-up and is not implemented here — see #3275.
//
// Session-scoped: one tracker per MessageHandler, same tradeoff as
// LethalTrifectaTracker and ApprovalFatigueTracker.
type LateralWriteTracker struct {
	mu        sync.Mutex
	sawIngest bool
	fired     bool
}

// NewLateralWriteTracker returns a ready tracker with no capabilities seen.
func NewLateralWriteTracker() *LateralWriteTracker {
	return &LateralWriteTracker{}
}

// Scan classifies the current tool call and returns
// SignalLateralWriteAfterIngest the first time an infra-mutation write/
// deploy/exec tool is invoked in a session that has already exercised an
// untrusted-content-ingest read. Returns "" otherwise (including all calls
// after the signal has already fired, and all calls before an ingest read has
// been seen).
func (t *LateralWriteTracker) Scan(toolName string, args map[string]interface{}) LateralWriteSignal {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.fired {
		return ""
	}
	lname := strings.ToLower(toolName)
	if isUntrustedContentIngestTool(lname) {
		t.sawIngest = true
		return ""
	}
	if t.sawIngest && isInfraMutationTool(lname) {
		t.fired = true
		return SignalLateralWriteAfterIngest
	}
	return ""
}

// isUntrustedContentIngestTool matches tools that pull in low-trust,
// externally-influenced content an attacker can shape without ever touching
// the MCP session directly — log lines, analytics rows, ticket/issue text,
// alert payloads. This is distinct from isUntrustedIngestTool in
// lethal_trifecta.go (which targets direct fetch/browse/download of a URL);
// here the untrusted content arrives indirectly, laundered through a
// read-only reporting/observability API.
func isUntrustedContentIngestTool(lname string) bool {
	needles := []string{
		"get_logs", "list_logs", "read_logs", "fetch_logs", "query_logs", "tail_logs", "search_logs",
		"get_events", "list_events", "query_events", "search_events",
		"get_analytics", "query_analytics", "list_analytics",
		"list_issues", "get_issue", "search_issues",
		"list_tickets", "get_ticket", "search_tickets",
		"get_alerts", "list_alerts", "search_alerts",
		"firewall_events", "get_firewall_events", "list_firewall_events", "query_firewall_events",
		"list_findings", "get_findings",
		"list_comments", "get_comments",
		"list_notifications", "get_notifications",
		"graphql_query", "run_analytics_query",
	}
	return containsAny(lname, needles)
}

// isInfraMutationTool matches tools capable of write, deploy, or command
// execution against production infrastructure — DNS, firewall, IAM, workers/
// functions, deployments, generic config/command execution. Scoped to
// infra-mutation rather than every write verb: a generic note-taking or
// task-tracker write is not the "co-located low-trust-read + high-trust-write"
// shape the source research describes, and including it would drown the
// signal in noise without adding precision.
func isInfraMutationTool(lname string) bool {
	needles := []string{
		"dns_record", "update_dns", "create_dns", "delete_dns", "modify_dns", "set_dns",
		"update_record", "create_record", "put_record", "patch_record",
		"deploy_worker", "create_worker", "publish_worker", "update_worker",
		"create_deployment", "update_deployment", "deploy_",
		"update_firewall", "create_firewall_rule", "modify_firewall",
		"update_iam", "create_iam", "grant_permission", "add_permission",
		"create_access_key", "rotate_key",
		"update_zone", "modify_zone",
		"invoke_function", "execute_command", "run_command", "exec_command",
		"apply_config", "update_config", "push_config",
		"create_webhook", "update_webhook",
	}
	return containsAny(lname, needles)
}
