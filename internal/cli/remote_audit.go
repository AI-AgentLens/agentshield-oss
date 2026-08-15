package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/analyzer"
	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// buildAuditPayload builds the JSON wire payload sent to the SaaS /api/audit
// endpoint. Extracted from sendRemoteAudit so the payload contract with the
// SaaS (issue #1952) is independently testable — see remote_audit_test.go
// and the matching golden file in
// `aiagentlens/internal/audit/testdata/audit-only-payload-contract.golden.json`.
//
// If either side renames a field, one of the two tests breaks loudly. The
// golden file is the contract: keep the two copies byte-identical.
//
// Wire schema (issue #3111 added taxonomy, rule_ids, signals, and the
// identity trio):
//
//	command, decision, mode                 always present
//	rule_id, reason, source                 always present (may be "")
//	rule_ids   []string                     always present — every rule that fired
//	taxonomy   []string                     always present — taxonomy node ids
//	signals    []string                     when a Go detector drove the decision
//	original_decision                       when audit-only downgraded a BLOCK
//	tool_name, arguments                    MCP events
//	cwd, session_id, principal              when observable (identity plane)
//
// Adding a key is backward compatible — the SaaS decodes with the standard
// (lenient) json decoder. Renaming or removing one is not.
func buildAuditPayload(event *logger.AuditEvent) ([]byte, error) {
	// Use tool name as command for MCP calls
	command := event.Command
	if command == "" && event.ToolName != "" {
		command = "mcp:" + event.ToolName
	}

	ruleIDs, signals := splitTriggeredRules(event.TriggeredRules)
	taxonomy := analyzer.NormalizeTaxonomyRefs(event.TaxonomyRefs)

	entry := map[string]any{
		"command":  command,
		"decision": event.Decision,
		// rule_id keeps its exact historical meaning — the FIRST triggered
		// entry, whatever it is. The SaaS reads it today; changing which
		// entry it names would silently re-point existing dashboards.
		// New readers should prefer rule_ids. Issue #3111.
		"rule_id": firstRule(event.TriggeredRules),
		// rule_ids preserves every rule that fired. A command that trips four
		// rules was previously attested by one; the other three vanished at
		// the boundary. Always present (possibly empty) — a taxonomy/rule-set
		// that is explicitly empty is evidence; a missing key is not.
		"rule_ids": ruleIDs,
		// taxonomy is the first hop of block -> taxonomy node -> compliance
		// control -> receipt. Always present so the SaaS can distinguish
		// "this decision maps to no taxonomy node" from "this agent is too
		// old to tell you". Issue #3111.
		"taxonomy": taxonomy,
		"reason":   firstReason(event.Reasons),
		"source":   event.Source,
		// Issue #1952: always emit the enforcement mode so the SaaS can
		// segment telemetry by rollout cohort (enforce vs audit-only).
		// Empty string is acceptable for the field-always-present invariant;
		// downstream readers default to "enforce" on empty.
		"mode": event.Mode,
	}
	// signals carries the detector labels that are NOT rule ids — see
	// splitTriggeredRules. Omitted when empty: its presence is the receiver's
	// cue that a Go-implemented scanner (not a pack rule) drove the decision.
	if len(signals) > 0 {
		entry["signals"] = signals
	}
	// Identity plane (issue #3111). Omitted when unknown — an empty principal
	// or session is an honest "not observable here", and omitempty keeps the
	// receiver from recording "" as a real identity.
	if event.Cwd != "" {
		entry["cwd"] = event.Cwd
	}
	if event.SessionID != "" {
		entry["session_id"] = event.SessionID
	}
	if event.Principal != "" {
		entry["principal"] = event.Principal
	}
	// Only set original_decision when a downgrade actually happened — the
	// SaaS treats presence-of-field as the "shadow block" signal. Issue #1952.
	if event.OriginalDecision != "" {
		entry["original_decision"] = event.OriginalDecision
	}
	if event.ToolName != "" {
		entry["tool_name"] = event.ToolName
	}
	if len(event.MCPArguments) > 0 {
		entry["arguments"] = event.MCPArguments
	}

	return json.Marshal(map[string]any{
		"events": []map[string]any{entry},
	})
}

// sendRemoteAudit sends an audit event to the SaaS synchronously.
// Uses a short timeout so it doesn't slow down the hook noticeably.
func sendRemoteAudit(event *logger.AuditEvent) {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}

	payload, err := buildAuditPayload(event)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", creds.Server+"/api/audit", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+creds.Token)

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// splitTriggeredRules partitions AuditEvent.TriggeredRules into resolvable
// rule ids and detector signals.
//
// Why this exists (issue #3111): the MCP dispatch appends synthetic labels to
// TriggeredRules alongside real rule ids — `content:<signal>`,
// `datalabel:<label-id>`, `path-traversal:<arg>`, `blocked-tool:<glob>` and
// friends (internal/mcp/handler.go). They carry per-finding detail, so their
// value space is unbounded and they can never appear in a rule -> control
// mapping table. Shipping them in the same array as rule ids left the SaaS
// unable to tell an attestable rule from a detector artifact.
//
// The convention is deliberately one rule you can verify rather than a
// growing list of known prefixes: **a rule id never contains a colon**.
// Every id across the shipped community + premium packs is a
// `[a-z0-9-]` slug; TestSplitTriggeredRules_NoPackRuleIDIsMisclassified is
// the fitness function that keeps it true.
//
// Note what deliberately stays in rule_ids: scanner-pass markers such as
// `argument-content-scan` and built-in intercepts such as `protected-path`.
// Those are stable, enumerable identifiers a mapping table can key on — and
// where a sentinel rule exists, the dispatch already emits the real rule id
// beside the marker (see LookupSentinel in internal/mcp/handler.go). Only
// labels carrying finding detail get namespaced out.
func splitTriggeredRules(triggered []string) (ruleIDs, signals []string) {
	ruleIDs = make([]string, 0, len(triggered))
	signals = make([]string, 0)
	seenRule := make(map[string]bool, len(triggered))
	seenSignal := make(map[string]bool, len(triggered))
	for _, t := range triggered {
		if t == "" {
			continue
		}
		if strings.Contains(t, ":") {
			if !seenSignal[t] {
				seenSignal[t] = true
				signals = append(signals, t)
			}
			continue
		}
		if !seenRule[t] {
			seenRule[t] = true
			ruleIDs = append(ruleIDs, t)
		}
	}
	return ruleIDs, signals
}

func firstRule(rules []string) string {
	if len(rules) > 0 {
		return rules[0]
	}
	return ""
}

func firstReason(reasons []string) string {
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}
