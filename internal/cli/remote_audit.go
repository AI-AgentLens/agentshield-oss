package cli

import (
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
//	notes      []{kind,rule,detail}         when evaluation excused a match or
//	                                        knowingly gave up (#3995); omitted
//	                                        when empty, so the golden is unchanged
//	machine_id, local_chain                 added by sendRemoteAudit (#4208); see
//	                                        buildLinkedAuditPayload
//	client_event_id                         always (#4467) — 32 hex chars, the
//	                                        SaaS's per-org idempotency key. Not
//	                                        "event_id": the SaaS already uses
//	                                        that for its integer row id
//
// A request may carry many events (the upload queue batches them, see
// audit_queue.go); each entry is exactly what auditWireEntry builds for one.
//
// Adding a key is backward compatible — the SaaS decodes with the standard
// (lenient) json decoder. Renaming or removing one is not.
//
// Redaction (#4332): the payload is built from event.Redacted(), the same
// redaction AuditLogger.Log applies to the audit.jsonl line. Log works on a
// copy, so the event the hook hands here is still the original; before this,
// command, arguments and the fail-safe reason went to /api/audit verbatim
// while the local line read [REDACTED]. Redact here, the one function every
// sender goes through, never at a call site.
//
// client_event_id (#4467): a 128-bit random hex id the client generates once
// per event. The upload is at-least-once (audit_queue.go retries a batch whose
// response it never saw), so the SaaS drops a repeat of an (org,
// client_event_id) it already stored. A retry re-sends the bytes stored with
// the event, never a new id. Omitted when clientEventID is empty, which only
// tests pass.
//
// buildAuditPayload is the payload of an event with no chain link and no
// machine id. That is exactly the golden's event, so the golden pins it
// byte for byte; sendRemoteAudit builds its entry with auditWireEntry.
func buildAuditPayload(original *logger.AuditEvent, clientEventID string) ([]byte, error) {
	return buildLinkedAuditPayload(original, clientEventID, auditLink{})
}

// auditLink is what ties a wire event to the machine and the local line
// that recorded it (#4208). The SaaS chains what it receives per org, but
// that cannot show a line deleted on the machine before it was sent. With
// each event's link, it can: per machine_id, a prev_hash that names no
// line_hash it ever received is a local line that never arrived.
type auditLink struct {
	// MachineID is enterprise.MachineID(), the value the heartbeat sends,
	// so the SaaS keys continuity on the machine it already knows.
	MachineID string
	// Chain is the local line's link, from AuditLogger.LogLinked. nil when
	// no line was written chained (no logger, or the write failed), and then
	// local_chain is omitted: an absent key is "not chain-reported", which
	// the SaaS counts and never flags, where a fabricated link would read
	// as a break.
	Chain *logger.ChainLink
}

// buildLinkedAuditPayload is buildAuditPayload plus the two #4208 keys,
// each omitted when unknown, so an event without them is byte-identical
// to buildAuditPayload's (the golden, with the golden's client_event_id):
//
//	machine_id   string                     when known
//	local_chain  {prev_hash, line_hash}     when the local line was written
//	                                        chained; prev_hash is "" at genesis
func buildLinkedAuditPayload(original *logger.AuditEvent, clientEventID string, link auditLink) ([]byte, error) {
	entry, err := json.Marshal(auditWireEntry(original, clientEventID, link))
	if err != nil {
		return nil, err
	}
	return auditBatchBody([]json.RawMessage{entry}), nil
}

// auditBatchBody wraps already-marshalled wire entries in the /api/audit
// envelope. For one entry it is byte-identical to marshalling
// {"events":[entry]} (TestAuditBatchBody_MatchesMarshal), so the queue's
// batches and the single-event golden share one encoding.
func auditBatchBody(entries []json.RawMessage) []byte {
	n := len(`{"events":[]}`)
	for _, e := range entries {
		n += len(e) + 1
	}
	b := make([]byte, 0, n)
	b = append(b, `{"events":[`...)
	for i, e := range entries {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, e...)
	}
	return append(b, `]}`...)
}

// auditWireEntry is one event as it goes on the wire, built from the redacted
// copy (see buildAuditPayload), with its #4208 link and #4467 id. It is the
// only builder: the payload helpers above and sendRemoteAudit all use it.
func auditWireEntry(original *logger.AuditEvent, clientEventID string, link auditLink) map[string]any {
	redacted := original.Redacted()
	event := &redacted

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
	// notes: attestation records (#3995). Present only when non-empty — an
	// event with none must stay byte-identical to the contract golden.
	if len(event.Notes) > 0 {
		entry["notes"] = event.Notes
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
	if link.MachineID != "" {
		entry["machine_id"] = link.MachineID
	}
	// prev_hash is always present inside local_chain: "" is the genesis
	// value and means something (a chain restart), so it is not omitempty.
	if link.Chain != nil {
		entry["local_chain"] = map[string]string{
			"prev_hash": link.Chain.PrevHash,
			"line_hash": link.Chain.LineHash,
		}
	}
	if clientEventID != "" {
		entry["client_event_id"] = clientEventID
	}
	return entry
}

// sendRemoteAudit hands an audit event to the SaaS upload. Every hook sender
// goes through it: evaluateCommand, auditMCPCall, recordSelfProtectBlock and
// failSafeDecision. Logged-out installs return here, as before.
//
// #4467: by default it does NOT talk to the network. It appends the redacted
// wire entry to the local upload queue and starts a detached background
// uploader (audit_queue.go), so a hook call no longer waits one SaaS round
// trip, or the 3 s timeout when the SaaS hangs. The decision is final before
// this runs; the upload is evidence delivery, not enforcement.
//
// AGENTSHIELD_AUDIT_UPLOAD=sync restores the synchronous POST, for an
// environment where a detached child does not outlive the hook (an ephemeral
// CI container). If the queue cannot be used, the event is POSTed
// synchronously rather than lost.
//
// chain is the link LogLinked returned for this event's local line, or nil
// when there was no logger or the write failed (#4208). The machine id is
// read only after the credentials check, so an install that reports
// nowhere does not pay for it, and its wait is bounded by machineIDWait.
func sendRemoteAudit(event *logger.AuditEvent, chain *logger.ChainLink) {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}
	// The wire entry is built once, here, and the queue and the synchronous
	// fallback carry the same bytes: the id, the local chain link and the
	// machine id are fixed when the event happens, never rebuilt at upload
	// time.
	entry, err := json.Marshal(auditWireEntry(event, newClientEventID(), auditLink{
		MachineID: machineIDs.within(machineIDWait),
		Chain:     chain,
	}))
	if err != nil {
		return
	}
	if auditUploadSync() {
		postAuditEntrySync(creds, entry)
		return
	}
	if err := enqueueAuditEntry(creds, entry); err != nil {
		postAuditEntrySync(creds, entry)
		return
	}
	kickAuditFlusher()
}

// postAuditEntrySync is the pre-#4467 upload: one POST, waited on, with a 3 s
// timeout, and the event is dropped on any error. Used in sync mode and when
// the queue cannot be used.
func postAuditEntrySync(creds *auth.Credentials, entry json.RawMessage) {
	client := &http.Client{Timeout: 3 * time.Second}
	_, _ = postAuditBody(client, creds, auditBatchBody([]json.RawMessage{entry}))
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
