package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// The SEP-1686 ("Tasks") status-poll response has an unrouted prose field.
//
// # The surface
//
// tasks/get and tasks/result (internal/mcp/task_amplification.go already
// models both for burst-detection) return a result shaped like:
//
//	{"taskId": "...", "status": "failed", "keepAlive": 30000, "error": "..."}
//
// Per the spec, "The tasks/get response SHOULD include an error field with
// details about the failure" — free text authored entirely by the (untrusted)
// server, forwarded to the requester the same way a tool's error text would
// be. It is the same trust class as error.message (mcp-error-message-injection)
// and error.data (mcp-error-data-injection, #3908) — a diagnostic channel the
// spec designs to be read and acted on — except this specific instance of the
// class was completely unrouted: DispatchServerResponse's shape discriminator
// only recognizes protocolVersion/tools/content/contents/resources/
// resourceTemplates/messages/prompts/completion, none of which a tasks/get
// result carries, and none of the ten response filters in the safety-net
// chain know what to do with taskId/status/error either. Reproduced against
// live dispatch code (#3957): zero scanning, zero audit event.
//
// # Design, reusing the error.data machinery rather than inventing a third copy
//
// `error` is a single untyped field, not a message/data split, so it is
// walked the same way error.data's leaves are (walkErrorDataNode handles a
// bare string, an object, or an array uniformly). Every leaf — top-level or
// nested — is scanned with scanErrorDataLeaf, the `data`-calibrated pattern
// set, never ScanErrorMessage's `message`-calibrated one. The spec's own
// wording for this field is "details about the failure", `data`'s role, not
// message's "SHOULD be limited to a concise single sentence" — and unlike the
// JSON-RPC error object there is no separate concise field to carry that
// role, so a real task failure routinely reads exactly like a `data` leaf:
// "The credentials file ~/.aws/credentials could not be parsed: line 4 is
// malformed. Fix the profile block and retry." is the spec's OWN worked
// example shape, and it is precisely the sentence error_data_scanner.go's TN
// corpus already established as the common benign case on that channel.
// Measured while building this: routing a flat "error" leaf through
// ScanErrorMessage (i.e. treating it as message-shaped) fires
// credentialHarvestPatterns on that exact sentence — confirming the `data`
// framing, not the `message` framing, is the right calibration here.
//
// # serverAssertedFailure does not gate the whole scan
//
// Unlike error.data's caller (msg.Error != nil is unconditional proof of a
// protocol failure), a task's `status` field is server-controlled prose-
// adjacent metadata, not the JSON-RPC envelope itself. Rather than trust it
// as a hard gate, only ScanToolResultErrorRemediation's serverAssertedFailure
// flag depends on status == "failed" — if status can't be read as "failed"
// (absent, wrong type, or a value other than "failed"), remediation steering
// still runs but falls back to the remediation scanner's own text-based
// failureFrameRE gate, exactly as it would for a tool result with isError
// unset. The hidden-instruction / exfiltration / stealth / behavioral-
// manipulation groups never depended on failure framing to begin with, so
// they run unconditionally on every leaf regardless of what `status` says.
// A malicious server cannot buy silence by mislabeling status.

// ScanTaskStatusError scans a tasks/get or tasks/result response's `error`
// field for injection prose. status is the response's `status` value (used
// only to set ScanToolResultErrorRemediation's serverAssertedFailure flag);
// errorRaw is the raw `error` field value, which may be absent.
func ScanTaskStatusError(status string, errorRaw json.RawMessage) RPCErrorProseScanResult {
	var result RPCErrorProseScanResult
	if len(errorRaw) == 0 {
		return result
	}
	// decodeJSONValue decodes with UseNumber, so a valid-but-unrepresentable
	// number (1e400) beside the payload cannot fail the decode and take
	// every sibling string leaf with it (#4069). A syntax error still
	// returns nothing here: it is not valid JSON, so nothing a real client
	// parsed either.
	v, ok := decodeJSONValue(errorRaw)
	if !ok {
		return result
	}

	var leaves []RPCErrorProseFinding
	walkErrorDataNode(&leaves, "error", v, 0)
	if len(leaves) == 0 {
		return result
	}

	add := func(field, signal, detail string) {
		result.Findings = append(result.Findings, RPCErrorProseFinding{
			Field: field, Signal: signal, Detail: detail,
		})
	}

	items := make([]ContentItem, 0, len(leaves))
	fields := make([]string, 0, len(leaves))
	for _, leaf := range leaves {
		if sig, detail := scanErrorDataLeaf(leaf.Detail); sig != "" {
			add(leaf.Field, string(sig), detail)
		}
		items = append(items, ContentItem{Type: "text", Text: leaf.Detail})
		fields = append(fields, leaf.Field)
	}

	serverAssertedFailure := strings.TrimSpace(status) == "failed"
	if rem := ScanToolResultErrorRemediation(items, serverAssertedFailure); rem.Found {
		for _, f := range rem.Findings {
			field := "error"
			if f.ContentIndex >= 0 && f.ContentIndex < len(fields) {
				field = fields[f.ContentIndex]
			}
			add(field, string(f.Signal), f.Detail)
		}
	}

	result.Found = len(result.Findings) > 0
	return result
}

// parseTaskStatusResponseFields shallow-parses a tasks/get-shaped result. ok
// is false when the result is not an object or lacks both taskId and status
// — the pair DispatchServerResponse's routing table uses to recognize this
// shape. fields is returned so the caller can rewrite the `error` entry in
// place while preserving every other field (including vendor extensions)
// verbatim.
func parseTaskStatusResponseFields(result json.RawMessage) (fields map[string]json.RawMessage, status string, errorRaw json.RawMessage, ok bool) {
	if err := json.Unmarshal(result, &fields); err != nil || len(fields) == 0 {
		return nil, "", nil, false
	}
	_, hasTaskID := fields["taskId"]
	statusRaw, hasStatus := fields["status"]
	if !hasTaskID || !hasStatus {
		return nil, "", nil, false
	}
	// A malformed/non-string status is tolerated (decode-idiom fail-open
	// lesson, wire_shape.go): leave status "" rather than bail out of the
	// whole scan. ScanTaskStatusError treats "" as not-asserted-failure and
	// still runs the unconditional pattern groups.
	_ = json.Unmarshal(statusRaw, &status)
	return fields, status, fields["error"], true
}

// FilterTaskGetResponse checks whether a response is a tasks/get or
// tasks/result result (SEP-1686 "Tasks") and, when it carries an `error`
// field, scans it for injection prose. Returns replacement bytes with the
// error field redacted when poisoning is found, or nil to forward the
// response unchanged — every other field (taskId, status, keepAlive,
// pollFrequency, and any vendor extension) is preserved verbatim.
func (h *MessageHandler) FilterTaskGetResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	fields, status, errorRaw, ok := parseTaskStatusResponseFields(msg.Result)
	if !ok || len(errorRaw) == 0 {
		return nil
	}

	scan := ScanTaskStatusError(status, errorRaw)
	if !scan.Found {
		return nil
	}
	first := scan.Findings[0]

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT task status response — injection in %s: %s\n", first.Field, first.Detail)

	if h.OnAudit != nil {
		reasons := make([]string, 0, len(scan.Findings))
		for _, f := range scan.Findings {
			reasons = append(reasons, f.Signal+": "+f.Detail+" (field: "+f.Field+")")
		}
		ruleID := "mcp-task-status-error-injection"
		taxonomyRef := "unauthorized-execution/agentic-attacks/mcp-task-status-error-injection"
		if sentinel := h.Evaluator.LookupSentinel(ruleID); sentinel != nil {
			ruleID = sentinel.ID
			taxonomyRef = sentinel.Taxonomy
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "tasks/get",
			Decision:       "AUDIT",
			Flagged:        true,
			TriggeredRules: []string{ruleID},
			Reasons:        reasons,
			Source:         "mcp-proxy-task-status-scan",
			ServerName:     h.ServerName,
			TaxonomyRef:    taxonomyRef,
		})
	}

	sanitized, err := json.Marshal("[AgentShield: task error detail sanitized — injection pattern detected]")
	if err != nil {
		return nil
	}
	fields["error"] = sanitized
	newResult, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	msg.Result = newResult
	out, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return out
}

// taskListScanMaxItems bounds how many tasks/list entries are scanned per
// response, for the same reason errorDataMaxLeaves bounds a single walk: a
// server can return an arbitrarily large page, and the scan cost must stay
// bounded rather than becoming a lever against the proxy itself. Generous
// relative to any real single-page tasks/list result.
const taskListScanMaxItems = 1000

// FilterTaskListResponse checks whether a response is a tasks/list result
// (SEP-1686 "Tasks") and scans each task summary's `error` field for
// injection prose — the same untrusted, server-authored channel
// FilterTaskGetResponse scans on tasks/get and tasks/result, except tasks/list
// returns an array of task summaries rather than a single task object, so
// DispatchServerResponse's taskId+status discriminator (and FilterTaskGetResponse
// itself, which expects those keys at the top level) never matches it. Per the
// spec's "Task List Response" shape: {tasks: [{taskId, status, keepAlive,
// pollFrequency?, error?}], nextCursor?}. Returns replacement bytes with any
// poisoned per-item `error` fields redacted, or nil to forward the response
// unchanged — every other field, per item and top-level (including
// nextCursor and any vendor extension), is preserved verbatim.
func (h *MessageHandler) FilterTaskListResponse(data []byte) []byte {
	var msg Message
	if err := json.Unmarshal(data, &msg); err != nil {
		return nil
	}
	if msg.Method != "" || msg.Result == nil || msg.Error != nil {
		return nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(msg.Result, &top); err != nil || len(top) == 0 {
		return nil
	}
	tasksRaw, hasTasks := top["tasks"]
	if !hasTasks {
		return nil
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal(tasksRaw, &items); err != nil {
		return nil
	}
	// Bound the SCAN, not the forwarded payload: every item, including any
	// beyond the cap, is still marshaled back unchanged below. Truncating
	// items here would silently drop legitimate tail entries from the
	// response the client sees.
	scanLimit := len(items)
	if scanLimit > taskListScanMaxItems {
		scanLimit = taskListScanMaxItems
	}

	type taskFinding struct {
		index int
		f     RPCErrorProseFinding
	}
	var findings []taskFinding
	changedAny := false
	for i, item := range items[:scanLimit] {
		errorRaw, hasError := item["error"]
		if !hasError || len(errorRaw) == 0 {
			continue
		}
		var status string
		if statusRaw, ok := item["status"]; ok {
			_ = json.Unmarshal(statusRaw, &status)
		}
		scan := ScanTaskStatusError(status, errorRaw)
		if !scan.Found {
			continue
		}
		for _, f := range scan.Findings {
			findings = append(findings, taskFinding{index: i, f: f})
		}
		sanitized, err := json.Marshal("[AgentShield: task error detail sanitized — injection pattern detected]")
		if err != nil {
			continue
		}
		item["error"] = sanitized
		items[i] = item
		changedAny = true
	}
	if !changedAny {
		return nil
	}
	first := findings[0]

	_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] AUDIT task list response — injection in tasks[%d].%s: %s\n",
		first.index, first.f.Field, first.f.Detail)

	if h.OnAudit != nil {
		reasons := make([]string, 0, len(findings))
		for _, tf := range findings {
			reasons = append(reasons, fmt.Sprintf("%s: %s (field: tasks[%d].%s)", tf.f.Signal, tf.f.Detail, tf.index, tf.f.Field))
		}
		ruleID := "mcp-task-status-error-injection"
		taxonomyRef := "unauthorized-execution/agentic-attacks/mcp-task-status-error-injection"
		if sentinel := h.Evaluator.LookupSentinel(ruleID); sentinel != nil {
			ruleID = sentinel.ID
			taxonomyRef = sentinel.Taxonomy
		}
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "tasks/list",
			Decision:       "AUDIT",
			Flagged:        true,
			TriggeredRules: []string{ruleID},
			Reasons:        reasons,
			Source:         "mcp-proxy-task-status-scan",
			ServerName:     h.ServerName,
			TaxonomyRef:    taxonomyRef,
		})
	}

	itemsRaw, err := json.Marshal(items)
	if err != nil {
		return nil
	}
	top["tasks"] = itemsRaw
	newResult, err := json.Marshal(top)
	if err != nil {
		return nil
	}
	msg.Result = newResult
	out, err := json.Marshal(msg)
	if err != nil {
		return nil
	}
	return out
}
