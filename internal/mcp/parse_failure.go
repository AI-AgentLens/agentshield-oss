package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// This file is the one place a payload the proxy could not parse is decided
// (#4158). Four sites feed it: the stdio proxy in both directions, the HTTP
// proxy's request path, and the HTTP proxy's two response relays. Before it,
// each site forwarded an unparseable message as-is with at most a stderr
// line, and that fact never reached the audit record. A JSON-RPC message
// nested deeper than encoding/json will read (10000 levels) failed every
// decode in this package the same way, so a tools/call for a tool in
// BlockedTools, carrying one unread field nested 10001 deep, reached the
// server with no decision and no receipt — while Node's JSON.parse, and so
// the TypeScript SDK on either end, reads that message without complaint.
//
// Two outcomes, and only two:
//
//   - Nesting past the decoder's limit is BLOCKED, with its own rule id. No
//     MCP message comes within two orders of magnitude of 10000 levels, the
//     shape is attacker-inducible (`arguments` is model-controlled JSON and
//     the field costs about 20 KB of brackets), and it is enumerable: the
//     decision is "more than jsonMaxNestingDepth arrays or objects open at
//     once, outside string literals", nothing wider. The reply is a JSON-RPC
//     parse error (-32700) with a null id, which is what the spec prescribes
//     when the id cannot be read.
//   - Every other parse failure keeps failing open — forwarded unscanned,
//     as before — and now leaves the existing mcp-extract-fail-open receipt
//     ("Shield could not read this message and forwarded it"), so the pass
//     is recorded rather than silent.
//
// Why a byte-level pre-check rather than matching the decoder's error.
// encoding/json reports the depth failure as a *json.SyntaxError whose text
// is "invalid character '[' exceeded max depth" — an unexported detail that
// a Go release, or a switch to encoding/json/v2 (which uses a different
// error type), can change without any test here noticing, at which point the
// BLOCK silently reverts to the fail-open it replaced. Counting brackets
// outside strings is the decoder's own definition of depth (its scanner
// pushes one parse state per `[` or `{` and refuses the 10001st), costs
// nothing on the happy path because it runs only once a parse has already
// failed, and works on the HTTP relay paths, where no single decoder error
// exists to inspect. TestJSONNestingLimitPinnedToEncodingJSON pins the limit
// to the stdlib's at the boundary, so a change there fails loudly.
//
// One deliberate consequence of deciding on the bytes rather than on which
// error the decoder reported first: a payload that both nests past the limit
// AND has some other syntax error is blocked on its nesting. That is the
// enumerable shape, present regardless of what else is wrong with it.

// jsonMaxNestingDepth mirrors encoding/json's unexported maxNestingDepth: the
// number of arrays and objects the decoder allows open at once. Pinned by
// TestJSONNestingLimitPinnedToEncodingJSON.
const jsonMaxNestingDepth = 10000

// jsonDepthExceededRuleID is the rule id carried by the BLOCK receipt for a
// payload nested past jsonMaxNestingDepth. It shares the taxonomy node of
// the two fail-open receipts (securityMediatorParseFailOpenTaxonomyRef): a
// mediator/endpoint parser differential is the technique, and this rule is
// the control against the one instance of it the proxy can enumerate.
const jsonDepthExceededRuleID = "mcp-json-depth-exceeded"

// unparseableMessageToolName is the ToolName on both receipts: the method
// cannot be read from a payload that did not parse.
const unparseableMessageToolName = "unparseable-message"

// Labels the receipts carry so a reader knows which seam the payload crossed.
const (
	parseTransportStdio = "stdio"
	parseTransportHTTP  = "http"

	parseDirClientToServer = "client-to-server"
	parseDirServerToClient = "server-to-client"
)

// jsonNestingExceeds reports whether data opens more than limit arrays or
// objects at once, counted outside string literals. Brackets inside a string
// do not count; a backslash escapes the next byte, so `\"` does not end the
// string and `\\` does not escape the quote that follows it. A payload
// shorter than limit+1 bytes cannot hold limit+1 open brackets and returns
// false without a scan.
//
// On well-formed JSON this is exactly the condition under which encoding/json
// refuses the input. On malformed JSON the two can disagree about which
// error comes first; see the file comment for why the bytes decide.
func jsonNestingExceeds(data []byte, limit int) bool {
	if len(data) <= limit {
		return false
	}
	depth := 0
	inString, escaped := false, false
	for _, b := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '[', '{':
			depth++
			if depth > limit {
				return true
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return false
}

// newParseErrorResponse builds the JSON-RPC 2.0 parse-error reply (-32700)
// for a request whose id could not be read. The spec requires `"id": null`
// in that case; Message.ID is omitempty, so the null is spelled out rather
// than left nil.
func newParseErrorResponse(message string) []byte {
	null := json.RawMessage("null")
	resp, err := NewErrorResponse(&null, RPCParseError, message)
	if err != nil {
		// Message marshals three strings and an int; this cannot fail, but a
		// block must never degrade into a forward.
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Blocked by AgentShield: unparseable message"}}`)
	}
	return resp
}

var utf8BOM = []byte("\xEF\xBB\xBF")

// looksLikeJSONRPCPayload reports whether data could be a JSON-RPC message
// or batch at all: after any run of leading whitespace and UTF-8 BOMs, it
// opens an object whose first token is a key or the closing brace, or an
// array whose first element is an object or the closing bracket. It gates
// the fail-open RECEIPT on server-to-client payloads, never the depth BLOCK:
// a stdio server that writes a banner or debug lines to stdout, or an HTTP
// upstream answering a notification with an empty 202, an HTML error page,
// or the legacy SSE `endpoint` frame, would otherwise leave one AUDIT per
// line forever, and a receipt that fires that often is a receipt nobody
// reads. Neither the TypeScript nor the Python host can act on a line that
// does not start this way, so nothing the receipt exists to record is lost.
//
// The second token matters: a log line like `[INFO] 3 tools registered`
// opens with a bracket, and no host can parse it. A message a host could act
// on is an object (`{"` or `{}`) or a batch of objects (`[{` or `[]`).
//
// BOMs are skipped as a run, not singly, and on purpose: Go rejects even one,
// but Response.json() in the TypeScript SDK (undici) strips one, and on Node
// 25 accepts two, so a BOM-prefixed message is a parser differential and
// must keep its receipt however many it carries.
func looksLikeJSONRPCPayload(data []byte) bool {
	for {
		data = bytes.TrimLeft(data, " \t\r\n")
		if !bytes.HasPrefix(data, utf8BOM) {
			break
		}
		data = data[len(utf8BOM):]
	}
	if len(data) == 0 {
		return false
	}
	opener := data[0]
	rest := bytes.TrimLeft(data[1:], " \t\r\n")
	if len(rest) == 0 {
		return false
	}
	switch opener {
	case '{':
		return rest[0] == '"' || rest[0] == '}'
	case '[':
		return rest[0] == '{' || rest[0] == ']'
	}
	return false
}

// ScreenParseFailure decides a payload the client sent that ParseMessage or
// ParseBatch could not read (stdio client-to-server, HTTP handlePost). It
// returns (true, reply) when the payload must not be forwarded and reply is
// the JSON-RPC error to send the client instead; (false, nil) means forward
// as before. Both outcomes are recorded through OnAudit when audit logging
// is enabled; the BLOCK does not depend on it. The receipt is unconditional
// here: every line a client sends is a message by the transport's framing.
func (h *MessageHandler) ScreenParseFailure(transport, direction string, raw []byte, parseErr error) (bool, []byte) {
	return h.screenParseFailure(transport, direction, raw, parseErr, false)
}

// ScreenRelayedParseFailure is ScreenParseFailure for a server-to-client
// payload whose parse has already failed (stdio). The depth BLOCK is
// unconditional; the fail-open receipt is withheld from payloads that are
// not shaped like a message — see looksLikeJSONRPCPayload.
func (h *MessageHandler) ScreenRelayedParseFailure(transport, direction string, raw []byte, parseErr error) (bool, []byte) {
	return h.screenParseFailure(transport, direction, raw, parseErr, true)
}

// ScreenRelayedPayload is ScreenRelayedParseFailure for the HTTP response
// relays, which have no decoder error of their own: every Filter* there
// parses the body independently and returns nil when it cannot, so an
// unparseable body slides through the whole chain unremarked. This parses
// once up front and screens on failure. The parse runs on every body, shape
// or not, because the depth check must: a run of BOMs defeats the shape
// gate as surely as it defeats the decoder, and a 202, an HTML page or an
// endpoint frame cannot hold 10001 open brackets, so screening them costs
// nothing.
func (h *MessageHandler) ScreenRelayedPayload(transport, direction string, raw []byte) (bool, []byte) {
	if _, _, err := ParseMessage(raw); err != nil {
		return h.ScreenRelayedParseFailure(transport, direction, raw, err)
	}
	return false, nil
}

// screenParseFailure is the decision. A whitespace-only payload is neither
// blocked nor recorded: nothing in it can be acted on by either end. Depth
// past the limit is blocked before any shape question is asked. Otherwise
// the fail-open receipt is written, unless gateReceipt is set and the
// payload is not shaped like a message.
func (h *MessageHandler) screenParseFailure(transport, direction string, raw []byte, parseErr error, gateReceipt bool) (bool, []byte) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return false, nil
	}

	if jsonNestingExceeds(raw, jsonMaxNestingDepth) {
		reason := fmt.Sprintf(
			"%s %s: message nests JSON more than %d levels deep, past the limit encoding/json will read — not forwarded (the decoder said: %v)",
			transport, direction, jsonMaxNestingDepth, parseErr)
		_, _ = fmt.Fprintf(h.Stderr, "[AgentShield MCP] BLOCKED %s\n", reason)
		if h.OnAudit != nil {
			h.OnAudit(AuditEntry{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				ToolName:       unparseableMessageToolName,
				Decision:       "BLOCK",
				Flagged:        true,
				TriggeredRules: []string{jsonDepthExceededRuleID},
				Reasons:        []string{reason},
				Source:         "mcp-proxy",
				ServerName:     h.ServerName,
				TaxonomyRef:    securityMediatorParseFailOpenTaxonomyRef,
			})
		}
		return true, newParseErrorResponse(fmt.Sprintf(
			"Blocked by AgentShield: JSON nested deeper than the decoder limit (%d levels) — message not forwarded",
			jsonMaxNestingDepth))
	}

	if gateReceipt && !looksLikeJSONRPCPayload(raw) {
		return false, nil
	}
	if h.OnAudit != nil {
		h.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       unparseableMessageToolName,
			Decision:       "AUDIT",
			Flagged:        true,
			TriggeredRules: []string{"mcp-extract-fail-open"},
			Reasons: []string{fmt.Sprintf(
				"%s %s: failed to parse message — forwarded unscanned (fail open): %v", transport, direction, parseErr)},
			Source:      "mcp-proxy",
			ServerName:  h.ServerName,
			TaxonomyRef: securityMediatorParseFailOpenTaxonomyRef,
		})
	}
	return false, nil
}

// writeBlockedJSON replies to the client with body in place of an upstream
// response the proxy refused to relay. Upstream headers travel with it,
// `Mcp-Session-Id` above all: the session the client is in was established
// by the upstream, and a reply that dropped the header would end it over one
// refused message. Only the three headers that described the replaced body
// are left out. Pinned by TestHTTPProxy_BlockedResponseKeepsUpstreamHeaders.
func (hp *HTTPProxy) writeBlockedJSON(w http.ResponseWriter, upstream *http.Response, body []byte) {
	for k, vs := range upstream.Header {
		switch http.CanonicalHeaderKey(k) {
		case "Content-Length", "Content-Encoding", "Content-Type":
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
