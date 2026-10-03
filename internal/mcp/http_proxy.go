package mcp

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// HTTPProxyConfig holds configuration for the MCP Streamable HTTP proxy.
type HTTPProxyConfig struct {
	// UpstreamURL is the URL of the real MCP server (e.g., "http://localhost:8080/mcp").
	UpstreamURL string

	// ListenAddr is the local address to listen on (e.g., ":9100" or "127.0.0.1:9100").
	// Defaults to "127.0.0.1:0" (random port on loopback).
	ListenAddr string

	// Evaluator is the MCP policy evaluator.
	Evaluator *PolicyEvaluator

	// OnAudit is called for every intercepted tools/call decision.
	OnAudit AuditFunc

	// Stderr is where proxy diagnostic messages go. Defaults to os.Stderr.
	Stderr io.Writer

	// ServerName is the human-readable name of the upstream MCP server,
	// recorded in audit entries so consumers know the call target.
	ServerName string

	// SchemaDriftCacheDir overrides the directory used for the schema drift cache.
	// When empty, defaults to ~/.agentshield. Set to t.TempDir() in tests.
	SchemaDriftCacheDir string

	// DataLabelScanner is an optional data label scanner for customer-defined PII patterns.
	DataLabelScanner *DataLabelScanner
}

// HTTPProxy is a transparent MCP Streamable HTTP reverse proxy that intercepts
// tools/call requests. It listens on a local HTTP endpoint, evaluates incoming
// JSON-RPC messages against policy, and forwards allowed requests to the
// upstream MCP server.
type HTTPProxy struct {
	cfg     HTTPProxyConfig
	handler *MessageHandler
	// client serves the discovery interceptors (OAuth AS metadata, A2A agent
	// card); relayClient serves the mediated MCP traffic, see NewHTTPProxy.
	client      *http.Client
	relayClient *http.Client
	server      *http.Server
	stderr      io.Writer
	listener    net.Listener
	mu          sync.Mutex
}

// NewHTTPProxy creates a new MCP Streamable HTTP proxy.
func NewHTTPProxy(cfg HTTPProxyConfig) *HTTPProxy {
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	relayTransport := http.DefaultTransport.(*http.Transport).Clone()
	relayTransport.DisableCompression = true
	return &HTTPProxy{
		cfg:    cfg,
		stderr: stderr,
		// Single shared handler ⇒ tracker/call history crosses sessions here
		// until keyed by Mcp-Session-Id (deferred); the stdio proxy is the
		// exact path (one handler == one agent == one session).
		handler: newMessageHandler(cfg.Evaluator, cfg.OnAudit, stderr, cfg.ServerName, cfg.SchemaDriftCacheDir, cfg.DataLabelScanner),
		client: &http.Client{
			Timeout: 5 * time.Minute, // generous timeout for long-running tool calls
		},
		// relayClient carries the mediated traffic (forwardPost,
		// proxyPassthrough). Transparent gzip is off so every content coding
		// reaches the proxy's own decoder under its full declaration (#4154):
		// the transport judged Content-Encoding by its first header line and
		// deleted the whole declaration once it had decoded, so a second line
		// was invisible to the scanners. forwardPost asks for gzip explicitly.
		// The discovery interceptors keep client and its transparent decoding.
		relayClient: &http.Client{
			Timeout:   5 * time.Minute,
			Transport: relayTransport,
		},
	}
}

// ListenAddr returns the actual address the proxy is listening on.
// Only valid after Run or ListenAndServe has been called.
func (hp *HTTPProxy) ListenAddr() string {
	hp.mu.Lock()
	defer hp.mu.Unlock()
	if hp.listener != nil {
		return hp.listener.Addr().String()
	}
	return ""
}

// ListenAndServe starts the HTTP proxy and blocks until the server is shut down.
func (hp *HTTPProxy) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", hp.handleMCP)

	hp.server = &http.Server{
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 5 * time.Minute, // long writes for SSE streaming
		IdleTimeout:  120 * time.Second,
	}

	ln, err := net.Listen("tcp", hp.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", hp.cfg.ListenAddr, err)
	}

	hp.mu.Lock()
	hp.listener = ln
	hp.mu.Unlock()

	addr := ln.Addr().String()
	_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] listening on http://%s\n", addr)
	_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] upstream: %s\n", hp.cfg.UpstreamURL)

	return hp.server.Serve(ln)
}

// Shutdown gracefully shuts down the HTTP proxy.
func (hp *HTTPProxy) Shutdown(ctx context.Context) error {
	if hp.server != nil {
		return hp.server.Shutdown(ctx)
	}
	return nil
}

// handleMCP is the main HTTP handler for all MCP messages.
// Supports POST (client→server requests) and GET (SSE session init).
func (hp *HTTPProxy) handleMCP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		hp.handlePost(w, r)
	case http.MethodGet:
		// SSE session initialization — pass through to upstream
		hp.handleGet(w, r)
	case http.MethodDelete:
		// Session termination — pass through to upstream
		hp.proxyPassthrough(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handlePost processes a POST request containing a JSON-RPC message.
// This is the primary client→server path in Streamable HTTP transport.
func (hp *HTTPProxy) handlePost(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if len(body) == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		return
	}

	// JSON-RPC 2.0 batch request (JSON array): evaluate each item individually.
	// Block the entire batch if any item violates policy (fail-closed).
	if IsBatch(body) {
		msgs, err := ParseBatch(body)
		if err != nil {
			// Unparseable batch: nesting past the decoder limit is blocked,
			// anything else is forwarded with a receipt (#4158).
			if blocked, errResp := hp.handler.ScreenParseFailure(parseTransportHTTP, parseDirClientToServer, body, err); blocked {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(errResp)
				return
			}
			_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] warning: failed to parse batch, forwarding: %v\n", err)
			hp.forwardPost(w, r, body)
			return
		}
		blocked, batchResp := hp.handler.HandleBatch(msgs)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(batchResp)
			return
		}
		hp.forwardPost(w, r, body)
		return
	}

	// Parse the JSON-RPC message
	msg, kind, err := ParseMessage(body)
	if err != nil {
		// Can't parse: nesting past the decoder limit is blocked, anything
		// else is forwarded as-is (fail open) with a receipt (#4158).
		if blocked, errResp := hp.handler.ScreenParseFailure(parseTransportHTTP, parseDirClientToServer, body, err); blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(errResp)
			return
		}
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] warning: failed to parse message, forwarding: %v\n", err)
		hp.forwardPost(w, r, body)
		return
	}

	// Evaluate tools/call requests
	if kind == KindToolCall {
		blocked, blockResp := hp.handler.HandleToolCall(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Evaluate resources/read requests
	if kind == KindResourceRead {
		blocked, blockResp := hp.handler.HandleResourceRead(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Evaluate resources/subscribe requests (passive file monitoring — exfiltration via change notifications)
	if kind == KindResourceSubscribe {
		blocked, blockResp := hp.handler.HandleResourceSubscribe(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Evaluate prompts/get requests (outbound argument content scanning — issue #2789)
	if kind == KindPromptsGet {
		blocked, blockResp := hp.handler.HandlePromptsGetRequest(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Evaluate completion/complete requests (outbound argument content scanning — issue #2791)
	if kind == KindCompletionComplete {
		blocked, blockResp := hp.handler.HandleCompletionCompleteRequest(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// tasks/get and tasks/result (SEP-1686 "Tasks" polling): recorded for
	// task-amplification burst detection, never blocked.
	if kind == KindTasksGet || kind == KindTasksResult {
		hp.handler.HandleTaskPollRequest(msg)
	}

	// Evaluate sampling/createMessage requests (server-initiated prompt injection surface)
	if kind == KindSamplingCreateMessage {
		blocked, blockResp := hp.handler.HandleSamplingCreateMessage(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Evaluate elicitation/create requests (server-initiated credential/approval harvesting)
	if kind == KindElicitationCreate {
		blocked, blockResp := hp.handler.HandleElicitationCreate(msg)
		if blocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(blockResp)
			return
		}
	}

	// Drop notifications/message payloads containing injection patterns.
	// In the HTTP transport, notifications arrive as server-sent events forwarded
	// through the proxy. Injected notifications are suppressed (204 No Content) so
	// the client never receives the malicious payload.
	if kind == KindNotification && hp.handler.HandleNotificationMessage(msg) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Drop notifications/resources/updated if the URI targets a blocked credential path.
	// A compromised server can redirect subscription update notifications to redirect
	// auto-updating agents toward reading sensitive files.
	if kind == KindNotification && hp.handler.HandleResourcesUpdatedNotification(msg) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Record pending capability expansion check when server signals tool list changed.
	if kind == KindNotification {
		hp.handler.HandleToolsListChangedNotification(msg)
	}

	// Drop notifications/progress if the message field contains injection patterns.
	if kind == KindNotification && hp.handler.HandleProgressNotification(msg) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// Intercept roots/list responses (client→server direction in HTTP transport).
	// The server sent a roots/list request; the client is responding with root URIs.
	// Block if any root encompasses sensitive credential directories.
	if kind == KindResponse {
		if replacement := hp.handler.HandleRootsListResponse(body); replacement != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(replacement)
			return
		}
	}

	// Forward the request to the upstream server
	hp.forwardPost(w, r, body)
}

// forwardPost forwards a POST request to the upstream MCP server and relays
// the response back to the client. Handles both plain JSON and SSE responses.
func (hp *HTTPProxy) forwardPost(w http.ResponseWriter, origReq *http.Request, body []byte) {
	req, err := http.NewRequestWithContext(origReq.Context(), http.MethodPost, hp.cfg.UpstreamURL, bytes.NewReader(body))
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] error creating upstream request: %v\n", err)
		http.Error(w, "Internal proxy error", http.StatusBadGateway)
		return
	}

	// Copy relevant headers from the original request
	copyHeaders(req.Header, origReq.Header)
	req.Header.Set("Content-Type", "application/json")
	// The proxy negotiates compression for itself (copyHeaders withheld the
	// client's Accept-Encoding) and decodes the answer before scanning it.
	req.Header.Set("Accept-Encoding", "gzip")

	resp, err := hp.relayClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] upstream request failed: %v\n", err)
		http.Error(w, "Upstream server unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	ct := resp.Header.Get("Content-Type")

	if strings.Contains(ct, "text/event-stream") {
		// SSE response — stream events, scanning tools/list responses
		hp.relaySSE(w, resp)
	} else {
		// Plain JSON response — scan and forward
		hp.relayJSON(w, resp)
	}
}

// relayJSON reads a plain JSON response from upstream, routes it through the
// shared response-filter dispatch (filterJSONResponse), and writes it to the
// client.
//
// A response under a Content-Encoding is read in every form a client might
// read it (#4154): the decoded forms when the proxy can decode the coding —
// the client then receives the form it would have read, as identity — and
// otherwise the raw bytes, which is what a client that does not know the
// coding reads. Whatever form is forwarded was scanned first. A label is not
// evidence either way: a scanner hit on any form counts, and a form the proxy
// could not decode is forwarded under its declared headers with a receipt
// only when no scanner acted on it.
func (hp *HTTPProxy) relayJSON(w http.ResponseWriter, resp *http.Response) {
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] error reading upstream response: %v\n", err)
		http.Error(w, "Error reading upstream response", http.StatusBadGateway)
		return
	}

	contentEncoding := declaredContentEncoding(resp.Header)
	codings := contentCodings(contentEncoding)
	if n := len(knownCodings(codings)); n > maxContentCodings {
		hp.writeBlockedJSON(w, resp, hp.blockEncodingChain(contentEncoding, n))
		return
	}
	if len(codings) == 0 || len(raw) == 0 {
		if hp.screenRelayedJSON(w, resp, raw) {
			return
		}
		body, _ := hp.filterJSONResponse(raw)
		hp.writeJSONResponse(w, resp, body, false)
		return
	}

	// The form to forward is the first whose decoded bytes make a complete
	// JSON document, cleanly decoded if any form is (a container cut before
	// its trailer still carried the message, and every client's decoder is
	// lenient about that). A form that decodes to something else — a cut
	// prefix, or bytes that merely survived the decoder — is not a message
	// any client reads. Every other complete form is scanned as well, for
	// its audits; none of its bytes go out.
	var forward *decodeAttempt
	var lastErr error
	multiMember := false
	for _, d := range decodersFor(codings) {
		if d.single && !multiMember {
			// Every multistream form so far saw one gzip member, so this
			// single-member form would decode to the same bytes.
			continue
		}
		a := d.decodeAll(raw)
		multiMember = multiMember || a.multiMember
		if a.err != nil {
			lastErr = a.err
		}
		// #4158's depth BLOCK, on this form before anything else is asked
		// of it. complete() is json.Valid, which refuses nesting past the
		// decoder limit, so a deep body would otherwise read as "not a
		// message" and go out raw under its coding, where the client's
		// decoder reads it without complaint (the #4161 interaction).
		if blocked, errResp := hp.depthBlocked(a.out); blocked {
			hp.writeBlockedJSON(w, resp, errResp)
			return
		}
		switch {
		case !a.complete():
		case forward == nil:
			forward = &a
		case forward.err != nil && a.err == nil:
			// A clean decode outranks a cut one; the cut one still gets its scan.
			hp.filterJSONResponse(forward.out)
			forward = &a
		case !bytes.Equal(a.out, forward.out):
			hp.filterJSONResponse(a.out)
		}
	}

	if forward != nil {
		if forward.err != nil {
			_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] upstream %s body is a complete message despite a container error, relaying the decoded form: %v\n", forward.label, forward.err)
		}
		if hp.screenRelayedJSON(w, resp, forward.out) {
			return
		}
		body, _ := hp.filterJSONResponse(forward.out)
		hp.writeJSONResponse(w, resp, body, true)
		return
	}

	// No decoded form is a message. The raw bytes are the only form a client
	// can act on as they stand, so they are scanned exactly as an identity
	// body is and forwarded under their declared headers. The receipt records
	// bytes the proxy forwarded without having read them in the form the
	// label names; a scanner that acted has already written its own record.
	if hp.screenRelayedJSON(w, resp, raw) {
		return
	}
	body, acted := hp.filterJSONResponse(raw)
	if !acted {
		hp.auditUnscannableEncoding(contentEncoding, undecodableDetail(codings, lastErr))
	}
	hp.writeJSONResponse(w, resp, body, false)
}

// writeJSONResponse relays resp's headers and status with body. Content-Length
// is always recomputed (a Filter* replacement changes it); Content-Encoding is
// dropped when the body was decoded, because the client is receiving identity.
func (hp *HTTPProxy) writeJSONResponse(w http.ResponseWriter, resp *http.Response, body []byte, decoded bool) {
	for k, vs := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Content-Length" || (decoded && ck == "Content-Encoding") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// dispatchServerData routes a server→client message through the same shared
// filter dispatch the stdio proxy uses (proxy.go's proxyServerToClient →
// DispatchServerResponse). msg is the already-parsed message when data is a
// methodless message (isServerResponse); pass nil when data could not be
// parsed, or carries a method, so the full ordered chain runs instead of
// guessing — the same safety invariant DispatchServerResponse documents for
// its own ambiguous-shape case, applied one level up to "is this even a
// response".
//
// This used to be a hand-rolled copy of the filter list, separate from
// handler.go's responseFilterChain() — three response scanners shipped
// without ever being added here (#3989). Routing through the handler means a
// filter added to responseFilterChain() is wired to every transport at once.
func (hp *HTTPProxy) dispatchServerData(msg *Message, data []byte) []byte {
	if msg != nil {
		return hp.handler.DispatchServerResponse(msg, data)
	}
	return hp.handler.runResponseFilterChain(data)
}

// isServerResponse is the predicate that decides whether a parsed
// server→client message goes to the response dispatch. It is the SAME
// predicate the stdio proxy uses (proxy.go: `msg.Method == ""`), deliberately
// not `kind == KindResponse`: ClassifyMessage requires a non-null id for
// KindResponse, so an error envelope with `"id":null` (what the JSON-RPC spec
// mandates when the server could not read the request id) or no id at all
// classifies as KindUnknown. The first cut of #3989 keyed on the kind, and the
// SSE relay forwarded exactly those envelopes with their error.message
// unscanned — a regression against the hand-written list it replaced, which
// ran FilterErrorResponse on every data line (Codex pass 1, finding 1).
func isServerResponse(msg *Message) bool {
	return msg != nil && msg.Method == ""
}

// screenRelayedJSON is #4158's screen on a body about to be relayed: nesting
// past the decoder limit is answered with a parse error in its place,
// anything else unreadable is relayed with a receipt. It reports whether the
// reply has already been written.
func (hp *HTTPProxy) screenRelayedJSON(w http.ResponseWriter, resp *http.Response, body []byte) bool {
	if blocked, errResp := hp.handler.ScreenRelayedPayload(parseTransportHTTP, parseDirServerToClient, body); blocked {
		hp.writeBlockedJSON(w, resp, errResp)
		return true
	}
	return false
}

// filterJSONResponse routes one JSON body through the shared response-filter
// dispatch (dispatchServerData) and reports whether any scanner acted. A body
// that does not parse, or that carries a method, runs the full chain rather
// than being skipped; every scanner in it rejects a methodful message itself.
func (hp *HTTPProxy) filterJSONResponse(body []byte) ([]byte, bool) {
	msg, _, perr := ParseMessage(body)
	if perr != nil || !isServerResponse(msg) {
		msg = nil
	}
	if filtered := hp.dispatchServerData(msg, body); filtered != nil {
		return filtered, true
	}
	return body, false
}

// filterSSEData routes one event's data through the shared response-filter
// dispatch (dispatchServerData), the same one relayJSON uses. It returns
// (replacement, true) when a scanner rewrote the event, (nil, true) when one
// suppressed it, and (nil, false) when the event passes unchanged.
//
// Server-initiated requests and notifications arrive here too: in Streamable
// HTTP, server→client messages (sampling/createMessage, elicitation/create,
// notifications/*) come over SSE, not through handlePost, so this mirrors
// the stdio proxy's proxyServerToClient protection. A blocked server request
// can only be suppressed — there is no JSON-RPC error to send on the SSE
// channel — and the server then stalls waiting for a response, which is
// acceptable for a malicious request.
func (hp *HTTPProxy) filterSSEData(data []byte) ([]byte, bool) {
	// An event no scanner below could read: nesting past the decoder limit
	// is replaced by a parse error, anything else is relayed with a receipt
	// (#4158). This runs on whichever form is being relayed.
	if blocked, errResp := hp.handler.ScreenRelayedPayload(parseTransportHTTP, parseDirServerToClient, data); blocked {
		return errResp, true
	}
	msg, kind, perr := ParseMessage(data)
	if perr != nil || isServerResponse(msg) {
		// A methodless message — a response, whatever its id — or a body we
		// couldn't parse at all (the dispatch treats that the same as an
		// ambiguous response: run every filter rather than guess).
		var m *Message
		if perr == nil {
			m = msg
		}
		if filtered := hp.dispatchServerData(m, data); filtered != nil {
			return filtered, true
		}
		return nil, false
	}
	// A message with a method is never a response; every response scanner
	// rejects it, so only the server-initiated handling below applies.
	switch kind {
	case KindSamplingCreateMessage:
		if blocked, _ := hp.handler.HandleSamplingCreateMessage(msg); blocked {
			return nil, true
		}
	case KindElicitationCreate:
		if blocked, _ := hp.handler.HandleElicitationCreate(msg); blocked {
			return nil, true
		}
	case KindNotification:
		if hp.handler.HandleNotificationMessage(msg) {
			return nil, true
		}
		if hp.handler.HandleResourcesUpdatedNotification(msg) {
			return nil, true
		}
		hp.handler.HandleToolsListChangedNotification(msg)
		if hp.handler.HandleProgressNotification(msg) {
			return nil, true
		}
	}
	return nil, false
}

// relaySSE streams Server-Sent Events from upstream to the client, routing
// each event's data through the same shared filter dispatch relayJSON uses
// (filterSSEData), plus the server-initiated request/notification handling
// that only applies on the SSE channel.
//
// Under a Content-Encoding the stream is read in the forms a client might
// read it, in the order real clients try them (#4154), and the first form
// that yields anything is the one relayed: a decoder that fails before a
// byte has gone out hands the bytes it consumed to the next form, down to
// the raw line scan an identity body gets. The response headers go out
// before any decoder is built, so a compressed header that only arrives with
// the first event cannot hold them up; that is also why Content-Encoding is
// dropped up front whenever a decoder exists — whichever form is relayed,
// the client receives it as identity, the bytes the scanners saw. A coding
// the proxy cannot decode keeps its header and gets the raw line scan.
func (hp *HTTPProxy) relaySSE(w http.ResponseWriter, resp *http.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] warning: ResponseWriter does not support flushing\n")
		// Fall back to buffered relay
		hp.relayJSON(w, resp)
		return
	}

	contentEncoding := declaredContentEncoding(resp.Header)
	codings := contentCodings(contentEncoding)
	decoders := decodersFor(codings)
	chainBlocked := len(knownCodings(codings)) > maxContentCodings

	// Copy response headers, except Content-Length: a Filter* replacement changes
	// the body length, and a stale declared length truncates or aborts the
	// stream (#4129). Content-Encoding goes when the body is decoded here,
	// and when nothing of the body is relayed at all.
	for k, vs := range resp.Header {
		ck := http.CanonicalHeaderKey(k)
		if ck == "Content-Length" || ((len(decoders) > 0 || chainBlocked) && ck == "Content-Encoding") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	if chainBlocked {
		// There is no JSON-RPC error to send on the SSE channel; the stream
		// ends with no data relayed, and the receipt says why.
		hp.blockEncodingChain(contentEncoding, len(knownCodings(codings)))
		return
	}

	rec := newRecordingReader(resp.Body)
	var acted bool
	var lastErr error
	multiMember := false
	for _, d := range decoders {
		if d.single && !multiMember {
			continue // see relayJSON
		}
		var probe gzipProbe
		dec, err := d.openWith(rec, &probe)
		var written, events int
		if err == nil {
			var a bool
			written, events, a, err = hp.relaySSEStream(w, flusher, dec, rec.stop)
			acted = acted || a
		}
		multiMember = multiMember || probe.multiMember
		// The relay commits to a form that proved readable: it carried an
		// event (relayed or suppressed), or bytes went out, or it decoded
		// cleanly past the fallback bound. An error after that cut the
		// stream: every event already relayed was scanned, the remainder was
		// never read. A form that decoded to lines with no event in them was
		// not a message either. Both get a receipt.
		if written > 0 || events > 0 || rec.overflowed {
			switch {
			case err != nil:
				hp.auditUnscannableEncoding(contentEncoding, fmt.Sprintf(
					"%s stream failed after %d bytes were relayed (%d events seen), remainder not forwarded: %v", d.label, written, events, err))
			case events == 0:
				hp.auditUnscannableEncoding(contentEncoding, fmt.Sprintf(
					"%s stream decoded to %d bytes carrying no event", d.label, written))
			}
			return
		}
		if err != nil {
			lastErr = err
		}
		// Nothing has gone out: the next form starts again from the first byte.
		rec = newRecordingReader(rec.rewound())
	}

	// No decoded form produced anything: the raw lines are what a client that
	// treats the label as identity reads, so they get the scan an identity
	// stream gets, exactly as before #4154. The receipt records bytes the
	// proxy relayed without having read them in the form the label names;
	// a scanner that acted has already written its own record, and a body
	// that carried no bytes needs none.
	written, _, a, err := hp.relaySSEStream(w, flusher, rec.rewound(), nil)
	acted = acted || a
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] upstream SSE stream ended with error: %v\n", err)
	}
	if len(codings) > 0 && written > 0 && !acted {
		hp.auditUnscannableEncoding(contentEncoding, undecodableDetail(codings, lastErr))
	}
}

// relaySSEStream line-scans one form of the upstream stream, relaying each
// event the scanners pass or rewrite and suppressing the ones they block. It
// reports the bytes written to the client, the data lines it saw, whether
// any scanner acted, and the error that ended the stream, if any. onCommit,
// when set, runs once, as soon as the form has proved readable: at the first
// data line, or before the first byte goes out, whichever comes first.
func (hp *HTTPProxy) relaySSEStream(w http.ResponseWriter, flusher http.Flusher, r io.Reader, onCommit func()) (written, events int, acted bool, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
	commit := func() {
		if onCommit != nil {
			onCommit()
			onCommit = nil
		}
	}
	emit := func(format string, args ...interface{}) {
		commit()
		n, _ := fmt.Fprintf(w, format, args...)
		written += n
		flusher.Flush()
	}

	for scanner.Scan() {
		line := scanner.Text()

		// SSE data lines start with "data: "
		if strings.HasPrefix(line, "data: ") {
			events++
			commit()
			data := []byte(strings.TrimPrefix(line, "data: "))
			if out, hit := hp.filterSSEData(data); hit {
				acted = true
				if out != nil {
					emit("data: %s\n", out)
				} else {
					flusher.Flush()
				}
				continue
			}
		}

		// Forward the line as-is (including event:, id:, retry:, and empty lines)
		emit("%s\n", line)
	}
	return written, events, acted, scanner.Err()
}

// handleGet handles GET requests.
// In Streamable HTTP transport, GET is used to open an SSE stream for
// server-initiated notifications. We also intercept well-known discovery
// requests to scan OAuth AS metadata and A2A agent cards for spoofing attacks.
func (hp *HTTPProxy) handleGet(w http.ResponseWriter, r *http.Request) {
	// Extract the origin domain from the request host for domain-mismatch detection.
	originDomain := r.Host
	if h, _, err := net.SplitHostPort(originDomain); err == nil {
		originDomain = h
	}

	// Intercept OAuth AS metadata discovery (RFC 8414).
	intercepted, statusCode, body := interceptOAuthASMetadata(
		hp.cfg.UpstreamURL,
		r.URL.Path,
		originDomain,
		hp.client,
		hp.cfg.OnAudit,
		hp.cfg.ServerName,
		hp.stderr,
	)
	if intercepted {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write(body)
		return
	}

	// Intercept A2A agent card discovery (Google A2A protocol).
	intercepted, statusCode, body = interceptA2AAgentCard(
		hp.cfg.UpstreamURL,
		r.URL.Path,
		originDomain,
		hp.client,
		hp.cfg.OnAudit,
		hp.cfg.ServerName,
		hp.stderr,
	)
	if intercepted {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write(body)
		return
	}

	hp.proxyPassthrough(w, r)
}

// proxyPassthrough forwards a request to the upstream server with no
// message-level inspection (used for GET/DELETE and other non-POST methods).
func (hp *HTTPProxy) proxyPassthrough(w http.ResponseWriter, origReq *http.Request) {
	req, err := http.NewRequestWithContext(origReq.Context(), origReq.Method, hp.cfg.UpstreamURL, origReq.Body)
	if err != nil {
		http.Error(w, "Internal proxy error", http.StatusBadGateway)
		return
	}
	copyHeaders(req.Header, origReq.Header)

	// No Accept-Encoding of the proxy's own here: the non-SSE branch below
	// relays the body as it is, so it must arrive as the client can read it.
	resp, err := hp.relayClient.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] upstream %s failed: %v\n", origReq.Method, err)
		http.Error(w, "Upstream server unreachable", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		hp.relaySSE(w, resp)
	} else {
		// Copy headers and body
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// copyHeaders copies selected headers from src to dst, preserving
// MCP session headers and auth while filtering hop-by-hop headers.
//
// Accept-Encoding is the one "Accept" header that is never forwarded (#4154).
// A client's Accept-Encoding switches off http.Transport's transparent gzip
// decoding, so the upstream's compressed bytes reached relayJSON/relaySSE
// unreadable and went on to the client unscanned — and both reference SDKs
// send "gzip, deflate" by default, so that was the common case, not an
// adversarial one. Content negotiation belongs to the party that has to read
// the body: with the header withheld the transport asks for gzip itself and
// hands the scanners plaintext, and the client receives an identity body.
func copyHeaders(dst, src http.Header) {
	passthroughPrefixes := []string{
		"Mcp-",          // MCP session headers (Mcp-Session-Id, etc.)
		"Authorization", // Auth tokens
		"Accept",
		"Content-Type",
		"X-",
	}

	for key, values := range src {
		if http.CanonicalHeaderKey(key) == "Accept-Encoding" {
			continue
		}
		shouldCopy := false
		for _, prefix := range passthroughPrefixes {
			if strings.HasPrefix(key, prefix) {
				shouldCopy = true
				break
			}
		}
		if shouldCopy {
			for _, v := range values {
				dst.Add(key, v)
			}
		}
	}
}

// Response-body content codings (#4154).
//
// The proxy asks the upstream for gzip on its own behalf (forwardPost) and
// decodes whatever comes back itself; transparent transport decoding is off
// (NewHTTPProxy), so every declaration reaches this code whole. A body is
// read in every form a client might read it: gzip and x-gzip through
// compress/gzip; deflate first as the zlib-wrapped stream RFC 9110 specifies
// and then as the raw stream a well-known class of servers sends instead,
// which is the order httpx tries them; and chains of at most
// maxContentCodings codings. Every decoder streams, so an SSE stream flows
// event by event. A coding outside that set — br, zstd, an unknown token —
// is not decoded: the raw bytes get the scan an identity body gets and are
// forwarded under their declared headers, with a receipt
// (auditUnscannableEncoding) when no scanner acted; a client that decodes
// such a coding reads content the proxy could not inspect, a trade decided
// in favour of forwarding (Gary, 2026-10-02). A chain of more than
// maxContentCodings decodable codings is the exception and is BLOCKed; see
// responseEncodingChainExceededRuleID for why that denial is justified.

// maxContentCodings bounds the chains the proxy decodes; a longer chain is
// BLOCKed (responseEncodingChainExceededRuleID). No transport and no known
// server chains codings at all, and a chain is the one shape where a small
// body's inflation compounds layer on layer: measured at 2,302:1 for one
// layer and about 504,000:1 for two.
const maxContentCodings = 2

// responseEncodingFailOpenRuleID is the rule id on the receipt for a response
// relayed in a form the proxy could not read as the label named. It sits
// beside mcp-extract-fail-open: that one records "Shield could not read this
// message", this one "Shield could not read this body as declared". AUDIT
// and not BLOCK, deliberately: an unrecognised coding is not evidence of a
// threat, the raw bytes were scanned regardless, and refusing traffic on a
// shape the proxy merely does not recognise is the fail-closed default this
// codebase declines to ship.
const responseEncodingFailOpenRuleID = "mcp-response-encoding-fail-open"

// auditUnscannableEncoding emits the receipt for a response relayed under a
// Content-Encoding the proxy could not read as declared. A no-op when
// OnAudit is nil.
func (hp *HTTPProxy) auditUnscannableEncoding(contentEncoding, detail string) {
	_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] AUDIT: upstream response Content-Encoding %q: %s\n", contentEncoding, detail)
	if hp.cfg.OnAudit == nil {
		return
	}
	hp.cfg.OnAudit(AuditEntry{
		Timestamp:      time.Now().UTC().Format(time.RFC3339),
		ToolName:       "http-response",
		Decision:       "AUDIT",
		Flagged:        true,
		TriggeredRules: []string{responseEncodingFailOpenRuleID},
		Reasons:        []string{fmt.Sprintf("upstream response Content-Encoding %q: %s", contentEncoding, detail)},
		Source:         "mcp-proxy",
		ServerName:     hp.cfg.ServerName,
		TaxonomyRef:    securityMediatorParseFailOpenTaxonomyRef,
	})
}

// knownCodings is the subset of codings the proxy decodes, in order. The
// rest are read as identity, as every client reads a token it does not
// know, and do not count toward maxContentCodings.
func knownCodings(codings []string) []string {
	var known []string
	for _, c := range codings {
		switch c {
		case "gzip", "x-gzip", "deflate":
			known = append(known, c)
		}
	}
	return known
}

// responseEncodingChainExceededRuleID is the rule id on the BLOCK for a
// Content-Encoding chain of more than maxContentCodings codings the proxy
// decodes (Gary, 2026-10-02). A denial this codebase can justify: the shape
// is an enumerable count of codings; no legitimate server sends a response
// compressed three times over; and every SDK decodes a three-layer chain to
// the payload, so forwarding it with a receipt — what undecodable single
// codings get — would put unscanned content in front of the client. Shares
// the fail-open receipts' taxonomy node: a mediator/endpoint decoder
// differential is the technique, and this is the one instance of it the
// proxy can enumerate rather than merely record.
const responseEncodingChainExceededRuleID = "mcp-response-encoding-chain-exceeded"

// blockEncodingChain records the BLOCK for an over-long coding chain and
// returns the JSON-RPC parse-error reply that stands in for the response.
func (hp *HTTPProxy) blockEncodingChain(contentEncoding string, known int) []byte {
	reason := fmt.Sprintf(
		"upstream response Content-Encoding %q chains %d codings the proxy decodes, more than the %d it will decode — response not forwarded",
		contentEncoding, known, maxContentCodings)
	_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] BLOCKED %s\n", reason)
	if hp.cfg.OnAudit != nil {
		hp.cfg.OnAudit(AuditEntry{
			Timestamp:      time.Now().UTC().Format(time.RFC3339),
			ToolName:       "http-response",
			Decision:       "BLOCK",
			Flagged:        true,
			TriggeredRules: []string{responseEncodingChainExceededRuleID},
			Reasons:        []string{reason},
			Source:         "mcp-proxy",
			ServerName:     hp.cfg.ServerName,
			TaxonomyRef:    securityMediatorParseFailOpenTaxonomyRef,
		})
	}
	return newParseErrorResponse(fmt.Sprintf(
		"Blocked by AgentShield: Content-Encoding chains %d codings, more than the %d the proxy decodes — response not forwarded",
		known, maxContentCodings))
}

// depthBlocked applies #4158's depth BLOCK to one decoded form of a body.
// Only nesting is judged here: a form that is not forwarded earns no
// fail-open receipt, since nothing of it goes out unread.
func (hp *HTTPProxy) depthBlocked(form []byte) (bool, []byte) {
	if !jsonNestingExceeds(form, jsonMaxNestingDepth) {
		return false, nil
	}
	_, _, err := ParseMessage(form)
	return hp.handler.ScreenRelayedParseFailure(parseTransportHTTP, parseDirServerToClient, form, err)
}

// undecodableDetail names why no decoded form of a body was relayed.
func undecodableDetail(codings []string, lastErr error) string {
	switch known := len(knownCodings(codings)); {
	case known == 0:
		return "coding not supported by the proxy; raw bytes scanned as identity and forwarded unchanged"
	case lastErr == nil:
		return "the decoded form is not a message; raw bytes scanned as identity and forwarded unchanged"
	default:
		return fmt.Sprintf("no decoded form yielded a complete message (%v); raw bytes scanned as identity and forwarded unchanged", lastErr)
	}
}

// declaredContentEncoding is the response's full Content-Encoding list. An
// upstream may send it as several header lines, which HTTP defines as the
// comma-joined list in order; Header.Get would see only the first, and a
// list judged by its first token alone could be decoded as the wrong thing.
func declaredContentEncoding(h http.Header) string {
	return strings.Join(h.Values("Content-Encoding"), ",")
}

// contentCodings splits a Content-Encoding value into its lowercased tokens
// in application order, dropping "identity", which encodes nothing.
func contentCodings(header string) []string {
	var out []string
	for _, tok := range strings.Split(header, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" || tok == "identity" {
			continue
		}
		out = append(out, tok)
	}
	return out
}

// decodableCodings reports whether every token names a coding the standard
// library can stream-decode.
func decodableCodings(codings []string) bool {
	for _, c := range codings {
		switch c {
		case "gzip", "x-gzip", "deflate":
		default:
			return false
		}
	}
	return true
}

// decoder is one form in which a client might decode a body: the content
// codings peeled from the outside in, each read one way.
type decoder struct {
	label string
	forms []string
	// single marks a variant that reads some gzip layer as its first member
	// only. It decodes to the same bytes as the multistream variant unless a
	// second member exists, so callers run it only once a multistream
	// attempt has reported one (decodeAttempt.multiMember, gzipProbe).
	single bool
}

// decodersFor lists the forms a body under these codings might decode to, in
// the order real clients try them: nil when there is nothing the proxy can
// decode. A token the proxy does not know (br, zstd, a misspelling) is read
// as identity, which is what every client does with a token it does not
// know, so "gzip, x-unknown" has the one coding gzip; a client that does know
// such a token reads something the proxy cannot, and the receipt covers
// that. gzip contributes two forms — every member joined, as Node reads a
// gzip stream, then the first member alone, as httpx does — and deflate two,
// zlib then raw, so a chain of two codings yields up to four. The first
// variant always reads every layer the Node way.
func decodersFor(codings []string) []decoder {
	known := knownCodings(codings)
	if len(known) == 0 || len(known) > maxContentCodings {
		return nil
	}
	variants := [][]string{nil}
	for _, c := range known {
		var forms []string
		switch c {
		case "gzip", "x-gzip":
			forms = []string{"gzip", "gzip-single"}
		case "deflate":
			forms = []string{"zlib", "raw"}
		}
		var next [][]string
		for _, prefix := range variants {
			for _, f := range forms {
				next = append(next, append(append([]string(nil), prefix...), f))
			}
		}
		variants = next
	}
	out := make([]decoder, 0, len(variants))
	for _, forms := range variants {
		d := decoder{label: strings.Join(forms, ","), forms: forms}
		for _, f := range forms {
			if f == "gzip-single" {
				d.single = true
			}
		}
		out = append(out, d)
	}
	return out
}

// gzipProbe collects what the gzip readers in one form learned about the
// stream while decoding it.
type gzipProbe struct {
	multiMember bool // some gzip layer carried more than one member
}

// openWith wraps r with one streaming decoder per form, outermost first:
// codings are listed in the order they were applied, so the last is peeled
// first. gzip and zlib read their headers here; raw deflate reads nothing
// until the first Read.
func (d decoder) openWith(r io.Reader, probe *gzipProbe) (io.Reader, error) {
	for i := len(d.forms) - 1; i >= 0; i-- {
		var err error
		switch d.forms[i] {
		case "gzip":
			r, err = newGzipMembers(r, probe)
		case "gzip-single":
			var zr *gzip.Reader
			if zr, err = gzip.NewReader(r); err == nil {
				zr.Multistream(false)
				r = zr
			}
		case "zlib":
			r, err = zlib.NewReader(r)
		case "raw":
			r = flate.NewReader(r)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.forms[i], err)
		}
	}
	return r, nil
}

// gzipMembers reads a gzip stream member by member and joins the members,
// exactly as gzip.Reader does in multistream mode (and as Node's zlib reads
// an HTTP body), while noting when a second member begins. That is the one
// fact the first-member-only form (httpx's reading) hinges on, and learning
// it here saves decoding every ordinary one-member body twice.
type gzipMembers struct {
	src   io.Reader // a ByteReader, so Reset continues at the exact byte
	zr    *gzip.Reader
	probe *gzipProbe
	done  bool
	err   error // deferred: reported after the bytes read before it
}

func newGzipMembers(r io.Reader, probe *gzipProbe) (*gzipMembers, error) {
	if _, ok := r.(io.ByteReader); !ok {
		r = bufio.NewReader(r)
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	zr.Multistream(false)
	return &gzipMembers{src: r, zr: zr, probe: probe}, nil
}

func (g *gzipMembers) Read(p []byte) (int, error) {
	for {
		if g.done {
			return 0, g.err
		}
		n, err := g.zr.Read(p)
		if err != io.EOF {
			return n, err
		}
		// This member is finished. The next header, if any, follows at once;
		// no header is a clean end, a bad one is the error gzip.Reader
		// reports in multistream mode.
		switch rerr := g.zr.Reset(g.src); rerr {
		case nil:
			g.zr.Multistream(false)
			if g.probe != nil {
				g.probe.multiMember = true
			}
		case io.EOF:
			g.done, g.err = true, io.EOF
		default:
			g.done, g.err = true, rerr
		}
		if n > 0 {
			return n, nil
		}
	}
}

// decodeAttempt is one form of an in-memory body: the bytes it decoded to,
// possibly only a prefix, and the error that stopped the decoder, if any.
type decodeAttempt struct {
	label       string
	out         []byte
	err         error
	multiMember bool
}

func (d decoder) decodeAll(raw []byte) decodeAttempt {
	var probe gzipProbe
	r, err := d.openWith(bytes.NewReader(raw), &probe)
	if err != nil {
		return decodeAttempt{label: d.label, err: err}
	}
	out, err := io.ReadAll(r)
	return decodeAttempt{label: d.label, out: out, err: err, multiMember: probe.multiMember}
}

// complete reports whether the decoded bytes make a whole JSON document,
// whatever the decoder said about its container: a container cut before its
// trailer still carried the message, and every client's decoder is lenient
// about that. Bytes that merely survived a decoder are not a message.
func (a decodeAttempt) complete() bool { return len(a.out) > 0 && json.Valid(a.out) }

// maxSSEFallbackBytes bounds what recordingReader keeps for a fallback. The
// fallback exists for a decoder that rejects the stream before it has
// yielded anything — a wrong form fails on its header or its first block,
// within a few hundred bytes — so a form still decoding cleanly this far
// into the wire bytes is the right form, and relaySSE commits to it. Past
// the bound nothing is retained; the cost of being wrong is that a stream
// which then fails before any event ends with a receipt instead of a raw
// relay, which is fail-safe: nothing unscanned reaches the client.
const maxSSEFallbackBytes = 1 << 20

// recordingReader passes reads through and keeps a copy of every byte until
// stop is called or the bound is reached, so a decoder that fails before
// anything was relayed can hand the bytes it consumed to the next form.
type recordingReader struct {
	r          io.Reader
	buf        []byte
	stopped    bool
	overflowed bool // the bound was reached before stop: no fallback remains
}

func newRecordingReader(r io.Reader) *recordingReader { return &recordingReader{r: r} }

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	if !rr.stopped && n > 0 {
		if len(rr.buf)+n > maxSSEFallbackBytes {
			rr.overflowed = true
			rr.stop()
		} else {
			rr.buf = append(rr.buf, p[:n]...)
		}
	}
	return n, err
}

func (rr *recordingReader) stop() {
	rr.stopped = true
	rr.buf = nil
}

// rewound is the stream from its first byte again: everything recorded so
// far, then whatever the underlying reader has not yet given out.
func (rr *recordingReader) rewound() io.Reader {
	return io.MultiReader(bytes.NewReader(rr.buf), rr.r)
}
