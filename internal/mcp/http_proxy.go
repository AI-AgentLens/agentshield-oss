package mcp

import (
	"bufio"
	"bytes"
	"context"
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
}

// HTTPProxy is a transparent MCP Streamable HTTP reverse proxy that intercepts
// tools/call requests. It listens on a local HTTP endpoint, evaluates incoming
// JSON-RPC messages against policy, and forwards allowed requests to the
// upstream MCP server.
type HTTPProxy struct {
	cfg      HTTPProxyConfig
	handler  *MessageHandler
	client   *http.Client
	server   *http.Server
	stderr   io.Writer
	listener net.Listener
	mu       sync.Mutex
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
	return &HTTPProxy{
		cfg:    cfg,
		stderr: stderr,
		handler: &MessageHandler{
			Evaluator:   cfg.Evaluator,
			OnAudit:     cfg.OnAudit,
			Stderr:      stderr,
			ServerName:  cfg.ServerName,
			SchemaDrift: newSchemaDriftScannerWithDir(cfg.SchemaDriftCacheDir),
		},
		client: &http.Client{
			Timeout: 5 * time.Minute, // generous timeout for long-running tool calls
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
		// Can't parse — forward as-is (fail open)
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

	resp, err := hp.client.Do(req)
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

// relayJSON reads a plain JSON response from upstream, scans it for
// tools/list and tools/call poisoning, and writes it to the client.
func (hp *HTTPProxy) relayJSON(w http.ResponseWriter, resp *http.Response) {
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] error reading upstream response: %v\n", err)
		http.Error(w, "Error reading upstream response", http.StatusBadGateway)
		return
	}

	// Inspect initialize responses for handshake manipulation
	if filtered := hp.handler.FilterInitializeResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Scan for tools/list poisoning and manifest flooding
	if filtered := hp.handler.FilterToolsListResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Scan for tools/call response poisoning
	if filtered := hp.handler.FilterToolCallResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Scan for prompts/get response poisoning
	if filtered := hp.handler.FilterPromptsGetResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Scan for prompts/list description poisoning
	if filtered := hp.handler.FilterPromptsListResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Scan for completion/complete injection
	if filtered := hp.handler.FilterCompletionResponse(respBody); filtered != nil {
		respBody = filtered
	}

	// Copy response headers (skip Content-Length — we may have changed the body)
	for k, vs := range resp.Header {
		if k == "Content-Length" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(respBody)
}

// relaySSE streams Server-Sent Events from upstream to the client,
// scanning each event's data for tools/list poisoning.
func (hp *HTTPProxy) relaySSE(w http.ResponseWriter, resp *http.Response) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		_, _ = fmt.Fprintf(hp.stderr, "[AgentShield MCP-HTTP] warning: ResponseWriter does not support flushing\n")
		// Fall back to buffered relay
		hp.relayJSON(w, resp)
		return
	}

	// Copy response headers
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	flusher.Flush()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		// SSE data lines start with "data: "
		if strings.HasPrefix(line, "data: ") {
			data := []byte(strings.TrimPrefix(line, "data: "))

			// Inspect initialize responses for handshake manipulation
			if filtered := hp.handler.FilterInitializeResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}

			// Scan JSON-RPC data for tools/list poisoning and manifest flooding
			if filtered := hp.handler.FilterToolsListResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}

			// Scan JSON-RPC data for tools/call response poisoning
			if filtered := hp.handler.FilterToolCallResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}

			// Scan JSON-RPC data for prompts/get response poisoning
			if filtered := hp.handler.FilterPromptsGetResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}

			// Scan JSON-RPC data for prompts/list description poisoning
			if filtered := hp.handler.FilterPromptsListResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}

			// Scan JSON-RPC data for completion/complete injection
			if filtered := hp.handler.FilterCompletionResponse(data); filtered != nil {
				_, _ = fmt.Fprintf(w, "data: %s\n", filtered)
				flusher.Flush()
				continue
			}
		}

		// Forward the line as-is (including event:, id:, retry:, and empty lines)
		_, _ = fmt.Fprintf(w, "%s\n", line)
		flusher.Flush()
	}
}

// handleGet handles GET requests, which in Streamable HTTP transport are used
// for opening an SSE stream for server-initiated notifications.
// We proxy this through to the upstream server.
func (hp *HTTPProxy) handleGet(w http.ResponseWriter, r *http.Request) {
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

	resp, err := hp.client.Do(req)
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
func copyHeaders(dst, src http.Header) {
	passthroughPrefixes := []string{
		"Mcp-",          // MCP session headers (Mcp-Session-Id, etc.)
		"Authorization", // Auth tokens
		"Accept",
		"Content-Type",
		"X-",
	}

	for key, values := range src {
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
