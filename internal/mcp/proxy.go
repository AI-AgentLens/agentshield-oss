package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// AuditEntry records an MCP tool call decision for the audit log.
type AuditEntry struct {
	Timestamp      string                 `json:"timestamp"`
	ToolName       string                 `json:"tool_name"`
	Arguments      map[string]interface{} `json:"arguments,omitempty"`
	Decision       string                 `json:"decision"`
	Flagged        bool                   `json:"flagged,omitempty"`
	TriggeredRules []string               `json:"triggered_rules,omitempty"`
	Reasons        []string               `json:"reasons,omitempty"`
	Source         string                 `json:"source"`
	// ServerName identifies which MCP server received (or would have received) this call.
	// Populated from ProxyConfig.ServerName so audit consumers know the call target.
	ServerName string `json:"server_name,omitempty"`
	// TaxonomyRef links the audit event to a taxonomy entry.
	// Populated for Go-implemented intercepts (e.g. roots/list guard).
	TaxonomyRef string `json:"taxonomy_ref,omitempty"`
}

// AuditFunc is a callback for logging audit entries.
// The proxy calls this for every tools/call it intercepts.
type AuditFunc func(entry AuditEntry)

// ProxyConfig holds configuration for the MCP stdio proxy.
type ProxyConfig struct {
	// ServerCmd is the command to launch the real MCP server (e.g., "npx", "-y", "@modelcontextprotocol/server-filesystem").
	ServerCmd []string

	// Evaluator is the MCP policy evaluator.
	Evaluator *PolicyEvaluator

	// OnAudit is called for every intercepted tools/call decision.
	OnAudit AuditFunc

	// Stderr is where proxy diagnostic messages go. Defaults to os.Stderr.
	Stderr io.Writer

	// ServerName is the human-readable name of the downstream MCP server,
	// recorded in audit entries so consumers know the call target.
	// If empty, derived from ServerCmd by the caller.
	ServerName string

	// SchemaDriftCacheDir overrides the directory used for the schema drift cache.
	// When empty, defaults to ~/.agentshield. Set to t.TempDir() in tests to avoid
	// polluting the real cache and ensure test isolation.
	SchemaDriftCacheDir string
}

// Proxy is a transparent MCP stdio proxy that intercepts tools/call requests.
type Proxy struct {
	cfg       ProxyConfig
	handler   *MessageHandler
	serverCmd *exec.Cmd
	stderr    io.Writer
}

// NewProxy creates a new MCP stdio proxy with the given configuration.
func NewProxy(cfg ProxyConfig) *Proxy {
	stderr := cfg.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	return &Proxy{
		cfg:    cfg,
		stderr: stderr,
		handler: &MessageHandler{
			Evaluator:    cfg.Evaluator,
			OnAudit:      cfg.OnAudit,
			Stderr:       stderr,
			ServerName:   cfg.ServerName,
			SchemaDrift:  newSchemaDriftScannerWithDir(cfg.SchemaDriftCacheDir),
			ToolRegistry: newToolRegistryWithDir(cfg.SchemaDriftCacheDir),
		},
	}
}

// Run starts the proxy: spawns the child MCP server, bridges stdin/stdout,
// and intercepts tools/call requests for policy evaluation.
// Blocks until both the client (stdin) and server process finish.
func (p *Proxy) Run() error {
	if len(p.cfg.ServerCmd) == 0 {
		return fmt.Errorf("no server command specified")
	}

	// Spawn the real MCP server as a child process.
	p.serverCmd = exec.Command(p.cfg.ServerCmd[0], p.cfg.ServerCmd[1:]...)
	p.serverCmd.Stderr = p.stderr

	serverStdin, err := p.serverCmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create server stdin pipe: %w", err)
	}
	serverStdout, err := p.serverCmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create server stdout pipe: %w", err)
	}

	if err := p.serverCmd.Start(); err != nil {
		return fmt.Errorf("failed to start MCP server: %w", err)
	}

	var wg sync.WaitGroup

	// Client → Proxy → Server (intercept tools/call)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverStdin.Close() }()
		p.proxyClientToServer(os.Stdin, serverStdin, os.Stdout)
	}()

	// Server → Proxy → Client (pass through)
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyServerToClient(serverStdout, os.Stdout)
	}()

	wg.Wait()

	// Wait for the server process to exit.
	if err := p.serverCmd.Wait(); err != nil {
		return fmt.Errorf("MCP server exited with error: %w", err)
	}

	return nil
}

// proxyClientToServer reads JSON-RPC messages from the client (IDE),
// evaluates tools/call requests, and either forwards or blocks them.
func (p *Proxy) proxyClientToServer(clientReader io.Reader, serverWriter io.Writer, clientWriter io.Writer) {
	scanner := bufio.NewScanner(clientReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // up to 10MB per message

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		// JSON-RPC 2.0 batch request (JSON array): evaluate each item individually.
		// Block the entire batch if any item violates policy (fail-closed).
		if IsBatch(line) {
			msgs, err := ParseBatch(line)
			if err != nil {
				_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] warning: failed to parse batch, forwarding: %v\n", err)
				writeLineToWriter(serverWriter, line)
				continue
			}
			blocked, batchResp := p.handler.HandleBatch(msgs)
			if blocked {
				writeLineToWriter(clientWriter, batchResp)
				continue
			}
			writeLineToWriter(serverWriter, line)
			continue
		}

		msg, kind, err := ParseMessage(line)
		if err != nil {
			// Can't parse — forward as-is (fail open)
			_, _ = fmt.Fprintf(p.stderr, "[AgentShield MCP] warning: failed to parse message, forwarding: %v\n", err)
			writeLineToWriter(serverWriter, line)
			continue
		}

		if kind == KindToolCall {
			blocked, blockResp := p.handler.HandleToolCall(msg)
			if blocked {
				// Send JSON-RPC error back to client; don't forward to server
				writeLineToWriter(clientWriter, blockResp)
				continue
			}
		}

		if kind == KindResourceRead {
			blocked, blockResp := p.handler.HandleResourceRead(msg)
			if blocked {
				writeLineToWriter(clientWriter, blockResp)
				continue
			}
		}

		if kind == KindResourceSubscribe {
			blocked, blockResp := p.handler.HandleResourceSubscribe(msg)
			if blocked {
				writeLineToWriter(clientWriter, blockResp)
				continue
			}
		}

		// roots/list responses (client→server): intercept to detect overbroad root declarations.
		// The server sent a roots/list REQUEST; the client is now responding with root URIs.
		// We inspect the response before forwarding to catch privilege escalation attempts.
		if kind == KindResponse {
			if replacement := p.handler.HandleRootsListResponse(line); replacement != nil {
				writeLineToWriter(clientWriter, replacement)
				continue
			}
		}

		// Forward all non-blocked messages to the server
		writeLineToWriter(serverWriter, line)
	}
}

// proxyServerToClient reads messages from the MCP server, scans tools/list
// responses for poisoned tool descriptions and tools/call responses for
// poisoned content, then forwards to the client.
func (p *Proxy) proxyServerToClient(serverReader io.Reader, clientWriter io.Writer) {
	scanner := bufio.NewScanner(serverReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()

		// Inspect initialize responses for handshake manipulation (downgrade, impersonation, capability injection)
		if filtered := p.handler.FilterInitializeResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan tools/list responses for poisoned tool descriptions and manifest flooding
		if filtered := p.handler.FilterToolsListResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan tools/call responses for poisoned response content
		if filtered := p.handler.FilterToolCallResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan resources/read responses for content injection
		if filtered := p.handler.FilterResourceReadResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan resources/list responses for URI template injection
		if filtered := p.handler.FilterResourceListResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan prompts/get responses for injected prompt template content
		if filtered := p.handler.FilterPromptsGetResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan prompts/list responses for poisoned prompt descriptions
		if filtered := p.handler.FilterPromptsListResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Scan completion/complete responses for injected suggestion values
		if filtered := p.handler.FilterCompletionResponse(line); filtered != nil {
			writeLineToWriter(clientWriter, filtered)
			continue
		}

		// Intercept sampling/createMessage, elicitation/create, and notifications/message (server→client)
		msg, kind, err := ParseMessage(line)
		if err == nil {
			switch kind {
			case KindSamplingCreateMessage:
				blocked, blockResp := p.handler.HandleSamplingCreateMessage(msg)
				if blocked {
					writeLineToWriter(clientWriter, blockResp)
					continue
				}
			case KindElicitationCreate:
				blocked, blockResp := p.handler.HandleElicitationCreate(msg)
				if blocked {
					writeLineToWriter(clientWriter, blockResp)
					continue
				}
			case KindNotification:
				// Drop notifications/message payloads containing injection patterns.
				// Notifications have no ID so we cannot send a JSON-RPC error back —
				// we simply suppress the notification to prevent it reaching the client.
				if p.handler.HandleNotificationMessage(msg) {
					continue
				}
			}
		}

		writeLineToWriter(clientWriter, line)
	}
}

// NOTE: evaluateToolCall, evaluateResourceRead, and filterToolsListResponse
// logic is now in handler.go (MessageHandler). The stdio Proxy delegates to
// p.handler for all message evaluation.

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

// writeLineToWriter writes a line followed by a newline to the writer.
func writeLineToWriter(w io.Writer, data []byte) {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, data...)
	buf = append(buf, '\n')
	_, _ = w.Write(buf)
}

// RunWithIO is like Run but accepts explicit reader/writer for testability.
// It does NOT spawn a child process — the caller provides the server I/O.
// serverWriter should be an io.WriteCloser so the proxy can signal the server
// that the client is done (by closing its stdin).
func (p *Proxy) RunWithIO(clientReader io.Reader, clientWriter io.Writer, serverReader io.Reader, serverWriter io.WriteCloser) {
	var wg sync.WaitGroup
	// clientWriter is shared by both proxy directions; wrap it to avoid data races
	clientWriter = &lockedWriter{w: clientWriter}

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { _ = serverWriter.Close() }() // signal server that client is done
		p.proxyClientToServer(clientReader, serverWriter, clientWriter)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		p.proxyServerToClient(serverReader, clientWriter)
	}()

	wg.Wait()
}

// ArgumentsToJSON serializes tool arguments to a JSON string for logging.
func ArgumentsToJSON(args map[string]interface{}) string {
	if args == nil {
		return "{}"
	}
	data, err := json.Marshal(args)
	if err != nil {
		return "{}"
	}
	return string(data)
}
