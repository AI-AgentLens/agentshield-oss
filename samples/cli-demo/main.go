// Package main is the AgentShield CLI deployment demo.
//
// It demonstrates the REAL production deployment path — the agentshield binary
// runs as a stdio proxy between a client and an MCP server, identical to how
// it is installed in Cursor or Claude Desktop via `agentshield setup mcp`.
//
// Architecture:
//
//	demo-client (this program)
//	    │  stdin/stdout JSON-RPC
//	    ▼
//	agentshield mcp-proxy --mcp-policy demo.yaml -- demo-server   ← real binary
//	    │  stdin/stdout JSON-RPC
//	    ▼
//	demo-server (samples/mcp-demo/server — same server used by mcp-demo)
//
// Usage (from repo root):
//
//	go run ./samples/cli-demo/
//
// Flags:
//
//	--quiet    Suppress per-scenario output; only print summary
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ─── ANSI colours ────────────────────────────────────────────────────────────

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// ─── Demo policy ──────────────────────────────────────────────────────────────

// demoPolicy is written to a temp file and passed to agentshield via --mcp-policy.
// It covers the same attack categories as the mcp-demo, kept minimal for clarity.
const demoPolicy = `defaults:
  decision: "AUDIT"

blocked_tools:
  - "execute_command"
  - "run_shell"

rules:
  - id: demo-block-etc-write
    match:
      tool_name_any: ["write_file", "create_file"]
      argument_patterns:
        path: "/etc/**"
    decision: "BLOCK"
    reason: "File write to /etc/ system directory is blocked."

resource_rules:
  - id: demo-block-ssh-resource
    match:
      uri_regex: "file://.*\\.ssh"
    decision: "BLOCK"
    reason: "SSH key resource access is blocked."

value_limits:
  - id: demo-cap-token-transfer
    tool_name_regex: "send_.*"
    argument: "amount"
    max: 1000.0
    decision: "BLOCK"
    reason: "Token transfer exceeds the 1,000-unit safety limit."
`

// ─── Scenarios ────────────────────────────────────────────────────────────────

type scenario struct {
	id       int
	label    string // display name
	layer    string // which AgentShield layer catches this
	expected string // "BLOCK", "AUDIT", "HIDDEN"
	msg      string // raw JSON-RPC line
}

var sshKeyContent = strings.ReplaceAll(
	"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29T2EXAMPLE\n-----END RSA PRIVATE KEY-----",
	"\n", `\n`,
)

func buildScenarios() []scenario {
	home := os.Getenv("HOME")
	return []scenario{
		{
			id:       1,
			label:    "execute_command",
			layer:    "blocked-tool list",
			expected: "BLOCK",
			msg:      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /tmp/data"}}}`,
		},
		{
			id:       2,
			label:    "write_file → /etc/passwd",
			layer:    "policy rule",
			expected: "BLOCK",
			msg:      `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"malicious"}}}`,
		},
		{
			id:       3,
			label:    "store_data (SSH private key)",
			layer:    "content scan",
			expected: "BLOCK",
			msg:      fmt.Sprintf(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"store_data","arguments":{"key":"backup","value":"%s"}}}`, sshKeyContent),
		},
		{
			id:       4,
			label:    "send_tokens (52,000,000 SOL)",
			layer:    "value limit",
			expected: "BLOCK",
			msg:      `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"0xAttacker","amount":52000000,"token":"SOL"}}}`,
		},
		{
			id:       5,
			label:    "tools/list (poisoned desc)",
			layer:    "description scan",
			expected: "HIDDEN",
			msg:      `{"jsonrpc":"2.0","id":5,"method":"tools/list"}`,
		},
		{
			id:       6,
			label:    "resources/read ~/.ssh/id_rsa",
			layer:    "resource rule",
			expected: "BLOCK",
			msg:      fmt.Sprintf(`{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"file://%s/.ssh/id_rsa"}}`, home),
		},
		{
			id:       7,
			label:    "get_weather (benign)",
			layer:    "—",
			expected: "AUDIT",
			msg:      `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"San Francisco"}}}`,
		},
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	quiet := flag.Bool("quiet", false, "Only print the summary")
	flag.Parse()

	sep := strings.Repeat("─", 70)
	fmt.Println(colorBold + "AgentShield CLI Deployment Demo" + colorReset)
	fmt.Println(colorDim + "Real binary · Real proxy · Real policy evaluation" + colorReset)
	fmt.Println(colorDim + sep + colorReset)

	// ── 1. Build agentshield binary ──
	if !*quiet {
		fmt.Print("Building agentshield binary … ")
	}
	agentshieldBin, cleanAS, err := buildBinary("cmd/agentshield", "agentshield")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nfailed: %v\n", err)
		os.Exit(1)
	}
	defer cleanAS()
	if !*quiet {
		fmt.Println("ok")
	}

	// ── 2. Build demo server binary ──
	if !*quiet {
		fmt.Print("Building demo server … ")
	}
	serverBin, cleanSrv, err := buildBinary("samples/mcp-demo/server", "demo-server")
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nfailed: %v\n", err)
		os.Exit(1)
	}
	defer cleanSrv()
	if !*quiet {
		fmt.Println("ok")
	}

	// ── 3. Write policy to temp file ──
	policyFile, err := os.CreateTemp("", "agentshield-demo-policy-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp policy: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = os.Remove(policyFile.Name()) }()
	if _, err := policyFile.WriteString(demoPolicy); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write policy: %v\n", err)
		os.Exit(1)
	}
	_ = policyFile.Close()

	if !*quiet {
		fmt.Printf("\nProxy:  %s mcp-proxy\n", agentshieldBin)
		fmt.Printf("Server: %s\n", serverBin)
		fmt.Printf("Policy: %s\n", policyFile.Name())
		fmt.Println(colorDim + sep + colorReset)
	}

	// ── 4. Launch: agentshield mcp-proxy --mcp-policy <file> -- demo-server ──
	proxyCmd := exec.Command(agentshieldBin,
		"mcp-proxy",
		"--mcp-policy", policyFile.Name(),
		"--", serverBin,
	)
	proxyCmd.Stderr = os.Stderr // show live proxy diagnostics on stderr

	proxyStdin, err := proxyCmd.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stdin pipe error: %v\n", err)
		os.Exit(1)
	}
	proxyStdout, err := proxyCmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "stdout pipe error: %v\n", err)
		os.Exit(1)
	}
	if err := proxyCmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start agentshield proxy: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		_ = proxyCmd.Process.Kill()
		_ = proxyCmd.Wait()
	}()

	// ── 5. Send initialize + all scenario messages ──
	scenarios := buildScenarios()
	go func() {
		defer func() { _ = proxyStdin.Close() }()
		// MCP requires an initialize handshake before tool calls
		init := `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cli-demo","version":"1.0"}}}`
		_, _ = fmt.Fprintln(proxyStdin, init)
		for _, s := range scenarios {
			_, _ = fmt.Fprintln(proxyStdin, s.msg)
		}
	}()

	// ── 6. Collect responses (keyed by JSON-RPC id) ──
	responses := make(map[int]string)
	scanner := bufio.NewScanner(proxyStdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == "" {
				continue
			}
			var msg struct {
				ID *json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal([]byte(line), &msg); err != nil || msg.ID == nil {
				continue
			}
			var id float64
			if err := json.Unmarshal(*msg.ID, &id); err != nil {
				continue
			}
			responses[int(id)] = line
		}
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		fmt.Fprintln(os.Stderr, "\ntimeout waiting for proxy responses")
		os.Exit(1)
	}

	// ── 7. Print results table ──
	fmt.Printf("\n%-3s  %-34s  %-18s  %s\n", "#", "Tool / Request", "Layer", "Decision")
	fmt.Println(colorDim + strings.Repeat("─", 80) + colorReset)

	counts := map[string]int{}
	for _, s := range scenarios {
		decision := classifyResponse(s, responses)
		counts[decision]++
		if !*quiet {
			fmt.Printf("%-3d  %-34s  %-18s  %s\n",
				s.id,
				truncate(s.label, 34),
				truncate(s.layer, 18),
				formatDecision(decision),
			)
		}
	}

	fmt.Println()
	fmt.Println(colorDim + strings.Repeat("─", 70) + colorReset)
	fmt.Printf(colorBold+"Results: %s%d BLOCKED%s  %s%d AUDITED%s  %s%d HIDDEN%s\n"+colorReset,
		colorRed, counts["BLOCK"], colorReset,
		colorYellow, counts["AUDIT"], colorReset,
		colorCyan, counts["HIDDEN"], colorReset,
	)
	fmt.Println(colorDim + strings.Repeat("─", 70) + colorReset)
}

// ─── Response classification ──────────────────────────────────────────────────

// classifyResponse determines the actual decision from the JSON-RPC response.
func classifyResponse(s scenario, responses map[int]string) string {
	raw, ok := responses[s.id]
	if !ok {
		return "?"
	}

	// HIDDEN: tools/list response must not contain the poisoned tool name
	if s.expected == "HIDDEN" {
		if !strings.Contains(raw, "calc_gas_fee") {
			return "HIDDEN"
		}
		return "PASS" // poisoning not caught
	}

	// BLOCK: agentshield returns a JSON-RPC error with "AgentShield" in message
	var resp struct {
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return "?"
	}
	if resp.Error != nil && strings.Contains(resp.Error.Message, "AgentShield") {
		return "BLOCK"
	}
	return "AUDIT"
}

// ─── Formatting ───────────────────────────────────────────────────────────────

func formatDecision(d string) string {
	switch d {
	case "BLOCK":
		return colorRed + colorBold + "🔴 BLOCK" + colorReset
	case "AUDIT":
		return colorYellow + "🟡 AUDIT" + colorReset
	case "HIDDEN":
		return colorCyan + "🫥 HIDDEN" + colorReset
	default:
		return colorDim + "? (" + d + ")" + colorReset
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ─── Build helpers ────────────────────────────────────────────────────────────

// buildBinary compiles the Go package at pkgRelPath (relative to module root)
// to a temp binary named binName. Returns (binaryPath, cleanup, error).
func buildBinary(pkgRelPath, binName string) (string, func(), error) {
	root, err := findModuleRoot()
	if err != nil {
		return "", nil, err
	}

	tmpDir, err := os.MkdirTemp("", "agentshield-cli-demo-*")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(tmpDir) }

	binPath := filepath.Join(tmpDir, binName)
	cmd := exec.Command("go", "build", "-o", binPath, filepath.Join(root, pkgRelPath))
	cmd.Dir = root
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("go build %s: %w", pkgRelPath, err)
	}
	return binPath, cleanup, nil
}

// findModuleRoot walks up from cwd until it finds a go.mod file.
func findModuleRoot() (string, error) {
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}
