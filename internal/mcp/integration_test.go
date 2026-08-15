package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// buildEchoServer compiles the test echo server and returns the path to the binary.
func buildEchoServer(t *testing.T) string {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(thisFile), "testdata")
	serverSrc := filepath.Join(testdataDir, "echo_server.go")

	tmpDir := t.TempDir()
	binary := filepath.Join(tmpDir, "echo_server")

	cmd := exec.Command("go", "build", "-o", binary, serverSrc)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to build echo server: %v", err)
	}

	return binary
}

// sendAndReceive sends a JSON-RPC request to the server's stdin and reads
// one line of response from stdout.
func sendAndReceive(t *testing.T, serverCmd *exec.Cmd, stdin *bufio.Writer, stdout *bufio.Scanner, request string) string {
	t.Helper()

	_, err := stdin.WriteString(request + "\n")
	if err != nil {
		t.Fatalf("failed to write to server: %v", err)
	}
	if err := stdin.Flush(); err != nil {
		t.Fatalf("failed to flush: %v", err)
	}

	if !stdout.Scan() {
		t.Fatal("no response from server")
	}
	return stdout.Text()
}

func TestIntegration_EchoServer_Direct(t *testing.T) {
	binary := buildEchoServer(t)

	cmd := exec.Command(binary)
	stdinPipe, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()

	stdin := bufio.NewWriter(stdinPipe)
	stdout := bufio.NewScanner(stdoutPipe)

	// Test tools/list
	resp := sendAndReceive(t, cmd, stdin, stdout,
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)

	var msg Message
	if err := json.Unmarshal([]byte(resp), &msg); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %v", msg.Error.Message)
	}

	var listResult ListToolsResult
	if err := json.Unmarshal(msg.Result, &listResult); err != nil {
		t.Fatalf("failed to parse tools list: %v", err)
	}
	if len(listResult.Tools) != 6 {
		t.Errorf("expected 6 tools, got %d", len(listResult.Tools))
	}

	// Test tools/call
	resp = sendAndReceive(t, cmd, stdin, stdout,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}`)

	if err := json.Unmarshal([]byte(resp), &msg); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if msg.Error != nil {
		t.Fatalf("unexpected error: %v", msg.Error.Message)
	}
	if !strings.Contains(string(msg.Result), "get_weather") {
		t.Errorf("expected echo of tool name in result, got: %s", string(msg.Result))
	}

	_ = stdinPipe.Close()
	_ = cmd.Wait()
}

func TestIntegration_ProxyWithEchoServer(t *testing.T) {
	binary := buildEchoServer(t)

	mcpPolicy := &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"execute_command"},
		Rules: []MCPRule{
			{
				ID: "block-etc-write",
				Match: MCPMatch{
					ToolName:         "write_file",
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Write to /etc/ blocked.",
			},
		},
	}

	evaluator := NewPolicyEvaluator(mcpPolicy)

	var auditLog []AuditEntry

	// Start echo server as child process
	serverCmd := exec.Command(binary)
	serverStdin, _ := serverCmd.StdinPipe()
	serverStdout, _ := serverCmd.StdoutPipe()
	serverCmd.Stderr = os.Stderr

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer func() { _ = serverCmd.Process.Kill() }()

	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		OnAudit: func(e AuditEntry) {
			auditLog = append(auditLog, e)
		},
		Stderr:              os.Stderr,
		SchemaDriftCacheDir: t.TempDir(), // isolate schema drift cache from real ~/.agentshield
	})

	// We'll use RunWithIO with the server's stdin/stdout pipes
	// and our own test reader/writer for the "client" side.

	// Prepare client messages
	clientMessages := []string{
		// 1. tools/list — should pass through
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		// 2. tools/call get_weather — should pass through (AUDIT)
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}`,
		// 3. tools/call execute_command — should be BLOCKED
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}`,
		// 4. tools/call write_file to /etc — should be BLOCKED by rule
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"evil"}}}`,
		// 5. tools/call read_file safe path — should pass through (AUDIT)
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/safe.txt"}}}`,
	}

	clientInput := strings.Join(clientMessages, "\n") + "\n"
	clientReader := strings.NewReader(clientInput)

	// We need to capture what the client receives
	clientOutputReader, clientOutputWriter, _ := os.Pipe()

	// Run proxy (client → proxy → server, server → proxy → client)
	done := make(chan struct{})
	go func() {
		proxy.RunWithIO(clientReader, clientOutputWriter, serverStdout, serverStdin)
		_ = clientOutputWriter.Close()
		close(done)
	}()

	// Read all client output
	var clientResponses []string
	scanner := bufio.NewScanner(clientOutputReader)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	// Use a timeout to avoid hanging
	responseDone := make(chan struct{})
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				clientResponses = append(clientResponses, line)
			}
		}
		close(responseDone)
	}()

	// Wait for proxy to finish
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy timed out")
	}

	// Wait for response reading to finish
	select {
	case <-responseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("response reading timed out")
	}

	_ = serverCmd.Process.Kill()
	_ = serverCmd.Wait()

	// Verify responses
	t.Logf("Got %d client responses", len(clientResponses))
	for i, r := range clientResponses {
		t.Logf("  Response %d: %s", i, truncate(r, 120))
	}

	// We should have:
	// - tools/list response (from server)
	// - get_weather response (from server)
	// - execute_command BLOCK (from proxy)
	// - write_file BLOCK (from proxy)
	// - read_file response (from server)
	if len(clientResponses) < 5 {
		t.Errorf("expected at least 5 responses, got %d", len(clientResponses))
	}

	// Check that blocked responses contain AgentShield
	blockedCount := 0
	for _, r := range clientResponses {
		if strings.Contains(r, "AgentShield") {
			blockedCount++
		}
	}
	if blockedCount != 2 {
		t.Errorf("expected 2 blocked responses, got %d", blockedCount)
	}

	// Check audit log
	t.Logf("Audit log entries: %d", len(auditLog))
	for _, e := range auditLog {
		t.Logf("  %s: %s → %s", e.ToolName, e.Decision, strings.Join(e.Reasons, "; "))
	}

	// Should have 5 audit entries:
	// 4 tools/call messages + 1 poisoned tool description from tools/list scan
	if len(auditLog) != 5 {
		t.Errorf("expected 5 audit entries, got %d", len(auditLog))
	}

	// Verify specific audit decisions
	decisions := map[string]string{}
	for _, e := range auditLog {
		decisions[e.ToolName] = e.Decision
	}

	if decisions["execute_command"] != "BLOCK" {
		t.Errorf("expected execute_command BLOCK, got %s", decisions["execute_command"])
	}
	if decisions["write_file"] != "BLOCK" {
		t.Errorf("expected write_file BLOCK, got %s", decisions["write_file"])
	}
	if decisions["get_weather"] != "AUDIT" {
		t.Errorf("expected get_weather AUDIT, got %s", decisions["get_weather"])
	}
	if decisions["read_file"] != "AUDIT" {
		t.Errorf("expected read_file AUDIT, got %s", decisions["read_file"])
	}
	if decisions["poisoned_add"] != "BLOCK" {
		t.Errorf("expected poisoned_add BLOCK (description poisoning), got %s", decisions["poisoned_add"])
	}

	// Verify the tools/list response sent to client has poisoned_add removed
	for _, r := range clientResponses {
		if strings.Contains(r, "poisoned_add") {
			t.Error("poisoned_add should have been hidden from tools/list response")
		}
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("... (%d chars)", len(s))
}
