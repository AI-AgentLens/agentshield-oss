package mcp

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// runProxyScenario builds the echo server, configures a proxy with the given
// policy, sends clientMessages through the proxy, and returns the client
// responses and audit log entries.
func runProxyScenario(t *testing.T, pol *MCPPolicy, clientMessages []string) (responses []string, audit []AuditEntry) {
	t.Helper()

	binary := buildEchoServer(t)

	serverCmd := exec.Command(binary)
	serverStdin, _ := serverCmd.StdinPipe()
	serverStdout, _ := serverCmd.StdoutPipe()
	serverCmd.Stderr = io.Discard

	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start echo server: %v", err)
	}
	defer func() { _ = serverCmd.Process.Kill(); _ = serverCmd.Wait() }()

	evaluator := NewPolicyEvaluator(pol)
	var auditMu sync.Mutex
	proxy := NewProxy(ProxyConfig{
		Evaluator: evaluator,
		OnAudit: func(e AuditEntry) {
			auditMu.Lock()
			defer auditMu.Unlock()
			audit = append(audit, e)
		},
		Stderr: io.Discard,
	})

	clientInput := strings.Join(clientMessages, "\n") + "\n"
	clientReader := strings.NewReader(clientInput)
	clientOutputReader, clientOutputWriter, _ := os.Pipe()

	done := make(chan struct{})
	go func() {
		proxy.RunWithIO(clientReader, clientOutputWriter, serverStdout, serverStdin)
		_ = clientOutputWriter.Close()
		close(done)
	}()

	responseDone := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(clientOutputReader)
		scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) != "" {
				responses = append(responses, line)
			}
		}
		close(responseDone)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy timed out")
	}
	select {
	case <-responseDone:
	case <-time.After(5 * time.Second):
		t.Fatal("response reading timed out")
	}

	return responses, audit
}

// assertAuditDecision checks that the audit log contains an entry for the given
// tool with the expected decision.
func assertAuditDecision(t *testing.T, audit []AuditEntry, toolName, expectedDecision string) {
	t.Helper()
	for _, e := range audit {
		if e.ToolName == toolName {
			if e.Decision != expectedDecision {
				t.Errorf("expected %s %s, got %s (reasons: %v)", toolName, expectedDecision, e.Decision, e.Reasons)
			}
			return
		}
	}
	t.Errorf("no audit entry found for tool %s", toolName)
}

// assertResponseBlocked checks that at least one response contains AgentShield
// block text for the given JSON-RPC id.
func assertResponseBlocked(t *testing.T, responses []string, id int) {
	t.Helper()
	idStr := `"id":` // We'll check for id in the error response
	for _, r := range responses {
		var msg Message
		if err := json.Unmarshal([]byte(r), &msg); err != nil {
			continue
		}
		if msg.ID == nil {
			continue
		}
		var respID float64
		if err := json.Unmarshal(*msg.ID, &respID); err != nil {
			continue
		}
		if int(respID) == id && msg.Error != nil && strings.Contains(msg.Error.Message, "AgentShield") {
			return
		}
	}
	_ = idStr
	t.Errorf("expected blocked response for id %d, not found", id)
}

// assertResponseAllowed checks that a response for the given JSON-RPC id
// does NOT contain an AgentShield block error.
func assertResponseAllowed(t *testing.T, responses []string, id int) {
	t.Helper()
	for _, r := range responses {
		var msg Message
		if err := json.Unmarshal([]byte(r), &msg); err != nil {
			continue
		}
		if msg.ID == nil {
			continue
		}
		var respID float64
		if err := json.Unmarshal(*msg.ID, &respID); err != nil {
			continue
		}
		if int(respID) == id {
			if msg.Error != nil && strings.Contains(msg.Error.Message, "AgentShield") {
				t.Errorf("expected allowed response for id %d, got block: %s", id, msg.Error.Message)
			}
			return
		}
	}
	t.Errorf("no response found for id %d", id)
}

// --- Red-team MCP integration tests ---

// mcp-rt-001: Blocked tool list — execute_command always blocked
func TestMCPRedTeam_BlockedTool(t *testing.T) {
	pol := &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"execute_command"},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"rm -rf /"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertAuditDecision(t, audit, "execute_command", "BLOCK")
}

// mcp-rt-002: Argument pattern rule — block writes to /etc
func TestMCPRedTeam_ArgumentPatternBlock(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
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

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/passwd","content":"evil"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/safe.txt","content":"ok"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseAllowed(t, responses, 2)
	assertAuditDecision(t, audit, "write_file", "BLOCK") // first match
}

// mcp-rt-003: Content scanning — SSH private key in arguments
func TestMCPRedTeam_SecretInArguments_SSHKey(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	sshKey := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n-----END RSA PRIVATE KEY-----"

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/notes.txt","content":"` + strings.ReplaceAll(sshKey, "\n", "\\n") + `"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertAuditDecision(t, audit, "write_file", "BLOCK")

	// Verify the reason mentions content scan
	for _, e := range audit {
		if e.ToolName == "write_file" {
			foundContentScan := false
			for _, rule := range e.TriggeredRules {
				if rule == "argument-content-scan" {
					foundContentScan = true
				}
			}
			if !foundContentScan {
				t.Error("expected argument-content-scan in triggered rules")
			}
		}
	}
}

// mcp-rt-004: Content scanning — AWS credentials in arguments
func TestMCPRedTeam_SecretInArguments_AWSKey(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/config","content":"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertAuditDecision(t, audit, "write_file", "BLOCK")
}

// mcp-rt-005: Value limits — Lobstar Wilde scenario (52M tokens instead of 4)
func TestMCPRedTeam_ValueLimit_LobstarWilde(t *testing.T) {
	maxAmount := 100.0
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ValueLimits: []ValueLimitRule{
			{
				ID:            "block-large-transfer",
				ToolNameRegex: "send_.*",
				Argument:      "amount",
				Max:           &maxAmount,
				Decision:      policy.DecisionBlock,
				Reason:        "Transfer exceeds safety limit.",
			},
		},
	}

	msgs := []string{
		// Lobstar Wilde: agent tries to send 52,000,000 instead of 4
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"0xWallet","amount":52000000,"token":"SOL"}}}`,
		// Small transfer: should pass
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"0xWallet","amount":4,"token":"SOL"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseAllowed(t, responses, 2)

	// Verify correct audit
	for _, e := range audit {
		if e.ToolName == "send_tokens" && e.Decision == "BLOCK" {
			foundValueLimit := false
			for _, rule := range e.TriggeredRules {
				if rule == "value-limit" {
					foundValueLimit = true
				}
			}
			if !foundValueLimit {
				t.Error("expected value-limit in triggered rules for blocked transfer")
			}
			return
		}
	}
}

// mcp-rt-006: Config file guard — block writes to IDE config
func TestMCPRedTeam_ConfigGuard_IDEConfig(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		// Try to write to ~/.cursor/mcp.json (config guard should catch)
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.cursor/mcp.json","content":"{}"}}}`,
		// Try to write to ~/.cursor/hooks.json
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.cursor/hooks.json","content":"{}"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseBlocked(t, responses, 2)

	for _, e := range audit {
		if e.Decision == "BLOCK" {
			foundGuard := false
			for _, rule := range e.TriggeredRules {
				if rule == "config-file-guard" {
					foundGuard = true
				}
			}
			if !foundGuard {
				t.Errorf("expected config-file-guard for %s, got rules: %v", e.ToolName, e.TriggeredRules)
			}
		}
	}
}

// mcp-rt-007: Config file guard — block writes to shell dotfiles
func TestMCPRedTeam_ConfigGuard_ShellDotfiles(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.bashrc","content":"alias sudo=evil"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.zshrc","content":"export PATH=/evil:$PATH"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseBlocked(t, responses, 2)

	for _, e := range audit {
		assertAuditDecision(t, audit, e.ToolName, "BLOCK")
	}
}

// mcp-rt-008: Tool description poisoning detection
func TestMCPRedTeam_ToolDescriptionPoisoning(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		// Request tools/list — the echo server includes a poisoned tool
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)

	// The poisoned_add tool should be stripped from the tools/list response
	for _, r := range responses {
		if strings.Contains(r, "poisoned_add") {
			t.Error("poisoned_add should have been hidden from tools/list response")
		}
	}
	// But safe tools should remain
	foundWeather := false
	for _, r := range responses {
		if strings.Contains(r, "get_weather") {
			foundWeather = true
		}
	}
	if !foundWeather {
		t.Error("get_weather should be present in filtered tools/list")
	}

	// Audit should record the poisoning
	assertAuditDecision(t, audit, "poisoned_add", "BLOCK")
}

// mcp-rt-009: Resource read — block sensitive file URIs
func TestMCPRedTeam_ResourceRead_SSHKeyBlock(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		BlockedResources: []string{
			"file:///home/*/.ssh/**",
			"file:///root/.ssh/**",
		},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"file:///home/user/.ssh/id_rsa"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"file:///tmp/safe.txt"}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseAllowed(t, responses, 2)
	assertAuditDecision(t, audit, "resources/read", "BLOCK")
}

// mcp-rt-010: Resource read — block database connection URIs
func TestMCPRedTeam_ResourceRead_DatabaseURI(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-mysql",
				Match:    ResourceMatch{Scheme: "mysql"},
				Decision: policy.DecisionBlock,
				Reason:   "Direct database access blocked.",
			},
			{
				ID:       "block-redis",
				Match:    ResourceMatch{Scheme: "redis"},
				Decision: policy.DecisionBlock,
				Reason:   "Direct database access blocked.",
			},
		},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"mysql://prod-db:3306/users"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"resources/read","params":{"uri":"redis://cache-server:6379/0"}}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///tmp/safe.txt"}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertResponseBlocked(t, responses, 2)
	assertResponseAllowed(t, responses, 3)

	blocked := 0
	for _, e := range audit {
		if e.Decision == "BLOCK" {
			blocked++
		}
	}
	if blocked != 2 {
		t.Errorf("expected 2 blocked resource reads, got %d", blocked)
	}
}

// mcp-rt-011: Allowed calls pass through cleanly
func TestMCPRedTeam_AllowedCallPassthrough(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"San Francisco"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/readme.txt"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseAllowed(t, responses, 1)
	assertResponseAllowed(t, responses, 2)

	// Both should be AUDIT (default)
	for _, e := range audit {
		if e.Decision != "AUDIT" {
			t.Errorf("expected AUDIT for %s, got %s", e.ToolName, e.Decision)
		}
	}

	// Verify echo server actually responded with tool content
	for _, r := range responses {
		if strings.Contains(r, "get_weather") && strings.Contains(r, "Echo:") {
			return
		}
	}
	t.Error("expected echo server response for get_weather")
}

// mcp-rt-012: Initialize handshake passes through
func TestMCPRedTeam_InitializePassthrough(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)

	// initialize should pass through with no audit (not a tools/call)
	if len(audit) != 0 {
		t.Errorf("expected 0 audit entries for initialize, got %d", len(audit))
	}

	// Should get a valid response with server info
	if len(responses) == 0 {
		t.Fatal("expected response from initialize")
	}
	if !strings.Contains(responses[0], "agentshield-test-server") {
		t.Error("expected server info in initialize response")
	}
}

// mcp-rt-013: Combined attack — multiple blocked + allowed in one session
func TestMCPRedTeam_CombinedSession(t *testing.T) {
	maxAmount := 50.0
	pol := &MCPPolicy{
		Defaults:     MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools: []string{"execute_command"},
		Rules: []MCPRule{
			{
				ID: "block-etc",
				Match: MCPMatch{
					ToolName:         "write_file",
					ArgumentPatterns: map[string]string{"path": "/etc/**"},
				},
				Decision: policy.DecisionBlock,
				Reason:   "Write to /etc/ blocked.",
			},
		},
		ValueLimits: []ValueLimitRule{
			{
				ID:            "limit-transfer",
				ToolNameRegex: "send_.*",
				Argument:      "amount",
				Max:           &maxAmount,
				Decision:      policy.DecisionBlock,
				Reason:        "Transfer exceeds limit.",
			},
		},
	}

	msgs := []string{
		// 1. tools/list — passes through, poisoned tool hidden
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`,
		// 2. Safe weather call — AUDIT
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"NYC"}}}`,
		// 3. Blocked tool — execute_command
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"execute_command","arguments":{"command":"whoami"}}}`,
		// 4. Blocked by rule — write to /etc
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/etc/shadow","content":"evil"}}}`,
		// 5. Blocked by value limit — big transfer
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"attacker","amount":999999}}}`,
		// 6. Blocked by config guard — write .npmrc
		`{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.npmrc","content":"//registry:_authToken=evil"}}}`,
		// 7. Blocked by content scan — secret in args
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/log","content":"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}}}`,
		// 8. Safe read — AUDIT
		`{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/safe.txt"}}}`,
		// 9. Small transfer — allowed
		`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"friend","amount":5}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)

	// Should have 9 responses (1 tools/list + 8 tool calls)
	if len(responses) < 9 {
		t.Errorf("expected at least 9 responses, got %d", len(responses))
		for i, r := range responses {
			t.Logf("  response %d: %s", i, truncate(r, 100))
		}
	}

	// Verify blocked responses
	assertResponseBlocked(t, responses, 3) // execute_command
	assertResponseBlocked(t, responses, 4) // /etc write
	assertResponseBlocked(t, responses, 5) // value limit
	assertResponseBlocked(t, responses, 6) // config guard
	assertResponseBlocked(t, responses, 7) // content scan

	// Verify allowed responses
	assertResponseAllowed(t, responses, 2) // get_weather
	assertResponseAllowed(t, responses, 8) // safe read
	assertResponseAllowed(t, responses, 9) // small transfer

	// Poisoned tool hidden
	for _, r := range responses {
		if strings.Contains(r, "poisoned_add") {
			t.Error("poisoned_add should be hidden")
		}
	}

	// Count audit decisions
	blocked := 0
	audited := 0
	for _, e := range audit {
		switch e.Decision {
		case "BLOCK":
			blocked++
		case "AUDIT":
			audited++
		}
	}
	t.Logf("Audit summary: %d blocked, %d audited, %d total", blocked, audited, len(audit))

	// 5 blocked tool calls + 1 poisoned description = 6 BLOCK entries
	if blocked != 6 {
		t.Errorf("expected 6 BLOCK entries, got %d", blocked)
		for _, e := range audit {
			t.Logf("  %s: %s (rules: %v)", e.ToolName, e.Decision, e.TriggeredRules)
		}
	}
	// 3 audited tool calls (get_weather, read_file, send_tokens small)
	if audited != 3 {
		t.Errorf("expected 3 AUDIT entries, got %d", audited)
	}
}

// mcp-rt-014: Content scanning — large base64 blob exfiltration attempt
func TestMCPRedTeam_Base64Exfiltration(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	// Create a large base64-looking blob (512+ chars of base64)
	blob := strings.Repeat("SGVsbG8gV29ybGQh", 40) // repeated "Hello World!" in base64

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/data","content":"` + blob + `"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertAuditDecision(t, audit, "write_file", "BLOCK")
}

// mcp-rt-015: Value limits — boundary test (exactly at max is OK)
func TestMCPRedTeam_ValueLimit_BoundaryAtMax(t *testing.T) {
	maxAmount := 100.0
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		ValueLimits: []ValueLimitRule{
			{
				ID:            "cap-transfer",
				ToolNameRegex: "send_.*",
				Argument:      "amount",
				Max:           &maxAmount,
				Decision:      policy.DecisionBlock,
				Reason:        "Too much.",
			},
		},
	}

	msgs := []string{
		// Exactly at max — should be allowed
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"friend","amount":100}}}`,
		// One over max — should be blocked
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"send_tokens","arguments":{"to":"friend","amount":100.01}}}`,
	}

	responses, _ := runProxyScenario(t, pol, msgs)
	assertResponseAllowed(t, responses, 1)
	assertResponseBlocked(t, responses, 2)
}

// mcp-rt-016: Config guard — block write to AgentShield's own policy
func TestMCPRedTeam_ConfigGuard_SelfProtection(t *testing.T) {
	pol := &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
	}

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"~/.agentshield/mcp-policy.yaml","content":"defaults:\\n  decision: ALLOW"}}}`,
	}

	responses, audit := runProxyScenario(t, pol, msgs)
	assertResponseBlocked(t, responses, 1)
	assertAuditDecision(t, audit, "write_file", "BLOCK")
}
