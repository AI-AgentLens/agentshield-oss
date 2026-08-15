package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/logger"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Issue #3111 — these tests sit one layer BELOW the wire-format tests in
// remote_audit_test.go. buildAuditPayload can be perfectly correct while the
// AuditEvent handed to it is empty, and that failure mode is invisible to a
// test that constructs the event by hand. Both audit paths are covered here
// because the MCP path is the one most likely to be missed: it builds its
// AuditEvent in a completely separate function from the shell path.

const testTaxonomyRef = "unauthorized-execution/agentic-attacks/test-only-node"

// writeTestPolicy lays down a minimal ~/.agentshield/policy.yaml with one
// taxonomy-tagged BLOCK rule on a made-up executable, so no shipped community
// pack rule can outrank it and steal the decision.
func writeTestPolicy(t *testing.T) string {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	configDir := filepath.Join(tmpHome, ".agentshield")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	policyYAML := `version: "0.1"

defaults:
  decision: "ALLOW"

rules:
  - id: e2e-block-frobnicate
    taxonomy: "` + testTaxonomyRef + `"
    match:
      command_prefix:
        - "frobnicate "
    decision: "BLOCK"
    reason: "Test-only rule for the audit taxonomy contract."
`
	if err := os.WriteFile(filepath.Join(configDir, "policy.yaml"), []byte(policyYAML), 0o600); err != nil {
		t.Fatalf("WriteFile policy.yaml: %v", err)
	}
	return tmpHome
}

// readAuditEventsForTest returns the events AgentShield wrote to the local audit log.
func readAuditEventsForTest(t *testing.T, home string) []logger.AuditEvent {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(home, ".agentshield", "audit.jsonl"))
	if err != nil {
		t.Fatalf("read audit.jsonl: %v", err)
	}
	var events []logger.AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e logger.AuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("decode audit line %q: %v", line, err)
		}
		events = append(events, e)
	}
	return events
}

// TestEvaluateCommand_AuditEventCarriesTaxonomyAndIdentity walks the shell hook
// path: policy -> engine -> EvalResult -> AuditEvent. If the AuditEvent loses
// the taxonomy here, every downstream wire test still passes and the SaaS still
// gets nothing.
func TestEvaluateCommand_AuditEventCarriesTaxonomyAndIdentity(t *testing.T) {
	home := writeTestPolicy(t)

	const sessionID = "sess-3111-shell"
	evalResult, event, err := evaluateCommand(
		"frobnicate --launch-sequence", "/workspace/acme-api", "claude-code-hook", sessionID)
	if err != nil {
		t.Fatalf("evaluateCommand: %v", err)
	}
	if evalResult.Decision != policy.DecisionBlock {
		t.Fatalf("Decision = %v; want BLOCK", evalResult.Decision)
	}
	if event == nil {
		t.Fatal("evaluateCommand returned a nil AuditEvent")
	}

	if !containsStr(event.TaxonomyRefs, testTaxonomyRef) {
		t.Errorf("AuditEvent.TaxonomyRefs = %v; want it to include %q — the "+
			"EvalResult knew the taxonomy node and the audit event dropped it",
			event.TaxonomyRefs, testTaxonomyRef)
	}
	if event.SessionID != sessionID {
		t.Errorf("AuditEvent.SessionID = %q; want %q", event.SessionID, sessionID)
	}
	if event.Cwd != "/workspace/acme-api" {
		t.Errorf("AuditEvent.Cwd = %q; want /workspace/acme-api", event.Cwd)
	}
	if event.Principal == "" {
		t.Error("AuditEvent.Principal is empty; the OS user is knowable at hook time")
	}

	// The same fields must survive the local audit log, which is the evidence
	// record when the agent is offline.
	logged := readAuditEventsForTest(t, home)
	if len(logged) != 1 {
		t.Fatalf("expected 1 logged event, got %d", len(logged))
	}
	if !containsStr(logged[0].TaxonomyRefs, testTaxonomyRef) {
		t.Errorf("logged event taxonomy = %v; want %q", logged[0].TaxonomyRefs, testTaxonomyRef)
	}
	if logged[0].SessionID != sessionID || logged[0].Principal == "" {
		t.Errorf("logged event identity = {session_id:%q principal:%q}; want both populated",
			logged[0].SessionID, logged[0].Principal)
	}

	// And through the wire builder, end to end.
	payload, err := buildAuditPayload(event)
	if err != nil {
		t.Fatalf("buildAuditPayload: %v", err)
	}
	if !strings.Contains(string(payload), testTaxonomyRef) {
		t.Errorf("wire payload does not carry the taxonomy ref: %s", string(payload))
	}
}

// TestAuditMCPCall_EventCarriesTaxonomyAndIdentity walks the MCP hook path,
// which builds its AuditEvent in auditMCPCall — a completely separate call
// site from the shell path, and the one an incomplete fix would miss.
func TestAuditMCPCall_EventCarriesTaxonomyAndIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".agentshield"), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	const sessionID = "sess-3111-mcp"
	result := mcp.MCPEvalResult{
		Decision:       policy.DecisionBlock,
		TriggeredRules: []string{"mcp-block-ssh-key-read", "content:ssh_private_key"},
		Reasons:        []string{"SSH private key read via MCP filesystem tool"},
		// A composite MCP decision can populate either field; both must reach
		// the audit event via AllTaxonomyRefs.
		TaxonomyRef:  "credential-exposure/secret-material/ssh-private-key-read",
		TaxonomyRefs: []string{testTaxonomyRef},
	}

	auditMCPCall("read_file", map[string]interface{}{"path": "/home/dev/.ssh/id_rsa"},
		result, "claude-code-hook", "enforce", sessionID)

	logged := readAuditEventsForTest(t, home)
	if len(logged) != 1 {
		t.Fatalf("expected 1 logged MCP event, got %d", len(logged))
	}
	e := logged[0]

	for _, want := range []string{
		"credential-exposure/secret-material/ssh-private-key-read",
		testTaxonomyRef,
	} {
		if !containsStr(e.TaxonomyRefs, want) {
			t.Errorf("MCP audit event taxonomy = %v; want it to include %q. "+
				"Reading only one of MCPEvalResult's two taxonomy fields drops "+
				"half the MCP decisions from the fusion chain.", e.TaxonomyRefs, want)
		}
	}
	if e.SessionID != sessionID {
		t.Errorf("MCP audit event SessionID = %q; want %q", e.SessionID, sessionID)
	}
	if e.Principal == "" {
		t.Error("MCP audit event Principal is empty; the OS user is knowable at hook time")
	}
	if e.Cwd == "" {
		t.Error("MCP audit event Cwd is empty; the MCP path must record it like the shell path")
	}

	// The MCP wire payload must split the synthetic label out of rule_ids.
	payload, err := buildAuditPayload(&e)
	if err != nil {
		t.Fatalf("buildAuditPayload: %v", err)
	}
	entry := decodeEntry(t, payload)
	if ids := stringSlice(t, entry, "rule_ids"); len(ids) != 1 || ids[0] != "mcp-block-ssh-key-read" {
		t.Errorf("rule_ids = %v; want only the real rule id", ids)
	}
	if sigs := stringSlice(t, entry, "signals"); len(sigs) != 1 || sigs[0] != "content:ssh_private_key" {
		t.Errorf("signals = %v; want the namespaced detector label", sigs)
	}
}

// TestSessionIDFor_UsesHarnessProvidedIDOnly pins the session_id decision:
// AgentShield reports what the harness sent and nothing else. Minting an id
// would correlate events the harness itself considers unrelated.
func TestSessionIDFor_UsesHarnessProvidedIDOnly(t *testing.T) {
	cases := []struct {
		name  string
		input hookInput
		want  string
	}{
		{
			name:  "claude code / codex session_id",
			input: hookInput{SessionID: "0c9b1f2e-claude"},
			want:  "0c9b1f2e-claude",
		},
		{
			name:  "windsurf trajectory_id",
			input: hookInput{TrajectoryID: "traj-77"},
			want:  "traj-77",
		},
		{
			name:  "session_id wins when both present",
			input: hookInput{SessionID: "sess-1", TrajectoryID: "traj-2"},
			want:  "sess-1",
		},
		{
			name:  "cursor sends neither — stays empty, never synthesized",
			input: hookInput{Command: "ls"},
			want:  "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sessionIDFor(tc.input); got != tc.want {
				t.Errorf("sessionIDFor() = %q; want %q", got, tc.want)
			}
		})
	}
}

// TestHookInput_ParsesClaudeCodeSessionID pins the wire field name on the
// inbound side — Claude Code sends session_id on every hook payload.
func TestHookInput_ParsesClaudeCodeSessionID(t *testing.T) {
	raw := `{"session_id":"abc-123","transcript_path":"/tmp/t.jsonl",` +
		`"cwd":"/workspace","hook_event_name":"PreToolUse","tool_name":"Bash",` +
		`"tool_input":{"command":"ls -la"}}`

	var input hookInput
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		t.Fatalf("Unmarshal hook payload: %v", err)
	}
	if input.SessionID != "abc-123" {
		t.Errorf("hookInput.SessionID = %q; want abc-123 (the JSON tag must stay "+
			"`session_id` — renaming it silently empties the identity plane)",
			input.SessionID)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
