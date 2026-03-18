package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// newTestScanner creates a SchemaDriftScanner that writes its cache to a temp directory.
func newTestScanner(t *testing.T) *SchemaDriftScanner {
	t.Helper()
	return &SchemaDriftScanner{CacheDir: t.TempDir()}
}

func rawSchema(t *testing.T, v interface{}) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("rawSchema: %v", err)
	}
	return b
}

// ── CheckDrift: first-time connection ──────────────────────────────────────────

func TestSchemaDrift_FirstConnection_NotDrift(t *testing.T) {
	s := newTestScanner(t)
	tools := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]string{"type": "object"})},
	}
	result := s.CheckDrift("my-server", tools)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Drifted {
		t.Error("first-time connection should not be flagged as drift")
	}
	if !result.FirstSeen {
		t.Error("expected FirstSeen=true on first connection")
	}
}

// ── CheckDrift: same schemas → no drift ───────────────────────────────────────

func TestSchemaDrift_NoChange_NoDrift(t *testing.T) {
	s := newTestScanner(t)
	tools := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]string{"type": "string"},
			},
		})},
		{Name: "write_file", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":    map[string]string{"type": "string"},
				"content": map[string]string{"type": "string"},
			},
		})},
	}
	// Seed the cache.
	_ = s.CheckDrift("server", tools)

	// Second call with identical tools — must not be drift.
	result := s.CheckDrift("server", tools)
	if result.Drifted {
		t.Errorf("same schema should not drift; got: %s", result.DriftSummary())
	}
}

// ── TP-1: New malicious parameter added to existing tool ─────────────────────
//
// A compromised MCP server adds an exec_command parameter to read_file between
// sessions — classic supply-chain schema injection.

func TestSchemaDrift_NewMaliciousParam_Detected(t *testing.T) {
	s := newTestScanner(t)
	const server = "malicious-server"

	original := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path": map[string]string{"type": "string"},
			},
		})},
	}
	// Seed baseline.
	_ = s.CheckDrift(server, original)

	// Server now returns read_file with a new exec_command parameter.
	mutated := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":         map[string]string{"type": "string"},
				"exec_command": map[string]string{"type": "string"}, // injected
			},
		})},
	}
	result := s.CheckDrift(server, mutated)
	if !result.Drifted {
		t.Fatal("expected drift when exec_command param is injected")
	}
	if len(result.ChangedTools) == 0 || result.ChangedTools[0] != "read_file" {
		t.Errorf("expected read_file in ChangedTools; got %v", result.ChangedTools)
	}
}

// ── TP-2: Input type mutation (string → object with system_cmd sub-field) ────
//
// A parameter's type is changed from string to object and gains a system_cmd
// sub-field — expanding the attack surface without changing the tool's name.

func TestSchemaDrift_TypeMutation_Detected(t *testing.T) {
	s := newTestScanner(t)
	const server = "type-mutant-server"

	original := []ToolDefinition{
		{Name: "send_message", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"body": map[string]string{"type": "string"},
			},
		})},
	}
	_ = s.CheckDrift(server, original)

	mutated := []ToolDefinition{
		{Name: "send_message", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"body": map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"text":       map[string]string{"type": "string"},
						"system_cmd": map[string]string{"type": "string"}, // expanded
					},
				},
			},
		})},
	}
	result := s.CheckDrift(server, mutated)
	if !result.Drifted {
		t.Fatal("expected drift when parameter type is mutated")
	}
	if len(result.ChangedTools) == 0 || result.ChangedTools[0] != "send_message" {
		t.Errorf("expected send_message in ChangedTools; got %v", result.ChangedTools)
	}
}

// ── TP-3: New tool added between sessions ────────────────────────────────────
//
// A second session exposes a shadow_exec tool not present in the baseline.

func TestSchemaDrift_NewToolAdded_Detected(t *testing.T) {
	s := newTestScanner(t)
	const server = "expanding-server"

	baseline := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
	}
	_ = s.CheckDrift(server, baseline)

	withNewTool := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
		{Name: "shadow_exec", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
	}
	result := s.CheckDrift(server, withNewTool)
	if !result.Drifted {
		t.Fatal("expected drift when a new tool appears")
	}
	if len(result.AddedTools) == 0 || result.AddedTools[0] != "shadow_exec" {
		t.Errorf("expected shadow_exec in AddedTools; got %v", result.AddedTools)
	}
}

// ── TN-1: Same schemas, different JSON key ordering ──────────────────────────
//
// JSON property ordering is implementation-defined; hashing must be canonical.

func TestSchemaDrift_KeyOrderIndependent_NoDrift(t *testing.T) {
	s := newTestScanner(t)
	const server = "reorder-server"

	// Seed with alpha-ordered properties.
	baseline := []ToolDefinition{
		{Name: "query", InputSchema: []byte(`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"integer"}}}`)},
	}
	_ = s.CheckDrift(server, baseline)

	// Same schema with b before a.
	reordered := []ToolDefinition{
		{Name: "query", InputSchema: []byte(`{"type":"object","properties":{"b":{"type":"integer"},"a":{"type":"string"}}}`)},
	}
	result := s.CheckDrift(server, reordered)
	if result.Drifted {
		t.Error("JSON key reordering must not trigger drift")
	}
}

// ── TN-2: Multiple independent servers, no cross-contamination ───────────────

func TestSchemaDrift_MultipleServers_Isolated(t *testing.T) {
	s := newTestScanner(t)
	tools := []ToolDefinition{
		{Name: "list_files", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
	}

	// Seed two separate servers.
	_ = s.CheckDrift("server-a", tools)
	_ = s.CheckDrift("server-b", tools)

	// Mutate server-a's tool list.
	mutated := []ToolDefinition{
		{Name: "list_files", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"injected": map[string]string{"type": "string"},
			},
		})},
	}
	driftA := s.CheckDrift("server-a", mutated)
	driftB := s.CheckDrift("server-b", tools) // server-b is unchanged

	if !driftA.Drifted {
		t.Error("server-a should detect drift")
	}
	if driftB.Drifted {
		t.Error("server-b must not be affected by server-a drift")
	}
}

// ── Handler integration: drift triggers AUDIT event ──────────────────────────

func TestFilterToolsListResponse_SchemaDrift_AuditEmitted(t *testing.T) {
	cacheDir := t.TempDir()
	const server = "test-mcp-server"

	// Build a handler with schema drift enabled.
	var auditEntries []AuditEntry
	h := &MessageHandler{
		Stderr:     os.Stderr,
		ServerName: server,
		SchemaDrift: &SchemaDriftScanner{CacheDir: cacheDir},
		OnAudit: func(e AuditEntry) {
			auditEntries = append(auditEntries, e)
		},
	}

	// Session 1: seed baseline.
	toolsListMsg := func(tools []ToolDefinition) []byte {
		result, _ := json.Marshal(ListToolsResult{Tools: tools})
		msg, _ := json.Marshal(Message{Result: result})
		return msg
	}

	baseline := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{"type": "object", "properties": map[string]interface{}{"path": map[string]string{"type": "string"}}})},
	}
	h.FilterToolsListResponse(toolsListMsg(baseline))

	// Session 2: malicious new parameter added.
	mutated := []ToolDefinition{
		{Name: "read_file", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"path":         map[string]string{"type": "string"},
				"exec_command": map[string]string{"type": "string"},
			},
		})},
	}
	h.FilterToolsListResponse(toolsListMsg(mutated))

	// Expect at least one AUDIT event with the schema-drift rule.
	found := false
	for _, e := range auditEntries {
		for _, r := range e.TriggeredRules {
			if r == "mcp-supply-chain-schema-drift" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected an AUDIT event for mcp-supply-chain-schema-drift; got %d entries: %+v", len(auditEntries), auditEntries)
	}
}

// ── Handler integration: no drift → no AUDIT event ───────────────────────────

func TestFilterToolsListResponse_NoSchemaDrift_NoAudit(t *testing.T) {
	cacheDir := t.TempDir()
	const server = "stable-server"

	var auditEntries []AuditEntry
	h := &MessageHandler{
		Stderr:     os.Stderr,
		ServerName: server,
		SchemaDrift: &SchemaDriftScanner{CacheDir: cacheDir},
		OnAudit: func(e AuditEntry) {
			auditEntries = append(auditEntries, e)
		},
	}

	toolsListMsg := func(tools []ToolDefinition) []byte {
		result, _ := json.Marshal(ListToolsResult{Tools: tools})
		msg, _ := json.Marshal(Message{Result: result})
		return msg
	}

	tools := []ToolDefinition{
		{Name: "query", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
	}
	// Session 1 (seed) then Session 2 (same).
	h.FilterToolsListResponse(toolsListMsg(tools))
	h.FilterToolsListResponse(toolsListMsg(tools))

	for _, e := range auditEntries {
		for _, r := range e.TriggeredRules {
			if r == "mcp-supply-chain-schema-drift" {
				t.Errorf("unexpected schema-drift AUDIT event for stable schema: %+v", e)
			}
		}
	}
}

// ── Cache persistence: survives process restart ───────────────────────────────

func TestSchemaDrift_CachePersistence(t *testing.T) {
	cacheDir := t.TempDir()
	tools := []ToolDefinition{
		{Name: "run_query", InputSchema: rawSchema(t, map[string]interface{}{"type": "object"})},
	}

	// Scanner 1 seeds the cache.
	s1 := &SchemaDriftScanner{CacheDir: cacheDir}
	_ = s1.CheckDrift("db-server", tools)

	// Verify the cache file was written.
	if _, err := os.Stat(filepath.Join(cacheDir, "mcp-schema-cache.json")); err != nil {
		t.Fatalf("cache file not written: %v", err)
	}

	// Scanner 2 (simulates restart) loads the cache and detects drift.
	s2 := &SchemaDriftScanner{CacheDir: cacheDir}
	mutated := []ToolDefinition{
		{Name: "run_query", InputSchema: rawSchema(t, map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"injected": map[string]string{"type": "string"},
			},
		})},
	}
	result := s2.CheckDrift("db-server", mutated)
	if !result.Drifted {
		t.Error("drift should be detected across process boundaries (persistent cache)")
	}
}
