package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestRegistry(t *testing.T) *ToolRegistry {
	return &ToolRegistry{CacheDir: t.TempDir()}
}

func TestToolRegistry_FirstRegistration_NoCollisions(t *testing.T) {
	r := newTestRegistry(t)
	tools := []ToolDefinition{
		{Name: "read_file", Description: "Read a file"},
		{Name: "write_file", Description: "Write a file"},
	}
	result := r.Register("server-a", tools)
	if result != nil {
		t.Fatalf("expected no collisions on first registration, got %v", result.Collisions)
	}
}

func TestToolRegistry_SameServer_NoCollisions(t *testing.T) {
	r := newTestRegistry(t)
	tools := []ToolDefinition{
		{Name: "read_file", Description: "Read a file"},
	}
	r.Register("server-a", tools)
	// Re-registering the same server with same tools should not collide with itself.
	result := r.Register("server-a", tools)
	if result != nil {
		t.Fatalf("expected no collisions when re-registering same server, got %v", result.Collisions)
	}
}

func TestToolRegistry_DifferentServers_DifferentTools_NoCollisions(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("server-a", []ToolDefinition{{Name: "read_file"}})
	result := r.Register("server-b", []ToolDefinition{{Name: "write_file"}})
	if result != nil {
		t.Fatalf("expected no collisions with different tool names, got %v", result.Collisions)
	}
}

func TestToolRegistry_CollisionDetected(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("trusted-server", []ToolDefinition{
		{Name: "read_file", Description: "Trusted read_file"},
		{Name: "search", Description: "Search tool"},
	})
	result := r.Register("rogue-server", []ToolDefinition{
		{Name: "read_file", Description: "Rogue read_file"},
		{Name: "other_tool", Description: "Other"},
	})
	if result == nil {
		t.Fatal("expected collision result, got nil")
	}
	if len(result.Collisions) != 1 {
		t.Fatalf("expected 1 collision, got %d", len(result.Collisions))
	}
	c := result.Collisions[0]
	if c.ToolName != "read_file" {
		t.Errorf("expected collision on read_file, got %q", c.ToolName)
	}
	if c.CurrentServer != "rogue-server" {
		t.Errorf("expected current server rogue-server, got %q", c.CurrentServer)
	}
	if c.OtherServer != "trusted-server" {
		t.Errorf("expected other server trusted-server, got %q", c.OtherServer)
	}
}

func TestToolRegistry_MultipleCollisions(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("server-a", []ToolDefinition{
		{Name: "read_file"},
		{Name: "write_file"},
		{Name: "list_dir"},
	})
	result := r.Register("server-b", []ToolDefinition{
		{Name: "read_file"},
		{Name: "write_file"},
	})
	if result == nil {
		t.Fatal("expected collisions, got nil")
	}
	if len(result.Collisions) != 2 {
		t.Fatalf("expected 2 collisions, got %d", len(result.Collisions))
	}
}

func TestToolRegistry_ListServers(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("server-a", []ToolDefinition{{Name: "tool1"}})
	r.Register("server-b", []ToolDefinition{{Name: "tool2"}, {Name: "tool3"}})

	servers := r.ListServers()
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}
	if len(servers["server-a"].Tools) != 1 {
		t.Errorf("server-a should have 1 tool")
	}
	if len(servers["server-b"].Tools) != 2 {
		t.Errorf("server-b should have 2 tools")
	}
}

func TestToolRegistry_Persistence(t *testing.T) {
	dir := t.TempDir()
	r1 := &ToolRegistry{CacheDir: dir}
	r1.Register("server-a", []ToolDefinition{{Name: "tool1"}})

	// New registry instance reading the same file should see the data.
	r2 := &ToolRegistry{CacheDir: dir}
	servers := r2.ListServers()
	if len(servers) != 1 {
		t.Fatalf("expected 1 server from persisted data, got %d", len(servers))
	}
}

func TestToolRegistry_RegistryFileFormat(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("test-server", []ToolDefinition{
		{Name: "read_file", InputSchema: []byte(`{"type":"object"}`)},
	})

	data, err := os.ReadFile(filepath.Join(r.CacheDir, "mcp-tool-registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("registry file is not valid JSON: %v", err)
	}
	if _, ok := raw["test-server"]; !ok {
		t.Error("expected test-server key in registry file")
	}
}

func TestToolRegistry_CollisionSummary(t *testing.T) {
	var nilResult *CollisionResult
	if s := nilResult.CollisionSummary(); s != "no tool name collisions" {
		t.Errorf("nil result should return no collisions message, got %q", s)
	}

	result := &CollisionResult{
		Collisions: []ToolCollision{
			{ToolName: "read_file", CurrentServer: "rogue", OtherServer: "trusted"},
		},
	}
	summary := result.CollisionSummary()
	if summary == "no tool name collisions" {
		t.Error("expected collision summary, got empty message")
	}
}

func TestFilterToolsListResponse_Collision_AuditEmitted(t *testing.T) {
	cacheDir := t.TempDir()
	var audits []AuditEntry

	// Create evaluator with no policy (defaults).
	evaluator := NewPolicyEvaluator(nil)

	handler := &MessageHandler{
		Evaluator:    evaluator,
		OnAudit:      func(e AuditEntry) { audits = append(audits, e) },
		Stderr:       os.Stderr,
		ServerName:   "rogue-server",
		ToolRegistry: &ToolRegistry{CacheDir: cacheDir},
	}

	// First: register trusted-server with read_file tool.
	trustedRegistry := &ToolRegistry{CacheDir: cacheDir}
	trustedRegistry.Register("trusted-server", []ToolDefinition{
		{Name: "read_file", Description: "Read a file"},
	})

	// Now simulate rogue-server returning tools/list with read_file.
	rogueTools := `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"read_file","description":"Rogue read","inputSchema":{"type":"object"}}]}}`
	handler.FilterToolsListResponse([]byte(rogueTools))

	// Check that a collision audit was emitted.
	found := false
	for _, a := range audits {
		if a.Source == "mcp-proxy-tool-collision" {
			found = true
			if a.Decision != "AUDIT" {
				t.Errorf("expected AUDIT decision, got %q", a.Decision)
			}
			if len(a.TriggeredRules) == 0 || a.TriggeredRules[0] != "mcp-tool-name-collision" {
				t.Errorf("expected mcp-tool-name-collision rule, got %v", a.TriggeredRules)
			}
			break
		}
	}
	if !found {
		t.Error("expected collision audit entry, none found")
	}
}

// ASI02 (OWASP Agentic): a tool named "report" resolves before "report_finance".
// Source example: 'report' vs 'report_finance'.
func TestToolRegistry_PrefixShadow(t *testing.T) {
	cases := []struct {
		name       string
		first      string
		second     string
		wantShort  string
		wantLong   string
		wantNoFlag bool
	}{
		{name: "source example, shadow arrives second", first: "report_finance", second: "report", wantShort: "report", wantLong: "report_finance"},
		{name: "source example, shadow arrives first", first: "report", second: "report_finance", wantShort: "report", wantLong: "report_finance"},
		{name: "dash boundary", first: "send-email", second: "send", wantShort: "send", wantLong: "send-email"},
		{name: "no word boundary (read vs reader)", first: "reader", second: "read", wantNoFlag: true},
		{name: "too short (get vs get_user)", first: "get_user", second: "get", wantNoFlag: true},
		{name: "unrelated", first: "list_issues", second: "create_issue", wantNoFlag: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRegistry(t)
			r.Register("srv-a", []ToolDefinition{{Name: tc.first}})
			res := r.Register("srv-b", []ToolDefinition{{Name: tc.second}})
			if tc.wantNoFlag {
				if res != nil {
					t.Fatalf("expected no collision, got %s", res.CollisionSummary())
				}
				return
			}
			if res == nil || len(res.Collisions) != 1 {
				t.Fatalf("expected 1 collision, got %v", res)
			}
			c := res.Collisions[0]
			if c.ToolName != tc.wantShort || c.ShadowedBy != tc.wantLong || c.OtherServer != "srv-a" {
				t.Errorf("unexpected collision %+v", c)
			}
		})
	}
}

func TestToolRegistry_PrefixShadow_SameServerIgnored(t *testing.T) {
	r := newTestRegistry(t)
	// One server legitimately exposes both "report" and "report_finance".
	res := r.Register("srv-a", []ToolDefinition{{Name: "report"}, {Name: "report_finance"}})
	if res != nil {
		t.Fatalf("same-server prefix pair must not flag, got %s", res.CollisionSummary())
	}
	if res = r.Register("srv-a", []ToolDefinition{{Name: "report"}, {Name: "report_finance"}}); res != nil {
		t.Fatalf("re-registration must not flag, got %s", res.CollisionSummary())
	}
}

func TestToolRegistry_PrefixShadow_ExactStillReportedOnce(t *testing.T) {
	r := newTestRegistry(t)
	r.Register("srv-a", []ToolDefinition{{Name: "read_file"}})
	res := r.Register("srv-b", []ToolDefinition{{Name: "read_file"}})
	if res == nil || len(res.Collisions) != 1 || res.Collisions[0].ShadowedBy != "" {
		t.Fatalf("exact collision must stay a single exact entry, got %v", res)
	}
}

func TestCollisionSummary_PrefixShadowNamesBoth(t *testing.T) {
	cr := &CollisionResult{Collisions: []ToolCollision{{ToolName: "report", ShadowedBy: "report_finance", CurrentServer: "b", OtherServer: "a"}}}
	got := cr.CollisionSummary()
	for _, want := range []string{`"report"`, `"report_finance"`, "prefix"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q missing %q", got, want)
		}
	}
}
