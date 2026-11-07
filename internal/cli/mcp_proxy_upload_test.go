package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/datalabel"
	"github.com/AI-AgentLens/agentshield/internal/mcp"
)

// The MCP proxies' audit sink logs each decision locally and queues it for AI
// Agent Lens (#4734). Before, the proxies wrote only the local line, so no
// decision about a Claude Desktop or Cursor MCP server reached the SaaS.

const (
	proxyTamperNode = "persistence-evasion/defense-evasion/security-tool-tampering"
	proxyDescNode   = "unauthorized-execution/agentic-attacks/tool-description-poisoning"
	proxyDescRule   = "mcp-desc-hidden-instructions-sentinel"
)

func proxyRuleTaxonomy(ids []string) []string {
	for _, id := range ids {
		if id == proxyDescRule {
			return []string{proxyDescNode}
		}
	}
	return nil
}

// proxyWriteEntry is the record the stdio proxy makes when audit-only mode
// forwards a write to AgentShield's own policy file, with a token in it.
func proxyWriteEntry(secret string) mcp.AuditEntry {
	return mcp.AuditEntry{
		Timestamp:        "2026-11-01T13:03:48Z",
		ToolName:         "write_file",
		Arguments:        map[string]interface{}{"path": `C:\Users\u\.agentshield\policy.yaml`, "content": "token " + secret},
		Decision:         "AUDIT",
		OriginalDecision: "BLOCK",
		Mode:             "audit-only",
		Flagged:          true,
		TriggeredRules:   []string{"mcp-persist-block-agentshield-config-write"},
		TaxonomyRefs:     []string{proxyTamperNode},
		Source:           "mcp-proxy",
		ServerName:       "kai-echo",
	}
}

// proxyDescEntry is the description scan's record of a poisoned tool, which
// names a sentinel rule but carries no taxonomy of its own.
func proxyDescEntry() mcp.AuditEntry {
	return mcp.AuditEntry{
		Timestamp:      "2026-11-01T12:57:30Z",
		ToolName:       "poisoned_add",
		Decision:       "BLOCK",
		Flagged:        true,
		TriggeredRules: []string{"tool-description-poisoning", proxyDescRule},
		Source:         "mcp-proxy-description-scan",
		ServerName:     "kai-echo",
	}
}

func uploadedEvents(t *testing.T, saas *fakeSaaS) []map[string]any {
	t.Helper()
	saas.mu.Lock()
	bodies := append([]string(nil), saas.bodies...)
	saas.mu.Unlock()
	var out []map[string]any
	for _, b := range bodies {
		var wire struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.Unmarshal([]byte(b), &wire); err != nil {
			t.Fatalf("upload body: %v", err)
		}
		out = append(out, wire.Events...)
	}
	return out
}

func noEngine() *datalabel.Engine { return nil }

func TestMCPProxyAuditSink_UploadsDecisions_4734(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	t.Setenv(auditUploadEnv, "sync")

	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	secret := "ghp_" + strings.Repeat("A1b2", 9)
	sink := newMCPProxyAuditSink(f, noEngine, proxyRuleTaxonomy)
	sink(proxyWriteEntry(secret))
	sink(proxyDescEntry())

	events := uploadedEvents(t, saas)
	if len(events) != 2 {
		t.Fatalf("SaaS received %d events; want both proxy decisions", len(events))
	}
	w, d := events[0], events[1]
	for k, want := range map[string]any{
		"source": "mcp-proxy", "tool_name": "write_file", "server_name": "kai-echo",
		"decision": "AUDIT", "original_decision": "BLOCK", "mode": "audit-only",
		"rule_id": "mcp-persist-block-agentshield-config-write",
	} {
		if w[k] != want {
			t.Errorf("write event %s = %v; want %v", k, w[k], want)
		}
	}
	if tax, _ := w["taxonomy"].([]any); len(tax) != 1 || tax[0] != proxyTamperNode {
		t.Errorf("write event taxonomy = %v; want [%s]", w["taxonomy"], proxyTamperNode)
	}
	if _, ok := w["arguments"].(map[string]any); !ok {
		t.Errorf("write event has no arguments: %v", w)
	}
	if p, _ := w["principal"].(string); p == "" {
		t.Errorf("write event has no principal")
	}
	if _, ok := w["cwd"]; ok {
		t.Errorf("write event carries the proxy's cwd %v; the proxy cannot observe the agent's", w["cwd"])
	}
	if d["source"] != "mcp-proxy-description-scan" {
		t.Errorf("description event source = %v", d["source"])
	}
	if tax, _ := d["taxonomy"].([]any); len(tax) != 1 || tax[0] != proxyDescNode {
		t.Errorf("description event taxonomy = %v; want the sentinel rule's [%s]", d["taxonomy"], proxyDescNode)
	}

	saas.mu.Lock()
	body := strings.Join(saas.bodies, "\n")
	saas.mu.Unlock()
	if strings.Contains(body, secret) {
		t.Errorf("the upload carries the unredacted token")
	}

	local, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(local)), "\n")
	if len(lines) != 2 {
		t.Fatalf("local log holds %d lines; want 2", len(lines))
	}
	if strings.Contains(string(local), secret) {
		t.Errorf("the local log carries the unredacted token")
	}
	if !strings.Contains(lines[1], proxyDescNode) {
		t.Errorf("local description line has no taxonomy: %s", lines[1])
	}
}

// A proxy whose local log could not be opened still reports to AI Agent Lens,
// as the hook does (#4470).
func TestMCPProxyAuditSink_UploadsWithoutLocalLog_4734(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	newQueueHome(t, saas.srv.URL)
	stubFlusher(t, nil)
	t.Setenv(auditUploadEnv, "sync")

	newMCPProxyAuditSink(nil, noEngine, nil)(proxyDescEntry())
	if got := uploadedEvents(t, saas); len(got) != 1 {
		t.Fatalf("SaaS received %d events; want 1", len(got))
	}
}

// Through the queue, the default: the proxy enqueues and starts an uploader.
func TestMCPProxyAuditSink_QueuesForUpload_4734(t *testing.T) {
	saas := newFakeSaaS(t, nil)
	dir := newQueueHome(t, saas.srv.URL)
	spawns := stubFlusher(t, nil)

	newMCPProxyAuditSink(nil, noEngine, nil)(proxyDescEntry())
	if n := len(queuedIDs(t, dir)); n != 1 {
		t.Fatalf("queue holds %d events; want the proxy decision", n)
	}
	if spawns() != 1 {
		t.Errorf("uploader starts = %d; want 1", spawns())
	}
}

// Not logged in: the local line is written and nothing is sent.
func TestMCPProxyAuditSink_NotLoggedIn_4734(t *testing.T) {
	newFailSafeHome(t, false, failSafePolicyGood)
	spawns := stubFlusher(t, nil)
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	newMCPProxyAuditSink(f, noEngine, nil)(proxyDescEntry())
	if spawns() != 0 {
		t.Errorf("an install that is not logged in started %d uploaders", spawns())
	}
	if b, _ := os.ReadFile(logPath); !strings.Contains(string(b), "poisoned_add") {
		t.Errorf("local line missing: %q", b)
	}
}

// server_name goes on the wire only when set, so a hook event's wire entry is
// unchanged (#4734).
func TestAuditWireEntry_ServerNameOnlyWhenSet_4734(t *testing.T) {
	ev := mcpProxyAuditEvent(proxyDescEntry())
	if got := auditWireEntry(&ev, "id", auditLink{})["server_name"]; got != "kai-echo" {
		t.Errorf("proxy event server_name = %v; want kai-echo", got)
	}
	ev.ServerName = ""
	if _, ok := auditWireEntry(&ev, "id", auditLink{})["server_name"]; ok {
		t.Errorf("an event with no server carries a server_name key")
	}
}

// An entry that already carries taxonomy keeps it; the rule lookup only fills
// an empty one.
func TestWithRuleTaxonomy_OnlyFillsEmpty_4734(t *testing.T) {
	e := proxyWriteEntry("x")
	e.TriggeredRules = append(e.TriggeredRules, proxyDescRule)
	if got := withRuleTaxonomy(e, proxyRuleTaxonomy).AllTaxonomyRefs(); len(got) != 1 || got[0] != proxyTamperNode {
		t.Errorf("taxonomy = %v; want the entry's own [%s]", got, proxyTamperNode)
	}
	if got := withRuleTaxonomy(proxyDescEntry(), nil).AllTaxonomyRefs(); len(got) != 0 {
		t.Errorf("nil lookup gave %v", got)
	}
}

// A record that carries only a Go intercept's ref (no per-rule refs) uploads
// that node, and its reason, as the hook's MCP event does through
// AllTaxonomyRefs (#4734 review: the wire must not read TaxonomyRefs alone).
func TestMCPProxyAuditEvent_GoInterceptTaxonomyAndReason_4734(t *testing.T) {
	ev := mcpProxyAuditEvent(mcp.AuditEntry{
		ToolName:       "resources/updated",
		Decision:       "BLOCK",
		TriggeredRules: []string{"block-secret-resource"},
		Reasons:        []string{"URI matches blocked resource pattern"},
		Source:         "mcp-proxy-resources-updated",
		TaxonomyRef:    "unauthorized-execution/agentic-attacks/mcp-resource-content-injection",
	})
	w := auditWireEntry(&ev, "id", auditLink{})
	tax, _ := w["taxonomy"].([]string)
	if len(tax) != 1 || tax[0] != "unauthorized-execution/agentic-attacks/mcp-resource-content-injection" {
		t.Errorf("wire taxonomy = %v; want the intercept's node", w["taxonomy"])
	}
	if w["reason"] != "URI matches blocked resource pattern" {
		t.Errorf("wire reason = %v", w["reason"])
	}
}

// The uploader a long-lived MCP proxy starts must be reaped. Started and
// released, each one stayed a zombie until the proxy exited: one per decision
// until the user ran out of processes (#4734 review).
func TestStartReaped_CollectsTheChild_4734(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	reaped, err := startReaped(cmd)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-reaped:
	case <-time.After(30 * time.Second):
		t.Fatal("the child exited but was never reaped")
	}
	if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
		t.Fatalf("process state %v; want an exited, collected child", cmd.ProcessState)
	}
}
