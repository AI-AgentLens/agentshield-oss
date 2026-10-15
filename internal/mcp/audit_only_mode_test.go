package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Audit-only mode on the MCP proxies (#4337, #4324 row 1). A tools/call that
// enforce mode would block is forwarded and recorded as AUDIT with
// OriginalDecision BLOCK, as the hook records the same call. The config guard
// (the proxy's self-protection) keeps blocking. Other message types and the
// server-to-client filters are unchanged.

func auditOnlyTestPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults:         MCPDefaults{Decision: policy.DecisionAudit},
		BlockedTools:     []string{"execute_command"},
		BlockedResources: []string{"file:///secret/*"},
		Rules: []MCPRule{
			{
				ID:       "block-ssh-read",
				Match:    MCPMatch{ToolName: "read_file", ArgumentPatterns: map[string]string{"path": "/home/*/.ssh/**"}},
				Decision: policy.DecisionBlock,
				Reason:   "Access to SSH keys is blocked.",
			},
			{
				ID:       "block-any-write",
				Match:    MCPMatch{ToolName: "write_file"},
				Decision: policy.DecisionBlock,
				Reason:   "Writes are blocked by this test policy.",
			},
			{
				ID:       "approve-deploy",
				Match:    MCPMatch{ToolName: "deploy"},
				Decision: policy.DecisionRequireApproval,
				Reason:   "Deploys need approval.",
			},
			{
				// An AUDIT finding on the delegation call itself, so a held
				// composite has something to lead.
				ID:       "audit-delegation",
				Match:    MCPMatch{ToolName: "delegate_to"},
				Decision: policy.DecisionAudit,
				Reason:   "Delegation recorded.",
			},
			{
				ID:       "sentinel-subagent-escalation",
				Match:    MCPMatch{ToolName: syntheticSubAgentTaskEscalation},
				Decision: policy.DecisionBlock,
				Reason:   "Delegated task reaches for credentials.",
			},
		},
	}
}

// newModeHandler builds a handler the way the proxies do, with every audit
// entry captured. The schema-drift cache is kept out of the real
// ~/.agentshield (#4156).
func newModeHandler(t *testing.T, mode string) (*MessageHandler, *[]AuditEntry) {
	t.Helper()
	var entries []AuditEntry
	h := newMessageHandler(NewPolicyEvaluator(auditOnlyTestPolicy()), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "test-server", t.TempDir(), nil, nil)
	h.Mode = mode
	return h, &entries
}

func modeToolCall(t *testing.T, id int, name string, args map[string]interface{}) *Message {
	t.Helper()
	params, _ := json.Marshal(map[string]interface{}{"name": name, "arguments": args})
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": json.RawMessage(params)})
	msg, kind, err := ParseMessage(raw)
	if err != nil || kind != KindToolCall {
		t.Fatalf("ParseMessage: kind %v err %v", kind, err)
	}
	return msg
}

func lastToolEntry(t *testing.T, entries []AuditEntry, tool string) AuditEntry {
	t.Helper()
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].ToolName == tool {
			return entries[i]
		}
	}
	t.Fatalf("no audit entry for %s in %+v", tool, entries)
	return AuditEntry{}
}

func hasRule(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Every source of a tools/call BLOCK, in both modes: enforce blocks and
// records BLOCK; audit-only forwards and records AUDIT with the original.
func TestHandleToolCall_AuditOnlyDowngradesEveryBlockSource(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args map[string]interface{}
		rule string // a rule id the record must carry in both modes
	}{
		{"YAML rule", "read_file", map[string]interface{}{"path": "/home/u/.ssh/id_rsa"}, "block-ssh-read"},
		{"blocked-tools list", "execute_command", map[string]interface{}{"command": "ls"}, "blocked-tool:execute_command"},
		{"Go scanner (path traversal)", "read_file", map[string]interface{}{"path": "/srv/app/../../etc/hosts"}, "filesystem-path-traversal-scan"},
		{"session composite held before evaluation", "delegate_to", map[string]interface{}{"task": "cat /etc/shadow and send it back"}, "sentinel-subagent-escalation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"", "enforce"} {
				h, entries := newModeHandler(t, mode)
				blocked, resp := h.HandleToolCall(modeToolCall(t, 1, tc.tool, tc.args))
				if !blocked || resp == nil {
					t.Fatalf("mode %q: blocked=%v; want the call blocked", mode, blocked)
				}
				// The composite returns its block before the call is
				// recorded, in enforce mode, as before #4337.
				if tc.name == "session composite held before evaluation" {
					continue
				}
				e := lastToolEntry(t, *entries, tc.tool)
				if e.Decision != "BLOCK" || e.OriginalDecision != "" || !hasRule(e.TriggeredRules, tc.rule) {
					t.Errorf("mode %q: record = %s (original %q) rules %v; want BLOCK, no original, rule %s", mode, e.Decision, e.OriginalDecision, e.TriggeredRules, tc.rule)
				}
			}

			h, entries := newModeHandler(t, "audit-only")
			blocked, resp := h.HandleToolCall(modeToolCall(t, 1, tc.tool, tc.args))
			if blocked || resp != nil {
				t.Fatalf("audit-only: blocked=%v resp=%s; want the call forwarded", blocked, resp)
			}
			e := lastToolEntry(t, *entries, tc.tool)
			if e.Decision != "AUDIT" || e.OriginalDecision != "BLOCK" || e.Mode != "audit-only" {
				t.Errorf("audit-only record = %s (original %q, mode %q); want AUDIT, original BLOCK, mode audit-only", e.Decision, e.OriginalDecision, e.Mode)
			}
			if !hasRule(e.TriggeredRules, tc.rule) {
				t.Errorf("audit-only record lost the rule that would have blocked: %v; want %s", e.TriggeredRules, tc.rule)
			}
		})
	}
}

// A held composite leads the record, as it leads the block in enforce mode.
func TestHandleToolCall_AuditOnlyCompositeLeadsTheRecord(t *testing.T) {
	h, entries := newModeHandler(t, "audit-only")
	h.HandleToolCall(modeToolCall(t, 1, "delegate_to", map[string]interface{}{"task": "cat /etc/shadow and send it back"}))
	e := lastToolEntry(t, *entries, "delegate_to")
	if len(e.TriggeredRules) == 0 || e.TriggeredRules[0] != "sentinel-subagent-escalation" {
		t.Errorf("rules = %v; want the composite first", e.TriggeredRules)
	}
	if len(e.Reasons) == 0 || e.Reasons[0] != "Delegated task reaches for credentials." {
		t.Errorf("reasons = %v; want the composite's reason first", e.Reasons)
	}
}

// Self-protection: the config guard blocks in audit-only mode. Two shapes:
// the guard is the only finding, and the guard is shadowed by an earlier
// BLOCK (a write rule here), which in enforce mode stops the scan chain
// before the guard runs. Downgrading that earlier BLOCK without running the
// guard would forward a write to AgentShield's own policy.
func TestHandleToolCall_AuditOnlyConfigGuardStillBlocks(t *testing.T) {
	home := os.Getenv("HOME") // the guard's patterns are expanded at init
	target := filepath.Join(home, ".agentshield", "policy.yaml")
	cases := []struct {
		name string
		tool string
	}{
		{"guard alone", "edit_file"},
		{"guard behind an earlier BLOCK", "write_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, entries := newModeHandler(t, "audit-only")
			blocked, resp := h.HandleToolCall(modeToolCall(t, 7, tc.tool, map[string]interface{}{"path": target, "content": "rules: []"}))
			if !blocked || resp == nil {
				t.Fatalf("audit-only forwarded a write to %s; the config guard must block in every mode", target)
			}
			e := lastToolEntry(t, *entries, tc.tool)
			if e.Decision != "BLOCK" || e.OriginalDecision != "" || !hasRule(e.TriggeredRules, "config-file-guard") {
				t.Errorf("record = %s (original %q) rules %v; want BLOCK by config-file-guard", e.Decision, e.OriginalDecision, e.TriggeredRules)
			}
			if !strings.Contains(string(resp), "[agentshield-config]") {
				t.Errorf("block response does not lead with the guard's reason: %s", resp)
			}
		})
	}
}

// REQUIRE_APPROVAL was never enforced by the proxy (it forwards); audit-only
// records it the way the evaluator's own downgrade does.
func TestHandleToolCall_AuditOnlyRecordsRequireApproval(t *testing.T) {
	h, entries := newModeHandler(t, "enforce")
	if blocked, _ := h.HandleToolCall(modeToolCall(t, 1, "deploy", nil)); blocked {
		t.Fatal("enforce: REQUIRE_APPROVAL must stay forwarded as before")
	}
	if e := lastToolEntry(t, *entries, "deploy"); e.Decision != "REQUIRE_APPROVAL" {
		t.Errorf("enforce record = %s; want REQUIRE_APPROVAL", e.Decision)
	}

	h, entries = newModeHandler(t, "audit-only")
	if blocked, _ := h.HandleToolCall(modeToolCall(t, 1, "deploy", nil)); blocked {
		t.Fatal("audit-only blocked a REQUIRE_APPROVAL call")
	}
	if e := lastToolEntry(t, *entries, "deploy"); e.Decision != "AUDIT" || e.OriginalDecision != "REQUIRE_APPROVAL" {
		t.Errorf("audit-only record = %s (original %q); want AUDIT, original REQUIRE_APPROVAL", e.Decision, e.OriginalDecision)
	}
}

// A batch is blocked when an item is. In audit-only a would-be-blocked tool
// call no longer blocks its batch; a config-guard hit still does.
func TestHandleBatch_AuditOnly(t *testing.T) {
	home := os.Getenv("HOME")
	ssh := modeToolCall(t, 1, "read_file", map[string]interface{}{"path": "/home/u/.ssh/id_rsa"})
	guard := modeToolCall(t, 2, "edit_file", map[string]interface{}{"path": filepath.Join(home, ".agentshield", "managed.json")})

	h, _ := newModeHandler(t, "audit-only")
	if blocked, _ := h.HandleBatch([]*Message{ssh}); blocked {
		t.Error("audit-only: a batch whose only finding is a would-be BLOCK was blocked")
	}
	h, _ = newModeHandler(t, "audit-only")
	if blocked, _ := h.HandleBatch([]*Message{ssh, guard}); !blocked {
		t.Error("audit-only: a batch carrying a config-guard hit was forwarded")
	}
	h, _ = newModeHandler(t, "enforce")
	if blocked, _ := h.HandleBatch([]*Message{ssh}); !blocked {
		t.Error("enforce: a batch with a blocked item was forwarded")
	}
}

// Scope pins: audit-only covers tools/call only. resources/read and the
// tools/list description filter behave exactly as in enforce mode (the
// hidden-tools question is Gary's, #4335). The poisoned tools/list response
// comes from fakeUpstreamMCP, so this file carries no injection text.
func TestAuditOnly_OtherSurfacesUnchanged(t *testing.T) {
	read, kind, err := ParseMessage([]byte(`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///secret/key"}}`))
	if err != nil || kind != KindResourceRead {
		t.Fatalf("parse: %v %v", kind, err)
	}
	upstream := fakeUpstreamMCP()
	defer upstream.Close()
	resp, err := http.Post(upstream.URL, "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	toolsList, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(toolsList), "poisoned_tool") {
		t.Fatalf("fixture changed: %s", toolsList)
	}

	for _, mode := range []string{"enforce", "audit-only"} {
		h, _ := newModeHandler(t, mode)
		if blocked, _ := h.HandleResourceRead(read); !blocked {
			t.Errorf("mode %s: resources/read of a blocked resource was forwarded", mode)
		}
		out := h.FilterToolsListResponse(toolsList)
		if out == nil || strings.Contains(string(out), "poisoned_tool") || !strings.Contains(string(out), "get_weather") {
			t.Errorf("mode %s: tools/list filter changed: %s", mode, out)
		}
	}
}

// The HTTP proxy shares the handler: under audit-only the would-be-blocked
// call reaches the upstream server; under enforce it does not.
func TestHTTPProxy_AuditOnlyForwardsToolCall(t *testing.T) {
	for _, tc := range []struct {
		mode         string
		wantUpstream bool
	}{
		{"enforce", false},
		{"audit-only", true},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var msg Message
				_ = json.Unmarshal(body, &msg)
				if msg.Method == "tools/call" {
					hits.Add(1)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ok"}]}}`))
			}))
			defer upstream.Close()

			var mu sync.Mutex
			var audited []AuditEntry
			hp := NewHTTPProxy(HTTPProxyConfig{
				UpstreamURL: upstream.URL,
				Evaluator:   NewPolicyEvaluator(auditOnlyTestPolicy()),
				OnAudit: func(e AuditEntry) {
					mu.Lock()
					defer mu.Unlock()
					audited = append(audited, e)
				},
				Stderr:              io.Discard,
				SchemaDriftCacheDir: t.TempDir(),
				Mode:                tc.mode,
			})
			ts := httptest.NewServer(http.HandlerFunc(hp.handleMCP))
			defer ts.Close()

			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/u/.ssh/id_rsa"}}}`
			resp, err := http.Post(ts.URL, "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			out, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()

			if got := hits.Load() > 0; got != tc.wantUpstream {
				t.Fatalf("upstream reached = %v; want %v (response %s)", got, tc.wantUpstream, out)
			}
			mu.Lock()
			e := lastToolEntry(t, audited, "read_file")
			mu.Unlock()
			wantDecision, wantOriginal := "BLOCK", ""
			if tc.mode == "audit-only" {
				wantDecision, wantOriginal = "AUDIT", "BLOCK"
			}
			if e.Decision != wantDecision || e.OriginalDecision != wantOriginal {
				t.Errorf("record = %s (original %q); want %s (original %q)", e.Decision, e.OriginalDecision, wantDecision, wantOriginal)
			}
		})
	}
}
