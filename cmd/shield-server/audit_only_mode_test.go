package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// #4356. Audit-only mode must apply to shield-server's FINAL MCP verdict,
// after every block source, as the MCP proxies apply it (#4341). The evaluator
// used to downgrade its own verdict and the value_limits pass then set BLOCK
// on top, so an audit-only server still blocked on a value limit, with no
// original_decision. These tests use only symbols that exist on main, so they
// also run there: the audit-only rows of
// TestEvaluateMCPAuditOnlyDowngradesEveryBlockSource fail on main and the
// enforce rows pass.

// valueLimitPolicyYAML is an MCP policy holding one block source of each
// kind the shield-server MCP path has: blocked_tools, a BLOCK rule, a
// REQUIRE_APPROVAL rule, a BLOCK value limit and an AUDIT value limit. The
// tool names are invented so no embedded community rule matches them.
const valueLimitPolicyYAML = `defaults:
  decision: "AUDIT"
blocked_tools:
  - "wire_payment_4356"
rules:
  - id: test4356-block-payment-to-held-account
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    match:
      tool_name_any: ["send_payment_4356"]
      argument_patterns:
        recipient: "acct-held-*"
    decision: "BLOCK"
    reason: "Payment to a held account."
  - id: test4356-approve-payout
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    match:
      tool_name_any: ["approve_payout_4356"]
    decision: "REQUIRE_APPROVAL"
    reason: "Payouts need approval."
value_limits:
  - id: test4356-cap-payment-amount
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    tool_name_regex: ".*pay.*"
    argument: "amount"
    max: 1000.0
    decision: "BLOCK"
    reason: "Payment amount exceeds safety limit of $1,000."
  - id: test4356-audit-large-tip
    tool_name_regex: ".*tip_4356.*"
    argument: "amount"
    max: 100.0
    decision: "AUDIT"
    reason: "Large tip."
`

func writeValueLimitPolicy(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mcp-policy.yaml")
	if err := os.WriteFile(path, []byte(valueLimitPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// newModeServer builds a server in the given mode over the value-limit policy,
// with its own audit log so a test can read the record it wrote.
func newModeServer(t *testing.T, mode, mcpPolicy string) (*httptest.Server, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	srv, err := NewServer(Options{Version: "test", Mode: mode, MCPPolicyPath: mcpPolicy, LogPath: logPath})
	if err != nil {
		t.Fatalf("NewServer(mode %q): %v", mode, err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, logPath
}

func lastAuditRecord(t *testing.T, logPath string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var ev map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("audit line: %v\n%s", err, lines[len(lines)-1])
	}
	return ev
}

func containsAll(have []string, want ...string) bool {
	set := map[string]bool{}
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}

func TestEvaluateMCPAuditOnlyDowngradesEveryBlockSource(t *testing.T) {
	policy := writeValueLimitPolicy(t)
	enforce, _ := newModeServer(t, "enforce", policy)
	auditOnly, auditLog := newModeServer(t, "audit-only", policy)

	cases := []struct {
		name string
		req  evaluateRequest
		// enforce mode's verdict, pinned: nothing about it may change.
		wantEnforce string
		wantRules   []string
		// absentRules must not appear in enforce mode's record.
		absentRules []string
	}{
		{
			name:        "value limit alone (the issue's repro)",
			req:         evaluateRequest{ToolName: "mcp__billing__create_payment", Arguments: map[string]interface{}{"amount": 5000, "currency": "USD"}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"value-limit", "test4356-cap-payment-amount"},
		},
		{
			name:        "value limit, bare tool name",
			req:         evaluateRequest{ToolName: "create_payment", Arguments: map[string]interface{}{"amount": "5000"}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"value-limit", "test4356-cap-payment-amount"},
		},
		{
			// The rule BLOCKs, so enforce mode never consults value limits.
			// On main the audit-only evaluator downgraded the rule first,
			// the value-limit pass then ran on the AUDIT and blocked.
			name:        "rule BLOCK over a value limit",
			req:         evaluateRequest{ToolName: "send_payment_4356", Arguments: map[string]interface{}{"recipient": "acct-held-7", "amount": 5000}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"test4356-block-payment-to-held-account"},
			absentRules: []string{"value-limit"},
		},
		{
			name:        "blocked_tools over a value limit",
			req:         evaluateRequest{ToolName: "wire_payment_4356", Arguments: map[string]interface{}{"amount": 5000}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"blocked-tool:wire_payment_4356"},
			absentRules: []string{"value-limit"},
		},
		{
			// REQUIRE_APPROVAL does not stop the value-limit pass, so enforce
			// mode blocks. On main, audit-only reported BLOCK with
			// original_decision REQUIRE_APPROVAL.
			name:        "REQUIRE_APPROVAL rule then a value-limit BLOCK",
			req:         evaluateRequest{ToolName: "approve_payout_4356", Arguments: map[string]interface{}{"amount": 5000}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"test4356-approve-payout", "value-limit", "test4356-cap-payment-amount"},
		},
		// Controls: these decided the same on main.
		{
			name:        "control: rule-only BLOCK with taxonomy",
			req:         evaluateRequest{ToolName: "send_payment_4356", Arguments: map[string]interface{}{"recipient": "acct-held-7", "amount": 5}},
			wantEnforce: "BLOCK",
			wantRules:   []string{"test4356-block-payment-to-held-account"},
		},
		{
			name:        "control: REQUIRE_APPROVAL under the limit",
			req:         evaluateRequest{ToolName: "approve_payout_4356", Arguments: map[string]interface{}{"amount": 5}},
			wantEnforce: "REQUIRE_APPROVAL",
			wantRules:   []string{"test4356-approve-payout"},
		},
		{
			name:        "control: AUDIT value limit",
			req:         evaluateRequest{ToolName: "leave_tip_4356", Arguments: map[string]interface{}{"amount": 500}},
			wantEnforce: "AUDIT",
			wantRules:   []string{"value-limit-audit", "test4356-audit-large-tip"},
		},
		{
			name:        "no-op control: under every limit",
			req:         evaluateRequest{ToolName: "create_payment", Arguments: map[string]interface{}{"amount": 25}},
			wantEnforce: "AUDIT",
			absentRules: []string{"value-limit", "test4356-cap-payment-amount"},
		},
		{
			name:        "control: embedded community rule BLOCK",
			req:         evaluateRequest{ToolName: "read_file", Arguments: map[string]interface{}{"path": credentialPath()}},
			wantEnforce: "BLOCK",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, enf := postEval(t, enforce, tc.req)
			if enf.Decision != tc.wantEnforce || enf.OriginalDecision != "" || enf.Mode != "enforce" {
				t.Fatalf("enforce: decision %q, original_decision %q, mode %q (rules %v); want %q, none, enforce",
					enf.Decision, enf.OriginalDecision, enf.Mode, enf.Rules, tc.wantEnforce)
			}
			if !containsAll(enf.Rules, tc.wantRules...) {
				t.Fatalf("enforce: rules %v, want them to include %v", enf.Rules, tc.wantRules)
			}
			for _, r := range tc.absentRules {
				if containsAll(enf.Rules, r) {
					t.Fatalf("enforce: rules %v include %q", enf.Rules, r)
				}
			}

			_, aud := postEval(t, auditOnly, tc.req)
			wantDecision, wantOriginal := enf.Decision, ""
			if enf.Decision == "BLOCK" || enf.Decision == "REQUIRE_APPROVAL" {
				wantDecision, wantOriginal = "AUDIT", enf.Decision
			}
			if aud.Decision != wantDecision || aud.OriginalDecision != wantOriginal || aud.Mode != "audit-only" {
				t.Errorf("audit-only: decision %q, original_decision %q, mode %q (rules %v); want %q, %q, audit-only",
					aud.Decision, aud.OriginalDecision, aud.Mode, aud.Rules, wantDecision, wantOriginal)
			}
			// The receipt path reads these: audit-only must record exactly
			// what enforce mode decided on.
			if !reflect.DeepEqual(aud.Rules, enf.Rules) {
				t.Errorf("audit-only rules %v, want enforce mode's %v", aud.Rules, enf.Rules)
			}
			if !reflect.DeepEqual(aud.Reasons, enf.Reasons) {
				t.Errorf("audit-only reasons %v, want enforce mode's %v", aud.Reasons, enf.Reasons)
			}
			if !reflect.DeepEqual(aud.Taxonomy, enf.Taxonomy) {
				t.Errorf("audit-only taxonomy %v, want enforce mode's %v", aud.Taxonomy, enf.Taxonomy)
			}
			ev := lastAuditRecord(t, auditLog)
			if ev["decision"] != wantDecision || ev["mode"] != "audit-only" || ev["tool_name"] != tc.req.ToolName {
				t.Errorf("audit record: decision %v, mode %v, tool %v; want %q, audit-only, %q", ev["decision"], ev["mode"], ev["tool_name"], wantDecision, tc.req.ToolName)
			}
			if got, _ := ev["original_decision"].(string); got != wantOriginal {
				t.Errorf("audit record original_decision %q, want %q", got, wantOriginal)
			}
		})
	}
}

// The taxonomy assertion above must be able to see a taxonomy: the rule BLOCK
// carries one. The value-limit rows did not exercise it, because a value-limit
// BLOCK used to carry no node in either mode (ValueLimitFinding dropped the
// rule's taxonomy, a gap that predated #4356). It carries its rule's node now;
// TestEvaluateMCPValueLimitCarriesRuleTaxonomy pins that, on tool names no
// embedded rule matches, so the node it sees can only be the value limit's.
func TestEvaluateMCPAuditOnlyKeepsRuleTaxonomy(t *testing.T) {
	policy := writeValueLimitPolicy(t)
	auditOnly, _ := newModeServer(t, "audit-only", policy)
	_, aud := postEval(t, auditOnly, evaluateRequest{ToolName: "send_payment_4356", Arguments: map[string]interface{}{"recipient": "acct-held-7", "amount": 5000}})
	if aud.Decision != "AUDIT" || aud.OriginalDecision != "BLOCK" {
		t.Fatalf("decision %q/%q, want AUDIT/BLOCK", aud.Decision, aud.OriginalDecision)
	}
	if !containsAll(aud.Taxonomy, "destructive-ops/resource-commitment/unbounded-transfer") {
		t.Errorf("taxonomy %v, want the rule's node", aud.Taxonomy)
	}
}

// valueLimitTaxonomyPolicyYAML holds value limits with and without a taxonomy
// node, on invented tool names that no embedded rule (community or premium)
// matches, so every node on a verdict comes from this policy.
const valueLimitTaxonomyPolicyYAML = `defaults:
  decision: "AUDIT"
rules:
  - id: test-vltax-approve-op
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    match:
      tool_name_any: ["zq_vltax_approve_4394"]
    decision: "REQUIRE_APPROVAL"
    reason: "Needs approval."
value_limits:
  - id: test-vltax-cap-op-amount
    taxonomy: "destructive-ops/resource-commitment/unbounded-transfer"
    tool_name_regex: "zq_vltax_(op|approve)_4394$"
    argument: "amount"
    max: 1000.0
    decision: "BLOCK"
    reason: "Amount exceeds 1000."
  - id: test-vltax-audit-op-amount
    taxonomy: "unauthorized-execution/agentic-attacks/agent-payment-mandate-forgery"
    tool_name_regex: "^zq_vltax_audit_4394$"
    argument: "amount"
    max: 100.0
    decision: "AUDIT"
    reason: "Amount above 100."
  - id: test-vltax-audit-no-node
    tool_name_regex: "^zq_vltax_free_4394$"
    argument: "amount"
    max: 100.0
    decision: "AUDIT"
    reason: "Amount above 100, no node."
`

// A value-limit verdict carries its rule's taxonomy node, in enforce mode and
// in audit-only mode, on the wire and in the audit record, so its receipt
// attests to the node instead of only to a rule id the consumer must resolve
// itself. ValueLimitFinding used to drop ValueLimitRule.Taxonomy: the first
// three rows fail on main, the others are controls that pass there.
func TestEvaluateMCPValueLimitCarriesRuleTaxonomy(t *testing.T) {
	const (
		transfer = "destructive-ops/resource-commitment/unbounded-transfer"
		mandate  = "unauthorized-execution/agentic-attacks/agent-payment-mandate-forgery"
	)
	path := filepath.Join(t.TempDir(), "mcp-policy.yaml")
	if err := os.WriteFile(path, []byte(valueLimitTaxonomyPolicyYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	args := func(amount float64) map[string]interface{} { return map[string]interface{}{"amount": amount} }
	cases := []struct {
		name    string
		req     evaluateRequest
		wantDec string // enforce mode's decision
		wantTax []string
	}{
		{"value-limit BLOCK", evaluateRequest{ToolName: "zq_vltax_op_4394", Arguments: args(5000)}, "BLOCK", []string{transfer}},
		{"value-limit BLOCK, mcp__ wire name", evaluateRequest{ToolName: "mcp__zqsrv__zq_vltax_op_4394", Arguments: args(5000)}, "BLOCK", []string{transfer}},
		{"value-limit AUDIT", evaluateRequest{ToolName: "zq_vltax_audit_4394", Arguments: args(500)}, "AUDIT", []string{mandate}},
		// Controls.
		{"control: REQUIRE_APPROVAL rule then a value-limit BLOCK on the same node, listed once", evaluateRequest{ToolName: "zq_vltax_approve_4394", Arguments: args(5000)}, "BLOCK", []string{transfer}},
		{"control: value limit without a node adds none", evaluateRequest{ToolName: "zq_vltax_free_4394", Arguments: args(500)}, "AUDIT", nil},
		{"no-op control: under every limit", evaluateRequest{ToolName: "zq_vltax_op_4394", Arguments: args(25)}, "AUDIT", nil},
	}
	for _, mode := range []string{"enforce", "audit-only"} {
		ts, logPath := newModeServer(t, mode, path)
		for _, tc := range cases {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				_, v := postEval(t, ts, tc.req)
				dec := v.Decision
				if v.OriginalDecision != "" {
					dec = v.OriginalDecision
				}
				if dec != tc.wantDec {
					t.Fatalf("decision %q (original %q, rules %v), want enforce mode's %q", v.Decision, v.OriginalDecision, v.Rules, tc.wantDec)
				}
				if !reflect.DeepEqual(v.Taxonomy, tc.wantTax) {
					t.Errorf("taxonomy %v, want %v (rules %v)", v.Taxonomy, tc.wantTax, v.Rules)
				}
				ev := lastAuditRecord(t, logPath)
				var recTax []string
				if raw, ok := ev["taxonomy"].([]interface{}); ok {
					for _, r := range raw {
						s, _ := r.(string)
						recTax = append(recTax, s)
					}
				}
				if !reflect.DeepEqual(recTax, tc.wantTax) {
					t.Errorf("audit record taxonomy %v, want %v", ev["taxonomy"], tc.wantTax)
				}
			})
		}
	}
}

// captureStderr runs f with os.Stderr redirected and returns what it wrote.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		var b strings.Builder
		_, _ = io.Copy(&b, bufio.NewReader(r))
		done <- b.String()
	}()
	f()
	os.Stderr = orig
	_ = w.Close()
	return <-done
}

// --mode goes through config.Load's normalisation (#4356 part 2). The engine
// already enforced on every unrecognised value; the reported mode now says
// so. No spelling other than the exact "audit-only" becomes audit-only: the
// fail-safe for an unknown value (enforce, with a warning) is a documented
// decision (config.TestConfig_InvalidMode).
func TestNewServerNormalisesMode(t *testing.T) {
	cases := []struct {
		flag     string
		wantMode string
		wantWarn bool
	}{
		{"", "enforce", false},
		{"enforce", "enforce", false},
		{"audit-only", "audit-only", false},
		{"observe", "enforce", true},
		{"Audit-Only", "enforce", true},
		{"audit_only", "enforce", true},
		{" audit-only", "enforce", true},
	}
	for _, tc := range cases {
		t.Run(tc.flag, func(t *testing.T) {
			var srv *Server
			var err error
			stderr := captureStderr(t, func() {
				srv, err = NewServer(Options{Version: "test", Mode: tc.flag, LogPath: filepath.Join(t.TempDir(), "audit.jsonl")})
			})
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			defer srv.Close()
			if warned := strings.Contains(stderr, "unrecognized mode"); warned != tc.wantWarn {
				t.Errorf("warning printed = %v, want %v; stderr:\n%s", warned, tc.wantWarn, stderr)
			}

			ts := httptest.NewServer(srv.Handler())
			defer ts.Close()
			resp, err := http.Get(ts.URL + "/healthz")
			if err != nil {
				t.Fatal(err)
			}
			var health healthResponse
			_ = json.NewDecoder(resp.Body).Decode(&health)
			_ = resp.Body.Close()
			if health.Mode != tc.wantMode {
				t.Errorf("/healthz mode = %q, want %q", health.Mode, tc.wantMode)
			}

			_, v := postEval(t, ts, evaluateRequest{ToolName: "read_file", Arguments: map[string]interface{}{"path": credentialPath()}})
			wantDecision := "BLOCK"
			if tc.wantMode == "audit-only" {
				wantDecision = "AUDIT"
			}
			if v.Mode != tc.wantMode || v.Decision != wantDecision {
				t.Errorf("verdict: mode %q decision %q, want %q %q", v.Mode, v.Decision, tc.wantMode, wantDecision)
			}
			_, sh := postEval(t, ts, evaluateRequest{Command: destructiveCommand()})
			if sh.Mode != tc.wantMode || sh.Decision != wantDecision {
				t.Errorf("shell verdict: mode %q decision %q, want %q %q", sh.Mode, sh.Decision, tc.wantMode, wantDecision)
			}
		})
	}
}
