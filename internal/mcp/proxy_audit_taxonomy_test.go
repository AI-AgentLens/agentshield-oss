package mcp

import (
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

const tamperNode = "persistence-evasion/defense-evasion/security-tool-tampering"

func taxonomyTestPolicy() *MCPPolicy {
	return &MCPPolicy{
		Defaults: MCPDefaults{Decision: policy.DecisionAudit},
		Rules: []MCPRule{
			{
				ID:       "block-policy-write",
				Match:    MCPMatch{ToolName: "write_file"},
				Decision: policy.DecisionBlock,
				Reason:   "AgentShield's policy file is protected.",
				Taxonomy: tamperNode,
			},
			{
				ID:       "mcp-desc-hidden-instructions-sentinel",
				Match:    MCPMatch{ToolName: "__sentinel__"},
				Decision: policy.DecisionBlock,
				Engine:   "mcp-desc-hidden-instructions",
				Taxonomy: "unauthorized-execution/agentic-attacks/tool-description-poisoning",
			},
		},
		ResourceRules: []ResourceRule{
			{
				ID:       "block-secret-resource",
				Match:    ResourceMatch{URIPattern: "file:///secret/*"},
				Decision: policy.DecisionBlock,
				Taxonomy: "credential-exposure/credential-access/secret-file-read",
			},
		},
	}
}

// The proxy's tools/call record carries the per-rule taxonomy of the decision,
// in both modes (#4734). It used to carry only the Go-intercept TaxonomyRef,
// so a YAML rule's node never reached the record, and MCP rules have no
// rule-id fallback in the SaaS.
func TestToolCallAuditEntryCarriesRuleTaxonomy_4734(t *testing.T) {
	for _, mode := range []string{"enforce", "audit-only"} {
		var entries []AuditEntry
		h := newMessageHandler(NewPolicyEvaluator(taxonomyTestPolicy()), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "kai-echo", t.TempDir(), nil, nil)
		h.Mode = mode
		h.HandleToolCall(modeToolCall(t, 1, "write_file", map[string]interface{}{"path": "/tmp/notes.txt"}))
		e := lastToolEntry(t, entries, "write_file")
		if !hasRule(e.TriggeredRules, "block-policy-write") {
			t.Fatalf("%s: rules %v; want block-policy-write", mode, e.TriggeredRules)
		}
		if got := e.AllTaxonomyRefs(); !hasRule(got, tamperNode) {
			t.Errorf("%s: record taxonomy %v; want %s", mode, got, tamperNode)
		}
		if e.ServerName != "kai-echo" {
			t.Errorf("%s: server %q; want kai-echo", mode, e.ServerName)
		}
	}
}

// RuleTaxonomyRefs reads the declared taxonomy of tool, sentinel and resource
// rules by id, in order, and skips ids that name no rule (a scanner's signal
// label) (#4734).
func TestRuleTaxonomyRefs_4734(t *testing.T) {
	e := NewPolicyEvaluator(taxonomyTestPolicy())
	got := e.RuleTaxonomyRefs([]string{"tool-description-poisoning", "mcp-desc-hidden-instructions-sentinel", "block-secret-resource", "block-policy-write"})
	want := []string{
		"unauthorized-execution/agentic-attacks/tool-description-poisoning",
		"credential-exposure/credential-access/secret-file-read",
		tamperNode,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("RuleTaxonomyRefs = %v; want %v", got, want)
	}
	if got := e.RuleTaxonomyRefs([]string{"no-such-rule"}); len(got) != 0 {
		t.Errorf("unknown id gave %v; want none", got)
	}
	var nilEval *PolicyEvaluator
	if got := nilEval.RuleTaxonomyRefs([]string{"block-policy-write"}); got != nil {
		t.Errorf("nil evaluator gave %v; want nil", got)
	}
}

// AllTaxonomyRefs merges an entry's Go-intercept ref with its per-rule refs,
// intercept first, without duplicates, as MCPEvalResult.AllTaxonomyRefs does.
func TestAuditEntryAllTaxonomyRefs_4734(t *testing.T) {
	e := AuditEntry{TaxonomyRef: "a/b/c", TaxonomyRefs: []string{"d/e/f", "a/b/c"}}
	if got, want := e.AllTaxonomyRefs(), []string{"a/b/c", "d/e/f"}; !reflect.DeepEqual(got, want) {
		t.Errorf("AllTaxonomyRefs = %v; want %v", got, want)
	}
	if got := (AuditEntry{}).AllTaxonomyRefs(); got == nil || len(got) != 0 {
		t.Errorf("empty entry = %#v; want a non-nil empty list", got)
	}
}

const argExfilNode = "data-exfiltration/llm-data-flow/mcp-prompts-get-argument-exfiltration"

func newTaxonomyHandler(t *testing.T) (*MessageHandler, *[]AuditEntry) {
	t.Helper()
	var entries []AuditEntry
	h := newMessageHandler(NewPolicyEvaluator(taxonomyTestPolicy()), func(e AuditEntry) { entries = append(entries, e) }, io.Discard, "kai-echo", t.TempDir(), nil, nil)
	return h, &entries
}

func handlerMsg(t *testing.T, method string, params interface{}) *Message {
	t.Helper()
	raw, _ := json.Marshal(map[string]interface{}{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	msg, _, err := ParseMessage(raw)
	if err != nil {
		t.Fatalf("ParseMessage %s: %v", method, err)
	}
	return msg
}

// A benign prompts/get or completion/complete record carries no taxonomy. It
// used to carry the argument-exfiltration node on every call, so each benign
// prompt fetch would upload as an exfiltration receipt (#4734 review). The
// node stays when the argument scan fires.
func TestPromptArgumentRecords_TaxonomyOnlyWhenAScanFired_4734(t *testing.T) {
	h, entries := newTaxonomyHandler(t)
	h.HandlePromptsGetRequest(handlerMsg(t, MethodPromptsGet, map[string]interface{}{"name": "greet", "arguments": map[string]string{"who": "x"}}))
	h.HandleCompletionCompleteRequest(handlerMsg(t, MethodCompletionComplete, map[string]interface{}{
		"ref": map[string]string{"type": "ref/prompt", "name": "greet"}, "argument": map[string]string{"name": "who", "value": "x"},
	}))
	for _, tool := range []string{MethodPromptsGet, MethodCompletionComplete} {
		if got := lastToolEntry(t, *entries, tool).AllTaxonomyRefs(); len(got) != 0 {
			t.Errorf("benign %s record carries taxonomy %v; want none", tool, got)
		}
	}

	token := "ghp_" + strings.Repeat("A1b2", 9)
	h.HandlePromptsGetRequest(handlerMsg(t, MethodPromptsGet, map[string]interface{}{"name": "greet", "arguments": map[string]string{"who": token}}))
	e := lastToolEntry(t, *entries, MethodPromptsGet)
	if !hasRule(e.TriggeredRules, "argument-content-scan") {
		t.Fatalf("token in prompts/get arguments: rules %v; want argument-content-scan", e.TriggeredRules)
	}
	if !hasRule(e.AllTaxonomyRefs(), argExfilNode) {
		t.Errorf("scanned prompts/get record taxonomy %v; want %s", e.AllTaxonomyRefs(), argExfilNode)
	}
}
