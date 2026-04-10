package mcp

import (
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/policy"
)

// Regression test for issue #1152: MCP structural rules that require both a
// URL match and a `method` arg filter must still fire when the tool name
// encodes the HTTP method (http_post, http_put, etc.) and the caller does
// not pass a separate `method` argument. Before the fix, matchArgField
// returned false for the missing method field, causing silent FN on every
// critical BLOCK rule that uses this pattern.
func TestMatchStructural_MethodInferenceFromTypedTools(t *testing.T) {
	// Rule: BLOCK HTTP PUT/POST to /v2/.../manifests/... (Docker registry push).
	rule := MCPStructuralMatch{
		ToolNameAny: []string{
			"http_request", "http_post", "http_put", "http_delete", "http_patch",
			"post_request", "put_request",
		},
		ArgsMatch: map[string]ArgFieldMatch{
			"url": {
				PatternAny: []string{`(?i)/v2/[^/]+(?:/[^/]+)*/manifests/`},
			},
			"method": {
				PatternAny: []string{`(?i)^(PUT|POST)$`},
			},
		},
	}

	tests := []struct {
		name   string
		tool   string
		args   map[string]interface{}
		expect bool
	}{
		// Attacker-bypass cases: typed tool, no method arg. MUST match.
		{
			name:   "http_put infers PUT",
			tool:   "http_put",
			args:   map[string]interface{}{"url": "https://registry-1.docker.io/v2/myorg/myimage/manifests/latest"},
			expect: true,
		},
		{
			name:   "http_post infers POST",
			tool:   "http_post",
			args:   map[string]interface{}{"url": "https://ghcr.io/v2/org/image/manifests/v1.0.0"},
			expect: true,
		},
		{
			name:   "put_request infers PUT",
			tool:   "put_request",
			args:   map[string]interface{}{"url": "https://registry-1.docker.io/v2/myorg/myimage/manifests/latest"},
			expect: true,
		},
		// Legacy path: explicit method arg still wins.
		{
			name:   "http_request with explicit PUT",
			tool:   "http_request",
			args:   map[string]interface{}{"url": "https://registry-1.docker.io/v2/myorg/myimage/manifests/latest", "method": "PUT"},
			expect: true,
		},
		// Generic tool, no method arg: inference should NOT fire (no method token
		// in "http_request"), so the rule correctly doesn't match — explicit
		// method arg is still required for generic tools.
		{
			name:   "http_request without method arg does not match (correct)",
			tool:   "http_request",
			args:   map[string]interface{}{"url": "https://registry-1.docker.io/v2/myorg/myimage/manifests/latest"},
			expect: false,
		},
		// Typed GET tool — inferred method is GET, which doesn't match PUT|POST filter.
		{
			name:   "http_get infers GET, filtered out",
			tool:   "http_get",
			args:   map[string]interface{}{"url": "https://registry-1.docker.io/v2/myorg/myimage/manifests/latest"},
			expect: false,
		},
		// URL doesn't match.
		{
			name:   "http_put to docs URL",
			tool:   "http_put",
			args:   map[string]interface{}{"url": "https://docs.docker.com/registry/"},
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchStructural(tt.tool, tt.args, rule)
			if got != tt.expect {
				t.Errorf("matchStructural(%q, %v) = %v, want %v", tt.tool, tt.args, got, tt.expect)
			}
		})
	}
}

func TestInferMethodFromToolName(t *testing.T) {
	tests := []struct {
		tool string
		want string
	}{
		{"http_post", "POST"},
		{"http_put", "PUT"},
		{"http_delete", "DELETE"},
		{"http_patch", "PATCH"},
		{"http_get", "GET"},
		{"post_request", "POST"},
		{"put_request", "PUT"},
		{"delete_request", "DELETE"},
		{"patch_request", "PATCH"},
		{"get_request", "GET"},
		{"HTTP_POST", "POST"},       // case-insensitive
		{"do-put", "PUT"},           // hyphen separator
		{"http.patch", "PATCH"},     // dot separator
		{"http_request", ""},        // generic — no method token
		{"network_request", ""},     // generic
		{"fetch_url", ""},           // generic
		{"make_request", ""},        // generic
		{"api_request", ""},         // generic
		{"send_request", ""},        // generic
		{"upload_file", ""},         // no method word
		{"list_items", ""},          // no method word
		{"write_file", ""},          // no method word
		{"", ""},                    // empty
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			got := inferMethodFromToolName(tt.tool)
			if got != tt.want {
				t.Errorf("inferMethodFromToolName(%q) = %q, want %q", tt.tool, got, tt.want)
			}
		})
	}
}

// Ensure matchStructuralRule (exported wrapper) delegates the inference.
func TestMatchStructuralRule_MethodInferenceDelegation(t *testing.T) {
	rule := MCPStructuralRule{
		ID: "test-block-k8s-pod",
		Match: MCPStructuralMatch{
			ToolNameAny: []string{"http_request", "http_post", "http_delete"},
			ArgsMatch: map[string]ArgFieldMatch{
				"url": {
					PatternAny: []string{`(?i)/api/v1/namespaces/[^/]+/pods`},
				},
				"method": {
					PatternAny: []string{`(?i)^(POST|PUT|PATCH|DELETE)$`},
				},
			},
		},
		Decision: policy.DecisionBlock,
	}

	// BEFORE fix: this silently fell through to ALLOW because method field missing.
	// AFTER fix: http_post infers POST, matches filter, rule fires.
	if !matchStructuralRule("http_post",
		map[string]interface{}{"url": "https://k8s.internal:6443/api/v1/namespaces/default/pods"},
		rule) {
		t.Error("expected http_post (typed tool) without method arg to trigger rule via method inference")
	}
	if !matchStructuralRule("http_delete",
		map[string]interface{}{"url": "https://k8s.internal:6443/api/v1/namespaces/default/pods/my-pod"},
		rule) {
		t.Error("expected http_delete (typed tool) without method arg to trigger rule via method inference")
	}
}
