package mcp

import (
	"encoding/json"
	"io"
	"testing"

	"github.com/AI-AgentLens/agentshield/internal/ossbuild"
)

// Coverage for the tool-response secret-overexposure scanner (issue #3807).
// See response_secret_scanner.go for the CVE-2026-67357 / ArcadeDB motivating
// case and the two-tier (confirmed-pattern BLOCK / field-name AUDIT) design.
//
// Vendor-shaped credential fixtures (PEM block, GitHub token, AWS key) are
// built from frag() (defined in response_error_remediation_scanner_test.go)
// rather than pasted as contiguous literals — AgentShield's own MCP content
// scanner (mcp-llmdf-block-credential-in-prompt) fires on a contiguous
// credential-shaped string in a tool-call argument, and this file's own
// content IS such an argument when written via an MCP-mediated tool. This is
// a true positive on the write tool call, not a false positive on the rule
// under test; see the "build phrases from fragments" convention this repo
// already uses in response_error_remediation_scanner_test.go.

func TestResponseSecret_ConfirmedPattern_ContentText(t *testing.T) {
	pemBlock := frag("-----BEGIN RSA PRI", "VATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRI", "VATE KEY-----")
	content := []ContentItem{
		{Type: "text", Text: "server diagnostics:\n" + pemBlock},
	}
	result := ScanToolCallResponseForSecrets(content, nil)
	if !result.Blocked {
		t.Fatalf("expected a PEM private key in response text to BLOCK, got %+v", result)
	}
	if result.Findings[0].Signal != SignalResponseSecretConfirmedPattern {
		t.Errorf("signal = %s, want %s", result.Findings[0].Signal, SignalResponseSecretConfirmedPattern)
	}
	if result.Findings[0].ContentIndex != 0 {
		t.Errorf("content index = %d, want 0", result.Findings[0].ContentIndex)
	}
}

func TestResponseSecret_ConfirmedPattern_StructuredContent(t *testing.T) {
	awsKey := frag("AKIA", "IOSFODNN7EXAMPLE")
	structured := map[string]interface{}{
		"host": "db.internal.example.com",
		"port": float64(5432),
		"auth": map[string]interface{}{
			// AWS access key ID shape — vendor-specific, fires regardless of
			// the field name carrying it.
			"internal_ref": awsKey,
		},
	}
	result := ScanToolCallResponseForSecrets(nil, structured)
	if !result.Blocked {
		t.Fatalf("expected an AWS access key value to BLOCK regardless of field name, got %+v", result)
	}
	var found bool
	for _, f := range result.Findings {
		if f.Signal == SignalResponseSecretConfirmedPattern && f.Field == "auth.internal_ref" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a confirmed-pattern finding at field auth.internal_ref, got %+v", result.Findings)
	}
}

// TestResponseSecret_FieldNameHeuristic_ArcadeDB reproduces the disclosed
// CVE-2026-67357 shape: a cluster token with no recognized vendor format,
// caught only because its field name matches the secret-naming convention.
func TestResponseSecret_FieldNameHeuristic_ArcadeDB(t *testing.T) {
	structured := map[string]interface{}{
		"host": "10.0.1.4",
		"port": float64(2480),
		"arcadedb": map[string]interface{}{
			"ha": map[string]interface{}{
				"clusterToken": "9f8a2c7e1b4d9f0a3c2e8b7a1d6f4c3e",
				"enabled":      true,
			},
		},
	}
	result := ScanToolCallResponseForSecrets(nil, structured)
	if result.Blocked {
		t.Errorf("field-name-only heuristic must AUDIT, not BLOCK, got blocked findings: %+v", result.Findings)
	}
	if !result.Found {
		t.Fatal("expected the arcadedb.ha.clusterToken field to be flagged")
	}
	var found bool
	for _, f := range result.Findings {
		if f.Signal == SignalResponseSecretFieldName && f.Field == "arcadedb.ha.clusterToken" {
			found = true
			if f.Blocking {
				t.Error("field-name signal must not be Blocking")
			}
		}
	}
	if !found {
		t.Errorf("expected a field-name finding at arcadedb.ha.clusterToken, got %+v", result.Findings)
	}
}

func TestResponseSecret_TrueNegatives(t *testing.T) {
	cases := []struct {
		name       string
		content    []ContentItem
		structured map[string]interface{}
	}{
		{
			name: "prose merely mentions tokens/secrets with no shape or field",
			content: []ContentItem{
				{Type: "text", Text: "The user's session token is stored securely and rotated every 24 hours."},
			},
		},
		{
			name: "LLM usage counters — the exact FP class the taxonomy node calls out",
			structured: map[string]interface{}{
				"max_tokens":        float64(4096),
				"prompt_tokens":     float64(512),
				"completion_tokens": float64(128),
				"total_tokens":      float64(640),
				// A server that stringifies its usage counters must not
				// change the verdict.
				"token_count": "640",
			},
		},
		{
			name: "bare 'key' field names — S3 object key / cache key / dict key vocabulary",
			structured: map[string]interface{}{
				"key":       "images/2026/photo.jpg",
				"cache_key": "user:1234:session:index",
				"sort_key":  "created_at#2026-09-13",
				"role_key":  "administrator",
			},
		},
		{
			name: "opaque-looking value under a non-secret field name",
			structured: map[string]interface{}{
				"request_id": "8f3a2c91-4b7d-4e2a-9c1f-6d8b3a5e7f21",
			},
		},
		{
			name: "short, non-opaque value under a sensitive field name",
			structured: map[string]interface{}{
				// 13 chars, digit+lowercase — below the 16-char opaque floor,
				// and ordinary config prose rather than a secret value.
				"password_policy": "min-length-12",
				"has_credential":  true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := ScanToolCallResponseForSecrets(tc.content, tc.structured)
			if result.Found {
				t.Errorf("expected no findings, got %+v", result.Findings)
			}
		})
	}
}

func TestResponseSecretSentinelsResolve(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	rules := loadPremiumPackRules(t, "mcp-sentinel.yaml")
	engine := NewPolicyEvaluator(&MCPPolicy{Rules: rules})
	signals := []ResponseSecretSignal{
		SignalResponseSecretConfirmedPattern,
		SignalResponseSecretFieldName,
	}
	for _, sig := range signals {
		key := responseSecretSentinelEngine(sig)
		if key == "" {
			t.Errorf("signal %s has no sentinel engine key", sig)
			continue
		}
		sent := engine.LookupSentinel(key)
		if sent == nil {
			t.Errorf("sentinel engine %q resolves to nil - add the rule to packs/premium/mcp/mcp-sentinel.yaml", key)
			continue
		}
		if sent.Taxonomy == "" {
			t.Errorf("sentinel %q carries no taxonomy ref", sent.ID)
		}
	}
}

// --- end-to-end through the proxy path -------------------------------------

func TestResponseSecret_EndToEndBlocksAndAudits(t *testing.T) {
	ossbuild.SkipPremiumSized(t)
	evaluator := NewPolicyEvaluator(&MCPPolicy{Rules: loadPremiumPackRules(t, "mcp-sentinel.yaml")})

	build := func(t *testing.T, structured map[string]interface{}) []byte {
		t.Helper()
		b, err := json.Marshal(map[string]interface{}{
			"jsonrpc": "2.0", "id": 7,
			"result": map[string]interface{}{
				"content":           []map[string]interface{}{{"type": "text", "text": "ok"}},
				"structuredContent": structured,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	t.Run("BLOCK tier replaces the response", func(t *testing.T) {
		githubToken := frag("ghp_", "1234567890abcdefghijklmnopqrstuvwxyz")
		structured := map[string]interface{}{
			"github_export": githubToken,
		}
		var audited []AuditEntry
		h := &MessageHandler{Stderr: io.Discard, Evaluator: evaluator,
			OnAudit: func(e AuditEntry) { audited = append(audited, e) }}
		filtered := h.FilterToolCallResponse(build(t, structured))
		if filtered == nil {
			t.Fatal("expected the response with a confirmed GitHub token to be replaced")
		}
		var msg Message
		if err := json.Unmarshal(filtered, &msg); err != nil {
			t.Fatalf("replacement is not valid JSON: %v", err)
		}
		if msg.Error == nil {
			t.Errorf("replacement must be a JSON-RPC error, got %s", filtered)
		}
		var found bool
		for _, e := range audited {
			if e.Source != "mcp-proxy-response-secret-scan" {
				continue
			}
			found = true
			if e.Decision != "BLOCK" {
				t.Errorf("decision = %s, want BLOCK", e.Decision)
			}
			if e.TaxonomyRef == "" {
				t.Error("audit entry carries no taxonomy ref - it cannot reach the attestation chain")
			}
			if e.TaxonomyRef != "data-exfiltration/llm-data-flow/mcp-tool-response-secret-overexposure" {
				t.Errorf("taxonomy ref = %q, want the secret-overexposure node", e.TaxonomyRef)
			}
			if len(e.TriggeredRules) < 2 {
				t.Errorf("expected a sentinel rule id alongside the scanner id, got %v", e.TriggeredRules)
			}
		}
		if !found {
			t.Fatalf("no secret-overexposure audit entry emitted, got %d entries", len(audited))
		}
	})

	t.Run("AUDIT tier passes the response through", func(t *testing.T) {
		structured := map[string]interface{}{
			"clusterToken": "9f8a2c7e1b4d9f0a3c2e8b7a1d6f4c3e",
		}
		var audited []AuditEntry
		h := &MessageHandler{Stderr: io.Discard, Evaluator: evaluator,
			OnAudit: func(e AuditEntry) { audited = append(audited, e) }}
		if filtered := h.FilterToolCallResponse(build(t, structured)); filtered != nil {
			t.Errorf("an AUDIT-tier finding must not replace the response, got %s", filtered)
		}
		var found bool
		for _, e := range audited {
			if e.Source == "mcp-proxy-response-secret-scan" && e.Decision == "AUDIT" {
				found = true
			}
		}
		if !found {
			t.Fatal("expected an AUDIT entry for the clusterToken field-name finding")
		}
	})

	t.Run("ordinary settings response passes through untouched", func(t *testing.T) {
		structured := map[string]interface{}{
			"host":       "10.0.1.4",
			"port":       float64(2480),
			"max_tokens": float64(4096),
			"ha_enabled": true,
		}
		var audited []AuditEntry
		h := &MessageHandler{Stderr: io.Discard, Evaluator: evaluator,
			OnAudit: func(e AuditEntry) { audited = append(audited, e) }}
		if filtered := h.FilterToolCallResponse(build(t, structured)); filtered != nil {
			t.Errorf("an ordinary settings response must pass through, got %s", filtered)
		}
		for _, e := range audited {
			if e.Source == "mcp-proxy-response-secret-scan" {
				t.Errorf("false positive on an ordinary settings response: %v", e.Reasons)
			}
		}
	})
}

// --- pure helper unit tests -------------------------------------------------

func TestLooksLikeOpaqueSecretValue(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"9f8a2c7e1b4d9f0a3c2e8b7a1d6f4c3e", true}, // 32-char hex, len>=24
		{"kX9mQ2vB7nR4wZ1c", true},                 // 16 chars, mixed case+digit
		{"administrator", false},                   // all-lowercase word, no digit
		{"read-only", false},                       // short, no digit/case mix
		{"enabled", false},
		{"min-length-12", false}, // 13 chars, digit+lowercase but below the 16-char floor
		{"short1", false},        // below the 16-char floor
		{"", false},
	}
	for _, tc := range cases {
		if got := looksLikeOpaqueSecretValue(tc.value); got != tc.want {
			t.Errorf("looksLikeOpaqueSecretValue(%q) = %v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIsSensitiveSecretFieldName(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"arcadedb.ha.clusterToken", true},
		{"api_key", true},
		{"private_key", true},
		{"access_key", true},
		{"credentials.password", true},
		{"max_tokens", false},
		{"prompt_tokens", false},
		{"key", false},
		{"cache_key", false},
		{"role_key", false},
		{"request_id", false},
	}
	for _, tc := range cases {
		if got := isSensitiveSecretFieldName(tc.path); got != tc.want {
			t.Errorf("isSensitiveSecretFieldName(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
