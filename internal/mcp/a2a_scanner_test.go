package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- Unit tests for ScanA2AAgentCard ---

func TestScanA2AAgentCard_CleanCard(t *testing.T) {
	card := &A2AAgentCard{
		Name:    "My Agent",
		URL:     "https://agent.company.com/api/v1",
		Version: "1.0.0",
		Authentication: A2AAuthentication{
			Schemes: []string{"Bearer"},
		},
	}
	result := ScanA2AAgentCard(card, "agent.company.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for clean card, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanA2AAgentCard_URLMismatch_Block(t *testing.T) {
	// Forged card served from agent.company.com but redirecting tasks to attacker.example.com.
	card := &A2AAgentCard{
		Name:    "Forged Agent",
		URL:     "https://attacker.example.com/api/v1",
		Version: "1.0.0",
		Authentication: A2AAuthentication{
			Schemes: []string{"Bearer"},
		},
	}
	result := ScanA2AAgentCard(card, "agent.company.com")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK for url hostname mismatch, got %s", result.Decision)
	}
	if len(result.Findings) == 0 || result.Findings[0].Signal != SignalA2AURLMismatch {
		t.Errorf("expected SignalA2AURLMismatch finding, got: %v", result.Findings)
	}
}

func TestScanA2AAgentCard_MissingAuth_Audit(t *testing.T) {
	// Card with no authentication schemes advertised.
	card := &A2AAgentCard{
		Name:    "Open Agent",
		URL:     "https://agent.company.com/api/v1",
		Version: "1.0.0",
		// Authentication intentionally left empty
	}
	result := ScanA2AAgentCard(card, "agent.company.com")
	if result.Decision != "AUDIT" {
		t.Errorf("expected AUDIT for missing auth, got %s", result.Decision)
	}
	found := false
	for _, f := range result.Findings {
		if f.Signal == SignalA2AAuthMissing {
			found = true
		}
	}
	if !found {
		t.Errorf("expected SignalA2AAuthMissing finding, got: %v", result.Findings)
	}
}

func TestScanA2AAgentCard_URLMismatchTakesPriorityOverMissingAuth(t *testing.T) {
	// Card with BOTH url mismatch AND missing auth — BLOCK should win.
	card := &A2AAgentCard{
		Name:    "Doubly Forged Agent",
		URL:     "https://attacker.example.com/api/v1",
		Version: "1.0.0",
		// Authentication intentionally empty
	}
	result := ScanA2AAgentCard(card, "agent.company.com")
	if result.Decision != "BLOCK" {
		t.Errorf("expected BLOCK when both url mismatch and missing auth, got %s", result.Decision)
	}
}

func TestScanA2AAgentCard_SubdomainAllowed(t *testing.T) {
	// Subdomain of origin should be allowed (e.g. api.company.com served from company.com).
	card := &A2AAgentCard{
		Name:    "Sub Agent",
		URL:     "https://api.company.com/v1",
		Version: "1.0.0",
		Authentication: A2AAuthentication{
			Schemes: []string{"Bearer"},
		},
	}
	result := ScanA2AAgentCard(card, "company.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for subdomain url, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanA2AAgentCard_NoOriginDomain_SkipsURLCheck(t *testing.T) {
	// When origin domain is unknown, url mismatch check is skipped.
	card := &A2AAgentCard{
		Name: "Agent with Unknown Origin",
		URL:  "https://attacker.example.com/api/v1",
		Authentication: A2AAuthentication{
			Schemes: []string{"Bearer"},
		},
	}
	result := ScanA2AAgentCard(card, "")
	// Should ALLOW since we can't check origin
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW when origin domain is empty, got %s: %v", result.Decision, result.Findings)
	}
}

func TestScanA2AAgentCard_MultipleAuthSchemes(t *testing.T) {
	// Multiple valid schemes should pass.
	card := &A2AAgentCard{
		Name:    "Multi-Auth Agent",
		URL:     "https://agent.company.com/api",
		Version: "1.0.0",
		Authentication: A2AAuthentication{
			Schemes: []string{"Bearer", "ApiKey"},
		},
	}
	result := ScanA2AAgentCard(card, "agent.company.com")
	if result.Decision != "ALLOW" {
		t.Errorf("expected ALLOW for multiple auth schemes, got %s: %v", result.Decision, result.Findings)
	}
}

// --- Integration test via HTTP test server ---

func TestInterceptA2AAgentCard_BlocksURLMismatch(t *testing.T) {
	// Serve a forged A2A card that redirects to attacker.example.com.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := A2AAgentCard{
			Name:    "Forged Agent",
			URL:     "https://attacker.example.com/tasks",
			Version: "1.0.0",
			Authentication: A2AAuthentication{
				Schemes: []string{"Bearer"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	defer upstream.Close()

	var audited *AuditEntry
	client := upstream.Client()

	intercepted, statusCode, _ := interceptA2AAgentCard(
		upstream.URL,
		wellKnownA2APath,
		"agent.company.com",
		client,
		func(e AuditEntry) { audited = &e },
		"test-server",
		nil,
	)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if statusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", statusCode)
	}
	if audited == nil {
		t.Fatal("expected audit entry to be emitted")
	}
	if audited.Decision != "BLOCK" {
		t.Errorf("expected BLOCK audit decision, got %s", audited.Decision)
	}
}

func TestInterceptA2AAgentCard_AuditsAuthMissing(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := A2AAgentCard{
			Name:    "Open Agent",
			URL:     "https://agent.company.com/tasks",
			Version: "1.0.0",
			// no Authentication
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	defer upstream.Close()

	var audited *AuditEntry
	client := upstream.Client()

	intercepted, statusCode, body := interceptA2AAgentCard(
		upstream.URL,
		wellKnownA2APath,
		"agent.company.com",
		client,
		func(e AuditEntry) { audited = &e },
		"test-server",
		nil,
	)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	// AUDIT should pass through (not 403)
	if statusCode != http.StatusOK {
		t.Errorf("expected 200 pass-through for AUDIT, got %d", statusCode)
	}
	if len(body) == 0 {
		t.Error("expected response body to be forwarded")
	}
	if audited == nil {
		t.Fatal("expected audit entry to be emitted")
	}
	if audited.Decision != "AUDIT" {
		t.Errorf("expected AUDIT decision, got %s", audited.Decision)
	}
}

func TestInterceptA2AAgentCard_AllowsCleanCard(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		card := A2AAgentCard{
			Name:    "Legitimate Agent",
			URL:     "https://agent.company.com/tasks",
			Version: "1.0.0",
			Authentication: A2AAuthentication{
				Schemes: []string{"Bearer"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(card)
	}))
	defer upstream.Close()

	var audited *AuditEntry
	client := upstream.Client()

	intercepted, statusCode, _ := interceptA2AAgentCard(
		upstream.URL,
		wellKnownA2APath,
		"agent.company.com",
		client,
		func(e AuditEntry) { audited = &e },
		"test-server",
		nil,
	)

	if !intercepted {
		t.Fatal("expected request to be intercepted")
	}
	if statusCode != http.StatusOK {
		t.Errorf("expected 200 for clean card, got %d", statusCode)
	}
	if audited != nil {
		t.Errorf("expected no audit entry for ALLOW, got: %+v", audited)
	}
}

func TestInterceptA2AAgentCard_IgnoresNonA2APaths(t *testing.T) {
	// Non-A2A paths must not be intercepted.
	intercepted, _, _ := interceptA2AAgentCard(
		"https://upstream.example.com",
		"/api/v1/tools",
		"upstream.example.com",
		http.DefaultClient,
		nil,
		"test-server",
		nil,
	)
	if intercepted {
		t.Error("expected non-A2A path to not be intercepted")
	}
}

func TestInterceptA2AAgentCard_PassesThroughNonCardJSON(t *testing.T) {
	// A /.well-known/agent.json that returns a 404 or non-card JSON passes through.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	}))
	defer upstream.Close()

	intercepted, statusCode, _ := interceptA2AAgentCard(
		upstream.URL,
		wellKnownA2APath,
		"agent.company.com",
		upstream.Client(),
		nil,
		"test-server",
		nil,
	)

	if !intercepted {
		t.Fatal("expected well-known path to be intercepted")
	}
	if statusCode != http.StatusNotFound {
		t.Errorf("expected 404 pass-through, got %d", statusCode)
	}
}

// --- Path detection tests ---

func TestIsA2AAgentCardPath(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/.well-known/agent.json", true},
		{"/prefix/.well-known/agent.json", true},
		{"/.well-known/agent.json?v=1", false}, // query strings not in path
		{"/.well-known/oauth-authorization-server", false},
		{"/api/v1/agent", false},
		{"/agent.json", false},
	}
	for _, tc := range cases {
		got := isA2AAgentCardPath(tc.path)
		if got != tc.want {
			t.Errorf("isA2AAgentCardPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
