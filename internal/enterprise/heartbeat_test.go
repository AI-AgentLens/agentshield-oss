package enterprise

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- isRevocationResponse unit tests ----

func TestIsRevocationResponse_ExplicitMarker(t *testing.T) {
	body := []byte(`{"reason": "agent_revoked"}`)
	if !isRevocationResponse(body) {
		t.Error("expected body with agent_revoked marker to be treated as revocation")
	}
}

func TestIsRevocationResponse_ExtraFieldsStillRevocation(t *testing.T) {
	body := []byte(`{"reason": "agent_revoked", "deleted_at": "2026-04-09T10:00:00Z", "by": "admin@example.com"}`)
	if !isRevocationResponse(body) {
		t.Error("expected body with agent_revoked marker + extra fields to be revocation")
	}
}

func TestIsRevocationResponse_DifferentReasonIsTransient(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"reason": "unauthorized"}`),
		[]byte(`{"reason": "token_expired"}`),
		[]byte(`{"reason": "invalid_signature"}`),
		[]byte(`{"reason": ""}`),
		[]byte(`{"error": "access_denied"}`), // no reason field at all
	}
	for _, b := range cases {
		if isRevocationResponse(b) {
			t.Errorf("expected body %s to NOT be revocation, but was", string(b))
		}
	}
}

func TestIsRevocationResponse_EmptyBodyIsTransient(t *testing.T) {
	if isRevocationResponse(nil) {
		t.Error("expected nil body to NOT be revocation")
	}
	if isRevocationResponse([]byte{}) {
		t.Error("expected empty body to NOT be revocation")
	}
}

func TestIsRevocationResponse_MalformedJSONIsTransient(t *testing.T) {
	cases := [][]byte{
		[]byte(`not json at all`),
		[]byte(`<html><body>403 Forbidden</body></html>`),
		[]byte(`{"reason":`),   // truncated
		[]byte(`{"reason": }`), // invalid
	}
	for _, b := range cases {
		if isRevocationResponse(b) {
			t.Errorf("expected malformed body %q to NOT be revocation, but was", string(b))
		}
	}
}

// ---- sendHeartbeat integration tests ----
// These verify the 403 handling end-to-end against a real http server.

func TestSendHeartbeat_403WithRevocationMarkerTriggersRevocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"reason": "agent_revoked"}`))
	}))
	defer server.Close()

	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	client := &http.Client{Timeout: 2 * time.Second}
	configDir := t.TempDir()

	if revoked := sendHeartbeat(client, cfg, configDir); !revoked {
		t.Error("expected 403 with agent_revoked marker to return revoked=true")
	}
}

func TestSendHeartbeat_403WithoutMarkerIsTransient(t *testing.T) {
	// Simulates a middlebox 403 or expired token — body does not carry
	// the revocation marker. Must NOT trigger revocation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error": "token_expired"}`))
	}))
	defer server.Close()

	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	client := &http.Client{Timeout: 2 * time.Second}
	configDir := t.TempDir()

	if revoked := sendHeartbeat(client, cfg, configDir); revoked {
		t.Error("expected 403 without agent_revoked marker to return revoked=false (transient)")
	}
}

func TestSendHeartbeat_403WithEmptyBodyIsTransient(t *testing.T) {
	// Middlebox returns 403 with no body at all (e.g., a corporate proxy
	// blocking the request). Must NOT trigger revocation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	client := &http.Client{Timeout: 2 * time.Second}
	configDir := t.TempDir()

	if revoked := sendHeartbeat(client, cfg, configDir); revoked {
		t.Error("expected 403 with empty body to return revoked=false (transient)")
	}
}

func TestSendHeartbeat_403WithHTMLBodyIsTransient(t *testing.T) {
	// Some middleboxes return an HTML error page on 403. Must NOT trigger revocation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`<html><body><h1>403 Forbidden</h1></body></html>`))
	}))
	defer server.Close()

	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	client := &http.Client{Timeout: 2 * time.Second}
	configDir := t.TempDir()

	if revoked := sendHeartbeat(client, cfg, configDir); revoked {
		t.Error("expected 403 with HTML body to return revoked=false (transient)")
	}
}

func TestSendHeartbeat_200Success(t *testing.T) {
	// Sanity check: 2xx responses are not treated as revocation.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()

	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	client := &http.Client{Timeout: 2 * time.Second}
	configDir := t.TempDir()

	if revoked := sendHeartbeat(client, cfg, configDir); revoked {
		t.Error("expected 200 to return revoked=false")
	}
}

// ---- rules_loaded ----

// captureHeartbeat runs one sendHeartbeat against a server that records the
// payload and returns the decoded rules_loaded.
func captureRulesLoaded(t *testing.T) int {
	t.Helper()
	var got struct {
		RulesLoaded *int `json:"rules_loaded"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	sendHeartbeat(&http.Client{Timeout: 2 * time.Second}, cfg, t.TempDir())
	if got.RulesLoaded == nil {
		t.Fatal("payload carried no rules_loaded field")
	}
	return *got.RulesLoaded
}

// The payload reports whatever the CLI-wired counter says — the loaders'
// number, not a file count. Positive control first: with the counter wired
// the field carries its value; then unwired it is 0, never a stale guess.
func TestSendHeartbeat_RulesLoadedComesFromInjectedCounter(t *testing.T) {
	old := RulesLoaded
	t.Cleanup(func() { RulesLoaded = old })

	RulesLoaded = func() int { return 3617 }
	if got := captureRulesLoaded(t); got != 3617 {
		t.Fatalf("rules_loaded = %d, want 3617 from the injected counter", got)
	}

	RulesLoaded = nil
	if got := captureRulesLoaded(t); got != 0 {
		t.Fatalf("rules_loaded = %d with no counter wired, want 0", got)
	}
}

// A packs directory full of YAML files must NOT influence the number: that
// was the old definition (files, not rules), and the SaaS reads this field
// as rules.
func TestSendHeartbeat_RulesLoadedIsNotAFileCount(t *testing.T) {
	old := RulesLoaded
	t.Cleanup(func() { RulesLoaded = old })
	RulesLoaded = func() int { return 5 }

	var got struct {
		RulesLoaded int `json:"rules_loaded"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	configDir := t.TempDir()
	packs := filepath.Join(configDir, "packs")
	if err := os.MkdirAll(packs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.yaml", "b.yaml", "c.yml", "d.yaml", "e.yaml", "f.yaml", "g.yaml", "h.yaml", "i.yaml"} {
		if err := os.WriteFile(filepath.Join(packs, name), []byte("name: x\nrules: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &HeartbeatConf{URL: server.URL, Token: "tok", IntervalSeconds: 900}
	sendHeartbeat(&http.Client{Timeout: 2 * time.Second}, cfg, configDir)
	if got.RulesLoaded != 5 {
		t.Fatalf("rules_loaded = %d, want 5 — nine YAML files on disk must not become the count", got.RulesLoaded)
	}
}
