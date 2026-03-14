package enterprise

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestWebhookSend_Success(t *testing.T) {
	var received []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &WebhookConf{URL: server.URL}
	event := map[string]string{"decision": "BLOCK", "command": "rm -rf /"}
	SendWebhookExported(cfg, event)

	// Give goroutine time to complete
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("expected webhook to receive data")
	}

	var parsed map[string]string
	if err := json.Unmarshal(received, &parsed); err != nil {
		t.Fatalf("invalid JSON received: %v", err)
	}
	if parsed["decision"] != "BLOCK" {
		t.Errorf("expected decision=BLOCK, got %s", parsed["decision"])
	}
}

func TestWebhookSend_WithAuth(t *testing.T) {
	var authHeader string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &WebhookConf{URL: server.URL, AuthHeader: "Bearer test-token-123"}
	SendWebhookExported(cfg, map[string]string{"test": "true"})

	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if authHeader != "Bearer test-token-123" {
		t.Errorf("expected Authorization header 'Bearer test-token-123', got '%s'", authHeader)
	}
}

func TestWebhookSend_NonBlocking(t *testing.T) {
	// Server that takes a long time to respond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Second)
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &RemoteLog{
		Webhook: &WebhookConf{URL: server.URL},
	}

	// RemoteLogger middleware should not block
	mw := RemoteLogger(cfg)
	ctx := &EvalContext{Command: "test", AuditEvent: map[string]string{"test": "true"}}

	done := make(chan struct{})
	go func() {
		mw(ctx, func() {})
		close(done)
	}()

	select {
	case <-done:
		// OK - middleware returned quickly
	case <-time.After(1 * time.Second):
		t.Error("RemoteLogger middleware blocked for too long")
	}
}

func TestWebhookSend_Retry(t *testing.T) {
	var attempts int
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempts++
		currentAttempt := attempts
		mu.Unlock()

		if currentAttempt == 1 {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer server.Close()

	cfg := &WebhookConf{URL: server.URL}
	SendWebhookExported(cfg, map[string]string{"test": "retry"})

	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if attempts != 2 {
		t.Errorf("expected 2 attempts (1 fail + 1 retry), got %d", attempts)
	}
}

func TestRemoteLogger_NilEvent(t *testing.T) {
	cfg := &RemoteLog{Webhook: &WebhookConf{URL: "http://localhost:9999"}}
	mw := RemoteLogger(cfg)

	ctx := &EvalContext{Command: "test", AuditEvent: nil}
	nextCalled := false
	mw(ctx, func() { nextCalled = true })

	if !nextCalled {
		t.Error("next() should be called even with nil event")
	}
}
