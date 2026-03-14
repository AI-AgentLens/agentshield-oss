package logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// WebhookLogger sends audit events to an HTTP webhook endpoint.
// Events are sent asynchronously (fire-and-forget) with a single retry.
type WebhookLogger struct {
	url        string
	authHeader string
	client     *http.Client
}

// NewWebhookLogger creates a new webhook backend.
func NewWebhookLogger(url, authHeader string) *WebhookLogger {
	return &WebhookLogger{
		url:        url,
		authHeader: authHeader,
		client:     &http.Client{Timeout: 5 * time.Second},
	}
}

// Log sends an audit event to the webhook. It fires in a goroutine with one retry.
func (w *WebhookLogger) Log(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	go w.send(data)
	return nil
}

func (w *WebhookLogger) send(data []byte) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", w.url, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if w.authHeader != "" {
			req.Header.Set("Authorization", w.authHeader)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
	}
}

// Close is a no-op for the webhook logger.
func (w *WebhookLogger) Close() error {
	return nil
}

// SendSync sends data synchronously (for testing).
func (w *WebhookLogger) SendSync(event AuditEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", w.url, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if w.authHeader != "" {
			req.Header.Set("Authorization", w.authHeader)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			if attempt == 1 {
				return fmt.Errorf("webhook send failed after retry: %w", err)
			}
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if attempt == 1 {
			return fmt.Errorf("webhook returned status %d", resp.StatusCode)
		}
	}
	return nil
}
