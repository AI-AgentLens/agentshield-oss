package enterprise

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"
)

// RemoteLogger is post-eval middleware that forwards audit events to remote destinations.
func RemoteLogger(cfg *RemoteLog) EvalMiddleware {
	return func(ctx *EvalContext, next func()) {
		next()
		if ctx.AuditEvent != nil {
			go forwardEvent(cfg, ctx.AuditEvent)
		}
	}
}

// forwardEvent sends an audit event to configured remote destinations.
func forwardEvent(cfg *RemoteLog, event interface{}) {
	if cfg.Webhook != nil {
		sendWebhook(cfg.Webhook, event)
	}
	// Syslog forwarding handled by the logger backend (SyslogLogger)
}

// sendWebhook POSTs an audit event to a webhook URL with a single retry.
func sendWebhook(cfg *WebhookConf, event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.AuthHeader != "" {
			req.Header.Set("Authorization", cfg.AuthHeader)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue // retry once
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return // success
		}
		// Non-2xx — retry once then drop
	}
	// After 2 attempts, drop the event (fire-and-forget)
}

// ForwardEventExported exposes forwardEvent for testing.
func ForwardEventExported(cfg *RemoteLog, event interface{}) {
	forwardEvent(cfg, event)
}

// SendWebhookExported exposes sendWebhook for testing.
func SendWebhookExported(cfg *WebhookConf, event interface{}) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequest("POST", cfg.URL, bytes.NewReader(data))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if cfg.AuthHeader != "" {
			req.Header.Set("Authorization", cfg.AuthHeader)
		}

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return
		}
	}
}
