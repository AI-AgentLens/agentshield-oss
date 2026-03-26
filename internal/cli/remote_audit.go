package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/security-researcher-ca/agentshield/internal/auth"
	"github.com/security-researcher-ca/agentshield/internal/logger"
)

// sendRemoteAudit sends an audit event to the SaaS in the background.
// Fire-and-forget — errors are silently ignored.
func sendRemoteAudit(event *logger.AuditEvent) {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}

	go func() {
		payload, err := json.Marshal(map[string]any{
			"events": []map[string]any{{
				"command":  event.Command,
				"decision": event.Decision,
				"rule_id":  firstRule(event.TriggeredRules),
				"reason":   firstReason(event.Reasons),
				"source":   event.Source,
			}},
		})
		if err != nil {
			return
		}

		req, err := http.NewRequest("POST", creds.Server+"/api/audit", bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+creds.Token)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		resp.Body.Close()
	}()
}

func firstRule(rules []string) string {
	if len(rules) > 0 {
		return rules[0]
	}
	return ""
}

func firstReason(reasons []string) string {
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}
