package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/AI-AgentLens/agentshield/internal/auth"
	"github.com/AI-AgentLens/agentshield/internal/logger"
)

// sendRemoteAudit sends an audit event to the SaaS synchronously.
// Uses a short timeout so it doesn't slow down the hook noticeably.
func sendRemoteAudit(event *logger.AuditEvent) {
	creds, _ := auth.Load()
	if creds == nil || creds.Token == "" {
		return
	}

	// Use tool name as command for MCP calls
	command := event.Command
	if command == "" && event.ToolName != "" {
		command = "mcp:" + event.ToolName
	}

	entry := map[string]any{
		"command":  command,
		"decision": event.Decision,
		"rule_id":  firstRule(event.TriggeredRules),
		"reason":   firstReason(event.Reasons),
		"source":   event.Source,
	}
	if event.ToolName != "" {
		entry["tool_name"] = event.ToolName
	}
	if len(event.MCPArguments) > 0 {
		entry["arguments"] = event.MCPArguments
	}

	payload, err := json.Marshal(map[string]any{
		"events": []map[string]any{entry},
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

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
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
