package enterprise

// ManagedConfig represents the enterprise managed configuration loaded from managed.json.
type ManagedConfig struct {
	Managed        bool            `json:"managed"`
	OrganizationID string          `json:"organization_id,omitempty"`
	FailClosed     bool            `json:"fail_closed"`
	RemoteLogging  *RemoteLog      `json:"remote_logging,omitempty"`
	Watchdog       *WatchdogConf   `json:"watchdog,omitempty"`
	Heartbeat      *HeartbeatConf  `json:"heartbeat,omitempty"`
	PolicySync     *PolicySyncConf `json:"policy_sync,omitempty"`
}

// HeartbeatConf configures the background heartbeat sender to AI Agent Lens.
type HeartbeatConf struct {
	URL             string `json:"url"`                        // e.g. "https://aiagentlens.com/api/heartbeat"
	Token           string `json:"token"`                      // Bearer token for auth
	IntervalSeconds int    `json:"interval_seconds,omitempty"` // default 60
}

// PolicySyncConf configures remote policy synchronization from AI Agent Lens.
type PolicySyncConf struct {
	URL             string `json:"url"`                        // e.g. "https://aiagentlens.com/api/policy"
	Token           string `json:"token"`                      // Bearer token for auth
	IntervalSeconds int    `json:"interval_seconds,omitempty"` // default 300
}

// RemoteLog configures remote audit event forwarding.
type RemoteLog struct {
	Syslog  *SyslogConf  `json:"syslog,omitempty"`
	Webhook *WebhookConf `json:"webhook,omitempty"`
}

// SyslogConf configures syslog forwarding (RFC 5424).
type SyslogConf struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"` // "tcp" or "udp"
}

// WebhookConf configures HTTP webhook forwarding.
type WebhookConf struct {
	URL        string `json:"url"`
	AuthHeader string `json:"auth_header,omitempty"`
}

// WatchdogConf configures the background watchdog service.
type WatchdogConf struct {
	IntervalSeconds int    `json:"interval_seconds"`
	AlertWebhook    string `json:"alert_webhook,omitempty"`
}
