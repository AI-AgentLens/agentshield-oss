package enterprise

// ManagedConfig represents the enterprise managed configuration loaded from managed.json.
type ManagedConfig struct {
	Managed        bool          `json:"managed"`
	OrganizationID string        `json:"organization_id,omitempty"`
	FailClosed     bool          `json:"fail_closed"`
	RemoteLogging  *RemoteLog    `json:"remote_logging,omitempty"`
	Watchdog       *WatchdogConf `json:"watchdog,omitempty"`
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
